/* Main Pyronia userspace API.
*
*@author Marcela S. Melara
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <linux/pyronia_mac.h>
#include <smv_lib.h>
#include <memdom_lib.h>

#include "pyronia_lib.h"
#include "security_context.h"
#include "serialization.h"
#include "si_comm.h"
#include "util.h"

static struct pyr_security_context *runtime = NULL;
static int pyr_smv_id = -1;
static int si_smv_id = -1;
static int is_build = 0;
static pthread_t recv_th;
static int num_interp_memdoms_in_use = 1;
static pyr_interp_dom_alloc_t *allocs_tail = NULL;

/** Do all the necessary setup for a language runtime to use
 * the Pyronia extensions: open the stack inspection communication
 * channel and initialize the SMV backend.
 * Note: This function revokes access to the interpreter domain at the end.
 */
int pyr_init(const char *main_mod_path,
             const char *lib_policy_file,
             pyr_cg_node_t *(*collect_callstack_cb)(void),
             void (*interpreter_lock_acquire_cb)(void),
             void (*interpreter_lock_release_cb)(void)) {
    int err = 0, i = 0;
    char *policy = NULL;
    pthread_mutexattr_t attr;
    char **obj_policy = NULL;
    int num_obj_rules = 0;

    is_inspecting_stack = true;
    rlog("[%s] Initializing pyronia for module %s\n", __func__, main_mod_path);

    // We make an exception for setup.py and the sysconfig modules
    // so we don't somehow clobber installs with Pyronia checks
    if (main_mod_path == NULL || !strcmp(main_mod_path, "../setup.py") ||
        !strcmp(main_mod_path, "sysconfig")) {
      is_build = 1;
      runtime = NULL;
      return 0;
    }

    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&security_ctx_mutex, &attr);
    pthread_cond_init(&si_cond_var, NULL);

    /* Register with the memdom subsystem */
    // We don't want the main thread's memdom to be
    // globally accessible, so init with 0.
    err = smv_main_init(0);
    if (err < 0) {
        printf("[%s] Memdom subsystem registration failure\n", __func__);
        goto out;
    }

    // create another SMV to be used by threads originally created by
    // pthread_create. We won't allow mixing pthreads woth smvthreads
    /*    pyr_smv_id = smv_create();
    if (pyr_smv_id == -1) {
      printf("[%s] Could not create an SMV for pyronia threads\n", __func__);
      goto out;
    }
    // We need this SMV to be able to access any Python functions
    smv_join_domain(MAIN_THREAD, pyr_smv_id);
    memdom_priv_add(MAIN_THREAD, pyr_smv_id, MEMDOM_READ | MEMDOM_WRITE);
    */

    /* Initialize the runtime's security context */
    err = pyr_security_context_alloc(&runtime, collect_callstack_cb,
                                     interpreter_lock_acquire_cb,
                                     interpreter_lock_release_cb);
    if (!err) {
      allocs_tail = runtime->interp_doms;
      err = set_str(main_mod_path, &runtime->main_path);
    }
    if (err) {
        printf("[%s] Runtime initialization failure\n", __func__);
        goto out;
    }

    /* Parse the library policy from disk */
    err = pyr_parse_lib_policy(lib_policy_file, &policy, &obj_policy,
                               &num_obj_rules);
    if (err < 0) {
      printf("[%s] Parsing lib policy failure: %d\n", __func__, err);
      goto out;
    }

    err = pyr_parse_data_obj_rules(obj_policy, num_obj_rules,
                                   &runtime);
    if (err) {
        printf("[%s] Parsing data object policy failure: %d\n",
               __func__, err);
      goto out;
    }

    /* Initialize the stack inspection communication channel with
     * the kernel */
    err = pyr_init_si_comm(policy);
    if (err) {
        printf("[%s] SI comm channel initialization failed\n", __func__);
        goto out;
    }

    //    PyEval_InitThreads(); // needed to enable stack inspector

    pyr_callstack_req_listen();
    pyr_is_inspecting(); // we want to wait for the listener to be ready
 out:
    if (policy)
      pyr_free_critical_state(policy);
    /* Revoke access to the interpreter domain now */
    pyr_revoke_critical_state_write(NULL);
    if (!err)
      rlog("[%s] Initialized pyronia extensions\n", __func__);
    return err;
}

/**** INTERPRETER DOMAIN MEMORY MANAGEMENT ****/

static void new_interp_memdom() {
  int interp_memdom = -1;
  pyr_interp_dom_alloc_t *new_dom = NULL;

  if (num_interp_memdoms_in_use+1 > MAX_NUM_INTERP_DOMS)
    return;

  new_dom = malloc(sizeof(pyr_interp_dom_alloc_t));
  if (!new_dom)
    goto fail;
  interp_memdom = memdom_create();
  if(interp_memdom == -1) {
    printf("[%s] Could not create interpreter dom # %d\n", __func__, num_interp_memdoms_in_use+1);
    goto fail;
  }
  // don't forget to add the main thread to this memdom
  smv_join_domain(interp_memdom, MAIN_THREAD);
  memdom_priv_add(interp_memdom, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);

  new_dom->memdom_id = interp_memdom;
  new_dom->start = NULL;
  new_dom->end = NULL;
  new_dom->has_space = true;
  new_dom->writable = true;
  new_dom->next = NULL;

  // for big profiles, we're going to be calling this functions before
  // we even launch the SI thread
  if (si_smv_id != -1) {
    smv_join_domain(new_dom->memdom_id, si_smv_id);
    memdom_priv_add(new_dom->memdom_id, si_smv_id, MEMDOM_READ | MEMDOM_WRITE);
  }

  // insert at tail
  allocs_tail->next = new_dom;
  allocs_tail = new_dom;

  num_interp_memdoms_in_use++;
  return;
 fail:
  if (new_dom)
    free(new_dom);
}

/** Wrapper around memdom_alloc in the interpreter domain.
 */
void *pyr_alloc_critical_runtime_state(size_t size) {
    void *new_block = NULL;
    int i = 1;
    pyr_interp_dom_alloc_t *dalloc = NULL;
    if (is_build)
      return malloc(size);

    if (!runtime)
        return NULL;

    if(size > MEMDOM_HEAP_SIZE) {
      rlog("[%s] Requested size is too large for interpreter dom.\n", __func__);
      return malloc(size);
    }

    pthread_mutex_lock(&security_ctx_mutex);
    dalloc = runtime->interp_doms;
    while(dalloc) {
        if (dalloc->has_space &&
            memdom_get_free_bytes(dalloc->memdom_id) >= size) {
            new_block = memdom_alloc(dalloc->memdom_id, size);

            if (new_block) {
                if (!dalloc->start) {
                    // this is our first allocation in this memdom
                    // so update the allocation metadata
                    dalloc->start = new_block;
                    dalloc->end = new_block+MEMDOM_HEAP_SIZE;
                }
                rlog("[%s] Allocated %lu bytes in memdom %d\n", __func__, size, dalloc->memdom_id);
                break;
            }
            else {
              dalloc->has_space = false;
              rlog("[%s] Memdom allocator could not find a suitable block in memdom %d. Current number of active memdoms: %d\n", __func__, dalloc->memdom_id, num_interp_memdoms_in_use);
              if (dalloc->next == NULL) {
                //num_interp_memdoms_in_use++;
                new_interp_memdom();
              }
            }
        }
        else {
          if (dalloc->has_space)
            dalloc->has_space = false;
          if (num_interp_memdoms_in_use == i) {
            rlog("[%s] Not enough space in any active memdoms. Current number of active memdoms: %d, last memdom %d\n", __func__, num_interp_memdoms_in_use, dalloc->memdom_id);
            //num_interp_memdoms_in_use++;
            new_interp_memdom();
          }
        }

        // let's make sure we never have more than MAX_NUM_INTERP_DOMS active
        if (num_interp_memdoms_in_use > MAX_NUM_INTERP_DOMS) {
          num_interp_memdoms_in_use = MAX_NUM_INTERP_DOMS;
          break;
        }
        dalloc = dalloc->next;
        // this is to keep track of how many domains we've already checked,
        // and compare to the max number of interpdoms
        i++;
    }
    pthread_mutex_unlock(&security_ctx_mutex);
    return new_block;
}

static pyr_interp_dom_alloc_t *get_interp_dom_memdom(void *op) {
    int id = 0;
    pyr_interp_dom_alloc_t *dalloc = NULL;

    pthread_mutex_lock(&security_ctx_mutex);
    dalloc = runtime->interp_doms;
    while(dalloc) {
        if (op >= dalloc->start &&
            op < dalloc->end) {
            goto out;
        }
        dalloc = dalloc->next;
    }
 out:
    pthread_mutex_unlock(&security_ctx_mutex);
    return dalloc;
}

/** Wrapper around memdom_free in the interpreter domain.
 * Returns 1 if the state was freed, 0 otherwise.
 */
int pyr_free_critical_state(void *op) {
    int obj_memdom = -1;
    pyr_interp_dom_alloc_t *dalloc = NULL;
    if (is_build) {
        return 0;
    }

    if (!runtime)
        return 0;

    dalloc = get_interp_dom_memdom(op);
    if (dalloc && dalloc->memdom_id > 0) {
        pthread_mutex_lock(&security_ctx_mutex);
        memdom_free(op);
        if (dalloc->has_space == false) {
            dalloc->has_space = true;
        }
        pthread_mutex_unlock(&security_ctx_mutex);
        rlog("[%s] Freed %p\n", __func__, op);
        return 1;
    }
    return 0;
}

/** Wrapper around memdom_query_id. Returns 1 if the
 * given pointer is in the interpreter_dom, 0 otherwise.
 */
int pyr_is_critical_state(void *op) {
    pyr_interp_dom_alloc_t *dalloc = NULL;

    if (is_build)
        return 0;

    if (!runtime)
        return 0;

    dalloc = get_interp_dom_memdom(op);
    if (!dalloc)
      return 0;

    return (dalloc->memdom_id > 0);
}

/** Grants the main thread write access to the interpreter domain.
 */
void pyr_grant_critical_state_write(void *op) {
    int i = 0;
    pyr_interp_dom_alloc_t *dalloc = NULL;

    if (is_build)
      return;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return;
    }

    // if the caller has given us an insecure object, exit
    if (op) {
      dalloc = get_interp_dom_memdom(op);
      rlog("[%s] grant access to obj %p?\n", __func__, op);
      if (!dalloc || dalloc->memdom_id <= 0)
        return;
    }

    pthread_mutex_lock(&security_ctx_mutex);
    // if the caller has given us an existing secure object to
    // modify, we should just go ahead an grant that particular
    // memdom the write access
    if (op && !dalloc->writable) {
      memdom_priv_add(dalloc->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
      dalloc->writable = true;
      rlog("[%s] Granted write access to obj in memdom %d\n", __func__, dalloc->memdom_id);
      goto out;
    }

    rlog("[%s] Grants: %d\n", __func__, runtime->nested_grants);

    // slight optimization: if we've already granted access
    // let's avoid another downcall to change the memdom privileges
    // and simply keep track of how many times we've granted access
    if (runtime->nested_grants == 0) {
      dalloc = runtime->interp_doms;
      while(dalloc) {
        if (dalloc->has_space) {
          memdom_priv_add(dalloc->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
          dalloc->writable = true;
          rlog("[%s] Granted write access to memdom %d\n", __func__, dalloc->memdom_id);
        }
        dalloc = dalloc->next;
      }
    }
 out:
    runtime->nested_grants++;
    pthread_mutex_unlock(&security_ctx_mutex);
}

/** Revokes the main thread's write privileges to the interpreter domain.
 */
void pyr_revoke_critical_state_write(void *op) {
    int i = 0;
    pyr_interp_dom_alloc_t *dalloc = NULL;
    if (is_build)
      return;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return;
    }

    // if the caller has given us an insecure object, exit
    if (op) {
      dalloc = get_interp_dom_memdom(op);
      rlog("[%s] revoke access from obj %p?\n", __func__, op);
      if (!dalloc || dalloc->memdom_id <= 0)
        return;
    }

    pthread_mutex_lock(&security_ctx_mutex);
    rlog("[%s] Number of grants: %d\n", __func__, runtime->nested_grants);
    runtime->nested_grants--;
    if (op && runtime->nested_grants == 0) {
      memdom_priv_del(dalloc->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
      dalloc->writable = false;
      rlog("[%s] Revoked write access for obj in domain %d\n", __func__, dalloc->memdom_id);
      goto out;
    }

    // same optimization as above
    if (runtime->nested_grants == 0) {
      dalloc = runtime->interp_doms;
      while(dalloc) {
        if (dalloc->writable) {
          memdom_priv_del(dalloc->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
          dalloc->writable = false;
          rlog("[%s] Revoked write access to domain %d\n", __func__, dalloc->memdom_id);
        }
        dalloc = dalloc->next;
      }
    }
 out:
    pthread_mutex_unlock(&security_ctx_mutex);
}

/**** DATA OBJECT DOMAIN MEMORY MANAGEMENT ****/

/** Wrapper around memdom_alloc for protected in-memory data objects.
 */
void *pyr_data_object_alloc(char *obj_name, size_t size) {
    void *new_block = NULL;
    pyr_data_obj_t *obj = NULL;
    pyr_data_obj_domain_t *domain = NULL;

    if (is_build)
      return malloc(size);

    if (!runtime)
        return NULL;

    /*if(size > MEMDOM_HEAP_SIZE) {
      printf("[%s] Requested size is too large for data object dom.\n", __func__);
      return malloc(size);
      }*/

    pthread_mutex_lock(&security_ctx_mutex);
    obj = find_data_obj(obj_name, runtime->data_objs_list);
    if (!obj)
        goto out;

    domain = find_domain(obj->domain_label, runtime->obj_domains_list);
    if (!domain)
        goto out;

    memdom_priv_add(domain->memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
    new_block = memdom_alloc(domain->memdom_id, size);
    memdom_priv_del(domain->memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
    if (!new_block)
        printf("[%s] Could not allocate memory in domain %s for object %s\n",
               __func__, obj->name, domain->label);
    obj->addr = new_block;

 out:
    pthread_mutex_unlock(&security_ctx_mutex);
    return new_block;
}

void pyr_data_obj_free(char *obj_name, void *addr) {
    pyr_data_obj_t *obj = NULL;
    pyr_data_obj_domain_t *domain = NULL;

    if (is_build)
      free(addr);

    if (!runtime)
        return;

    /*if(size > MEMDOM_HEAP_SIZE) {
      printf("[%s] Requested size is too large for data object dom.\n", __func__);
      return malloc(size);
      }*/

    pthread_mutex_lock(&security_ctx_mutex);
    obj = find_data_obj(obj_name, runtime->data_objs_list);
    if (!obj)
        goto out;

    if (addr != obj->addr) {
        printf("[%s] Expected address %p, got %p, for object %s\n", __func__,
               obj->addr, addr, obj->name);
        goto out;
    }

    domain = find_domain(obj->domain_label, runtime->obj_domains_list);
    if (!domain)
        goto out;

    memdom_priv_add(domain->memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
    memdom_free(obj->addr);
    memdom_priv_del(domain->memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);

 out:
    pthread_mutex_unlock(&security_ctx_mutex);
}

/** Grants the main thread write access to the data object domains
 * for the given function sandbox.
 */
void pyr_grant_sandbox_access(char *sandbox_name) {
    pyr_func_sandbox_t *sb = NULL;

    if (is_build)
      return;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return;
    }

    printf("[%s] Sandbox? %s\n", __func__, sandbox_name);

    pthread_mutex_lock(&security_ctx_mutex);
    sb = find_sandbox(sandbox_name, runtime->func_sandboxes);
    if (!sb)
        goto out;

    if (sb->in_sandbox) {
        printf("[%s] already in sandbox\n", __func__);
        goto out;
    }

    dom_list_t *ro_dom = sb->read_only;
    while (ro_dom) {
        pyr_data_obj_domain_t *dom = ro_dom->domain;
        memdom_priv_add(dom->memdom_id, MAIN_THREAD, MEMDOM_READ);
        printf("[%s] Add read privilege to domain %s for sandbox %s\n",
               __func__, dom->label, sandbox_name);
        ro_dom = ro_dom->next;
    }

    dom_list_t *rw_dom = sb->read_write;
    while (rw_dom) {
        pyr_data_obj_domain_t *dom = rw_dom->domain;
        memdom_priv_add(dom->memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
        printf("[%s] Add read/write privilege to domain %s for sandbox %s\n",
               __func__, dom->label, sandbox_name);
        rw_dom = rw_dom->next;
    }

    sb->in_sandbox = true;

 out:
    pthread_mutex_unlock(&security_ctx_mutex);
}

/** Revokes the main thread write access to the data object domains
 * for the given function sandbox.
 */
void pyr_revoke_sandbox_access(char *sandbox_name) {
    pyr_func_sandbox_t *sb = NULL;

    if (is_build)
      return;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return;
    }

    printf("[%s] Sandbox? %s\n", __func__, sandbox_name);

    pthread_mutex_lock(&security_ctx_mutex);
    sb = find_sandbox(sandbox_name, runtime->func_sandboxes);
    if (!sb)
        goto out;

    if (!sb->in_sandbox)
        goto out;

    dom_list_t *ro_dom = sb->read_only;
    while (ro_dom) {
        pyr_data_obj_domain_t *dom = ro_dom->domain;
        memdom_priv_del(dom->memdom_id, MAIN_THREAD, MEMDOM_READ);
        printf("[%s] Revoke read privilege to domain %s for sandbox %s\n",
               __func__, dom->label, sandbox_name);
        ro_dom = ro_dom->next;
    }

    dom_list_t *rw_dom = sb->read_write;
    while (rw_dom) {
        pyr_data_obj_domain_t *dom = rw_dom->domain;
        memdom_priv_del(dom->memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
        printf("[%s] Revoke read/write privilege to domain %s for sandbox %s\n",
               __func__, dom->label, sandbox_name);
        rw_dom = rw_dom->next;
    }

    sb->in_sandbox = false;

 out:
    pthread_mutex_unlock(&security_ctx_mutex);
}

/**** MISC PYRONIA API ****/

/** Starts an SMV thread that has access to the MAIN_THREAD memdom.
 * I.e. this is a wrapper for smvthread_create that is supposed to be used
 * in the language runtime as a replacement for all pthread_create calls.
 * This is needed because SMV doesn't allow you to spawn other smvthreads
 * to run in the MAIN_THREAD smv.
 */
int pyr_thread_create(pthread_t* tid, const pthread_attr_t *attr,
                      void*(fn)(void*), void* args) {
    int ret = 0;
    /*
#ifdef PYR_INTERCEPT_PTHREAD_CREATE
#undef pthread_create
#endif

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    ret = smvthread_create_attr(pyr_smv_id, tid, attr, fn, args);
#ifdef PYR_INTERCEPT_PTHREAD_CREATE
#define pthread_create(tid, attr, fn, args) pyr_thread_create(tid, attr, fn, args)
#endif
    */
    printf("[%s] Created new Pyronia thread to run in SMV %d\n", __func__, pyr_smv_id);
    return ret;
}

/** Loads the given native library into its own memory domain.
 */
int pyr_load_native_lib_isolated(const char *lib) {
    // FIXME
    return 0;
}

/** Runs the given function belonging to the given library in
 * in an isolated compartment (i.e. SMV).
 */
int pyr_run_native_func_isolated(const char *lib, void *(*func)(void)) {
    // FIXME
    return 0;
}

/** Starts the SI listener and dispatch thread.
 */
void pyr_callstack_req_listen() {
    pthread_attr_t attr;
    int i = 0;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    si_smv_id = smv_create();
    if (si_smv_id == -1) {
      printf("[%s] Could not create and SMV for the SI thread\n", __func__);
      return;
    }

    // we trust this thread, but also, we need this thread to be able
    // to access the functions
    smv_join_domain(MAIN_THREAD, si_smv_id);
    memdom_priv_add(MAIN_THREAD, si_smv_id, MEMDOM_READ | MEMDOM_WRITE);
    pyr_interp_dom_alloc_t *dalloc = runtime->interp_doms;
    while(dalloc) {
      smv_join_domain(dalloc->memdom_id, si_smv_id);
      memdom_priv_add(dalloc->memdom_id, si_smv_id, MEMDOM_READ | MEMDOM_WRITE);
      dalloc = dalloc->next;
    }

    smvthread_create_attr(si_smv_id, &recv_th, &attr, pyr_recv_from_kernel, NULL);
}

int pyr_is_interpreter_build() {
  return is_build;
}

/* Do all necessary teardown actions. */
void pyr_exit() {
    if (is_build) {
      return;
    }

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    rlog("[%s] Exiting Pyronia runtime\n", __func__);
    pthread_cancel(recv_th);
    pyr_teardown_si_comm();
    pyr_grant_critical_state_write((void *)runtime->main_path);
    if (runtime->main_path)
      pyr_free_critical_state(runtime->main_path);
    pyr_security_context_free(&runtime);
}

/** Wrapper around the runtime callstack collection callback
 * to be called by the si_comm component in handle_callstack_request.
 */
pyr_cg_node_t *pyr_collect_runtime_callstack() {
    pyr_cg_node_t *cg = NULL;
    runtime->interpreter_lock_acquire_cb();
    cg = runtime->collect_callstack_cb();
    runtime->interpreter_lock_release_cb();
    rlog("[%s] Done collecting callstack\n", __func__);
    return cg;
}

/* CALLGRAPH ALLOCATION AND FREE */
/* These mirror the callgraph allocation and free functions.
 * Until we register a new syscall, we need to be careful
 * to keep them in sync. */

// Allocate a new callgraph node
int pyr_new_cg_node(pyr_cg_node_t **cg_root, const char* lib,
                        enum pyr_data_types data_type,
                        pyr_cg_node_t *child) {

    pyr_cg_node_t *n = pyr_alloc_critical_runtime_state(sizeof(pyr_cg_node_t));

    if (n == NULL) {
        goto fail;
    }

    if (set_str(lib, &n->lib))
      goto fail;
    n->data_type = data_type;
    n->child = child;

    *cg_root = n;
    return 0;
 fail:
    pyr_free_critical_state(n);
    return -1;
}

// Recursively free the callgraph nodes
static void free_node(pyr_cg_node_t **node) {
    pyr_cg_node_t *n = *node;

    if (n == NULL) {
      return;
    }

    if (n->child != NULL) {
      free_node(&n->child);
    }

    pyr_free_critical_state(n->lib);
    pyr_free_critical_state(n);
    *node = NULL;
}

// Free a callgraph
void pyr_free_callgraph(pyr_cg_node_t **cg_root) {
    free_node(cg_root);
}
