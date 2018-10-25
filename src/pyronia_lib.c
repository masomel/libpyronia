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
static int is_build = 0;
static pthread_t recv_th;
static int num_interp_memdoms_in_use = 1;
static bool interp_dom_has_space[MAX_NUM_INTERP_DOMS];

/** Do all the necessary setup for a language runtime to use
 * the Pyronia extensions: open the stack inspection communication
 * channel and initialize the SMV backend.
 * Note: This function revokes access to the interpreter domain at the end.
 */
int pyr_init(const char *main_mod_path,
             const char *lib_policy_file,
             pyr_cg_node_t *(*collect_callstack_cb)(void)) {
    int err = 0, i = 0;
    char *policy = NULL;
    pthread_mutexattr_t attr;

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
    pyr_smv_id = smv_create();
    if (pyr_smv_id == -1) {
      printf("[%s] Could not create an SMV for pyronia threads\n", __func__);
      goto out;
    }
    // We need this SMV to be able to access any Python functions
    smv_join_domain(MAIN_THREAD, pyr_smv_id);
    memdom_priv_add(MAIN_THREAD, pyr_smv_id, MEMDOM_READ | MEMDOM_WRITE);

    // init the mem management
    for (i = 0; i < MAX_NUM_INTERP_DOMS; i++) {
        interp_dom_has_space[i] = true;
    }

    /* Initialize the runtime's security context */
    err = pyr_security_context_alloc(&runtime, collect_callstack_cb);
    if (!err)
      err = set_str(main_mod_path, &runtime->main_path);
    if (err) {
        printf("[%s] Runtime initialization failure\n", __func__);
        goto out;
    }

    /* Parse the library policy from disk */
    err = pyr_parse_lib_policy(lib_policy_file, &policy);
    if (err < 0) {
      printf("[%s] Parsing lib policy failure: %d\n", __func__, err);
      goto out;
    }

    /* Initialize the stack inspection communication channel with
     * the kernel */
    err = pyr_init_si_comm(policy);
    if (err) {
        printf("[%s] SI comm channel initialization failed\n", __func__);
        goto out;
    }

    pyr_callstack_req_listen();
    pyr_is_inspecting(); // we want to wait for the listener to be ready
 out:
    if (policy)
      pyr_free_critical_state(policy);
    /* Revoke access to the interpreter domain now */
    pyr_revoke_critical_state_write();
    if (!err)
      rlog("[%s] Initialized pyronia extensions\n", __func__);
    return err;
}

/** Wrapper around memdom_alloc in the interpreter domain.
 */
void *pyr_alloc_critical_runtime_state(size_t size) {
    void *new_block = NULL;
    int i = 0;
    if (is_build)
      return malloc(size);

    if (!runtime)
        return NULL;

    pthread_mutex_lock(&security_ctx_mutex);
    for (i = 0; i < num_interp_memdoms_in_use; i++) {
        if (memdom_get_free_bytes(runtime->interp_dom[i]->memdom_id) >= size
            && interp_dom_has_space[i]) {
            new_block = memdom_alloc(runtime->interp_dom[i]->memdom_id, size);

            if (new_block) {
                if (!runtime->interp_dom[i]->start) {
                    // this is our first allocation in this memdom
                    // so update the allocation metadata
                    runtime->interp_dom[i]->start = new_block;
                    runtime->interp_dom[i]->end = new_block+MEMDOM_HEAP_SIZE;
                }
	        rlog("[%s] Allocated %lu bytes in memdom %d\n", __func__, size, runtime->interp_dom[i]->memdom_id);
                break;
	    }
            else {
	      interp_dom_has_space[i] = false;
	      rlog("[%s] Memdom allocator could not find a suitable block in memdom %d. Current number of active memdoms: %d\n", __func__, runtime->interp_dom[i]->memdom_id, num_interp_memdoms_in_use);
	      if (num_interp_memdoms_in_use == runtime->interp_dom[i]->memdom_id) {
		num_interp_memdoms_in_use++;
	      }
            }
        }
	else {
	  if (interp_dom_has_space[i])
	    interp_dom_has_space[i] = false;
	  if (num_interp_memdoms_in_use == runtime->interp_dom[i]->memdom_id) {
	    rlog("[%s] Not enough space in any active memdoms. Current number of active memdoms: %d\n", __func__, num_interp_memdoms_in_use);
	    num_interp_memdoms_in_use++;
	  }
	}

	// let's make sure we never have more than MAX_NUM_INTERP_DOMS active
	if (num_interp_memdoms_in_use > MAX_NUM_INTERP_DOMS) {
	  num_interp_memdoms_in_use = MAX_NUM_INTERP_DOMS;
	  break;
	}
    }
    pthread_mutex_unlock(&security_ctx_mutex);
    return new_block;
}

static int get_interp_dom_memdom(void *op) {
    int id = 0;
    int i = 0;

    pthread_mutex_lock(&security_ctx_mutex);
    for (i = 0; i < num_interp_memdoms_in_use; i++) {
        if (op >= runtime->interp_dom[i]->start &&
            op < runtime->interp_dom[i]->end) {
            id = runtime->interp_dom[i]->memdom_id;
            goto out;
        }
    }
 out:
    pthread_mutex_unlock(&security_ctx_mutex);
    return id;
}

/** Wrapper around memdom_free in the interpreter domain.
 * Returns 1 if the state was freed, 0 otherwise.
 */
int pyr_free_critical_state(void *op) {
    int obj_memdom = -1;
    if (is_build) {
        return 0;
    }

    if (!runtime)
        return 0;

    obj_memdom = get_interp_dom_memdom(op);
    if (obj_memdom > 0) {
        pthread_mutex_lock(&security_ctx_mutex);
        memdom_free(op);
        if (interp_dom_has_space[obj_memdom-1] == false) {
            interp_dom_has_space[obj_memdom-1] = true;
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
    int ret = 0;

    if (is_build)
        return 0;

    if (!runtime)
        return 0;

    ret = get_interp_dom_memdom(op);

    return (ret > 0);
}

/** Grants the main thread write access to the interpreter domain.
 */
void pyr_grant_critical_state_write() {
    int i = 0;

    if (is_build)
      return;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return;
    }

    // slight optimization: if we've already granted access
    // let's avoid another downcall to change the memdom privileges
    // and simply keep track of how many times we've granted access
    pthread_mutex_lock(&security_ctx_mutex);
    if (runtime->nested_grants == 0) {
        for (i = 0; i < num_interp_memdoms_in_use; i++)
            memdom_priv_add(runtime->interp_dom[i]->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
    }
    runtime->nested_grants++;
    pthread_mutex_unlock(&security_ctx_mutex);
}

/** Revokes the main thread's write privileges to the interpreter domain.
 */
void pyr_revoke_critical_state_write() {
    int i = 0;
    if (is_build)
      return;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return;
    }

    rlog("[%s] Number of grants: %d\n", __func__, runtime->nested_grants);

    pthread_mutex_lock(&security_ctx_mutex);
    runtime->nested_grants--;
    // same optimization as above
    if (runtime->nested_grants == 0) {
        for (i = 0; i < num_interp_memdoms_in_use; i++)
            memdom_priv_del(runtime->interp_dom[i]->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
    }
    pthread_mutex_unlock(&security_ctx_mutex);
}

/** Starts an SMV thread that has access to the MAIN_THREAD memdom.
 * I.e. this is a wrapper for smvthread_create that is supposed to be used
 * in the language runtime as a replacement for all pthread_create calls.
 * This is needed because SMV doesn't allow you to spawn other smvthreads
 * to run in the MAIN_THREAD smv.
 */
int pyr_thread_create(pthread_t* tid, const pthread_attr_t *attr,
                      void*(fn)(void*), void* args) {
    int ret = -1;
#ifdef PYR_INTERCEPT_PTHREAD_CREATE
#undef pthread_create
#endif

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    ret = smvthread_create_attr(pyr_smv_id, tid, attr, fn, args);
#ifdef PYR_INTERCEPT_PTHREAD_CREATE
#define pthread_create(tid, attr, fn, args) pyr_thread_create(tid, attr, fn, args)
#endif
    rlog("[%s] Created new Pyronia thread to run in SMV %d\n", __func__, pyr_smv_id);
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
    int smv_id = -1;
    int i = 0;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    smv_id = smv_create();
    if (smv_id == -1) {
      printf("[%s] Could not create and SMV for the SI thread\n", __func__);
      return;
    }

    // we trust this thread, but also, we need this thread to be able
    // to access the functions
    smv_join_domain(MAIN_THREAD, smv_id);
    memdom_priv_add(MAIN_THREAD, smv_id, MEMDOM_READ | MEMDOM_WRITE);
    for (i = 0; i < MAX_NUM_INTERP_DOMS; i++) {
      smv_join_domain(runtime->interp_dom[i]->memdom_id, smv_id);
      memdom_priv_add(runtime->interp_dom[i]->memdom_id, smv_id, MEMDOM_READ | MEMDOM_WRITE);
    }

    smvthread_create_attr(smv_id, &recv_th, &attr, pyr_recv_from_kernel, NULL);
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
    pyr_grant_critical_state_write();
    if (runtime->main_path)
      pyr_free_critical_state(runtime->main_path);
    pyr_security_context_free(&runtime);
}

/** Wrapper around the runtime callstack collection callback
 * to be called by the si_comm component in handle_callstack_request.
 */
pyr_cg_node_t *pyr_collect_runtime_callstack() {
    pyr_cg_node_t *cg = NULL;
    cg = runtime->collect_callstack_cb();
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
