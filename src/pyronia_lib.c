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
static pyr_dom_alloc_t *allocs_tail = NULL;
static pyr_func_sandbox_t *cur_sandbox = NULL;
static int num_pyr_threads = 0;

static void pyr_thread_setup(void);
static struct pyr_thread *get_cur_pyr_thread(void);

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

    is_inspecting_stack = false;
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

    if (obj_policy && num_obj_rules) {
      err = pyr_parse_data_obj_rules(obj_policy, num_obj_rules,
				     &runtime);
      if (err) {
        printf("[%s] Parsing data object policy failure: %d\n",
               __func__, err);
	goto out;
      }
    }

    /* Initialize the stack inspection communication channel with
     * the kernel */
    err = pyr_init_si_comm(policy);
    if (err) {
        printf("[%s] SI comm channel initialization failed\n", __func__);
        goto out;
    }

    pyr_thread_setup();

    is_inspecting_stack = true;
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

/**** MEMDOM POOL MEMORY MANAGEMENT ****/
static void new_interp_memdom(void);
static void new_data_obj_memdom(char *);

static void *alloc_memdom_pool(pyr_dom_alloc_t *pool, int pool_size,
			       int is_interp_dom, char *opt_label,
			       size_t size) {
  void *new_block = NULL;
  int i = 1;
  pyr_dom_alloc_t *dalloc = NULL;
  
  if(size > MEMDOM_HEAP_SIZE) {
    rlog("[%s] Requested size is too large for interpreter dom.\n", __func__);
    return malloc(size);
  }
  
  dalloc = pool;
  while(dalloc) {
    if (dalloc->has_space &&
	memdom_get_free_bytes(dalloc->memdom_id) >= size) {
      new_block = memdom_alloc(dalloc->memdom_id, size);
      
      if (new_block) {
	if (!dalloc->start) {
	  // this is our first allocation in this memdom
	  // so update the allocation metadata
	  dalloc->start = new_block;
	  dalloc->size = MEMDOM_HEAP_SIZE;
	  rlog("[%s] Memdom %d at %p\n", __func__, dalloc->memdom_id, dalloc->start);
	}
	rlog("[%s] Allocated %lu bytes in memdom %d\n", __func__, size, dalloc->memdom_id);
	break;
      }
      else {
	dalloc->has_space = false;
	rlog("[%s] Memdom allocator could not find a suitable block in memdom %d\n", __func__, dalloc->memdom_id);
	if (dalloc->next == NULL) {
	  if (is_interp_dom)
	    new_interp_memdom();
	  else
	    new_data_obj_memdom(opt_label);
	}
      }
    }
    else {
      if (dalloc->has_space)
	dalloc->has_space = false;
      if (pool_size == i) {
	rlog("[%s] Not enough space in any active memdoms. Current number of active memdoms: %d, last memdom %d\n", __func__, pool_size, dalloc->memdom_id);
	if (is_interp_dom)
	  new_interp_memdom();
	else
	  new_data_obj_memdom(opt_label);
      }
    }
    dalloc = dalloc->next;
    // this is to keep track of how many domains we've already checked,
    // and compare to the max number of doms
    i++;
  }
  return new_block;
}

static pyr_dom_alloc_t *get_dom_alloc(void *op, pyr_dom_alloc_t *pool) {
    int id = 0;
    pyr_dom_alloc_t *dalloc = NULL;

    dalloc = pool;
    while(dalloc) {
        if (op >= dalloc->start &&
            op < (dalloc->start+dalloc->size)) {
            goto out;
        }
        dalloc = dalloc->next;
    }
 out:
    return dalloc;
}

static int free_dom_alloc(void *op, pyr_dom_alloc_t *pool) {
    int obj_memdom = -1;
    pyr_dom_alloc_t *dalloc = NULL;

    dalloc = get_dom_alloc(op, pool);
    if (dalloc && dalloc->memdom_id > 0) {
        memdom_free(op);
        if (dalloc->has_space == false) {
            dalloc->has_space = true;
        }
        rlog("[%s] Freed %p\n", __func__, op);
        return 1;
    }
    return 0;
}

/**** INTERPRETER DOMAIN MEMORY MANAGEMENT ****/

static void new_interp_memdom() {
  pyr_dom_alloc_t *new_dom = NULL;
  struct pyr_thread *th = NULL;
  
  if (num_interp_memdoms_in_use+1 > MAX_NUM_INTERP_DOMS)
    return;

  if (new_dom_alloc(&new_dom)) {
    printf("[%s] Could not create interpreter dom # %d\n", __func__, num_interp_memdoms_in_use+1);
    goto fail;
  }

  // for big profiles, we're going to be calling this functions before
  // we even launch the SI thread
  if (si_smv_id != -1) {
    smv_join_domain(new_dom->memdom_id, si_smv_id);
    memdom_priv_add(new_dom->memdom_id, si_smv_id, MEMDOM_READ);
  }

  if (pyr_smv_id != -1) {
    smv_join_domain(new_dom->memdom_id, pyr_smv_id);
    memdom_priv_add(new_dom->memdom_id, pyr_smv_id, MEMDOM_READ);
  }

  th = get_cur_pyr_thread();
  if (!th)
      goto fail;

  if (th->smv_id == MAIN_THREAD) {
      new_dom->writable_main = true;
      memdom_priv_add(new_dom->memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
  }
  else if (th->smv_id == pyr_smv_id) {
      new_dom->pyr_thread_refcnt = 1;
      memdom_priv_add(new_dom->memdom_id, pyr_smv_id, MEMDOM_READ | MEMDOM_WRITE);
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

  if (is_build)
    return malloc(size);

  if (!runtime)
    return NULL;

  if(size > MEMDOM_HEAP_SIZE) {
    rlog("[%s] Requested size is too large for interpreter dom.\n", __func__);
    return (void *)1;
  }

  pthread_mutex_lock(&security_ctx_mutex);
  new_block = alloc_memdom_pool(runtime->interp_doms, num_interp_memdoms_in_use,
				true, NULL, size);
  rlog("[%s] New interp dom buffer %p\n", __func__, new_block);
  pthread_mutex_unlock(&security_ctx_mutex);
  return new_block;
  
}

/** Wrapper around memdom_free in the interpreter domain.
 * Returns 1 if the state was freed, 0 otherwise.
 */
int pyr_free_critical_state(void *op) {
    int obj_memdom = -1;
    pyr_dom_alloc_t *dalloc = NULL;
    int ret = 0;
    if (is_build) {
        return 0;
    }

    if (!runtime)
        return 0;

    pthread_mutex_lock(&security_ctx_mutex);
    ret = free_dom_alloc(op, runtime->interp_doms);
    pthread_mutex_unlock(&security_ctx_mutex);
    return ret;
}

/** Wrapper around memdom_query_id. Returns 1 if the
 * given pointer is in the interpreter_dom, 0 otherwise.
 */
int pyr_is_critical_state(void *op) {
    pyr_dom_alloc_t *dalloc = NULL;

    if (is_build)
        return 0;

    if (!runtime)
        return 0;

    pthread_mutex_lock(&security_ctx_mutex);
    dalloc = get_dom_alloc(op, runtime->interp_doms);
    pthread_mutex_unlock(&security_ctx_mutex);
    
    return (dalloc && dalloc->memdom_id > 0);
}

/** Grants the main thread write access to the interpreter domain.
 */
void pyr_grant_critical_state_write(void *op) {
    int i = 0;
    pyr_dom_alloc_t *dalloc = NULL;
    int cur_smv = -1;
    
    if (is_build)
      return;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return;
    }

    pthread_mutex_lock(&security_ctx_mutex);
    // make sure we only call this function from main or pyr_smv
    if (num_pyr_threads > 0) {
        struct pyr_thread *th = NULL;
        th = get_cur_pyr_thread();
        if (!th)
            goto out;
        cur_smv = th->smv_id;
        if (cur_smv != MAIN_THREAD && cur_smv != pyr_smv_id) {
            printf("[%s] Current thread with policy ID %d is not authorized\n",
                   __func__, cur_smv);
            goto out;
        }
    }
    else {
        cur_smv = MAIN_THREAD;
    }

    // if the caller has given us an insecure object, exit
    if (op) {
      dalloc = get_dom_alloc(op, runtime->interp_doms);
      rlog("[%s] grant access to obj %p?\n", __func__, op);
      if (!dalloc || dalloc->memdom_id <= 0) {
	pthread_mutex_unlock(&security_ctx_mutex);
	return;
      }

      // if the caller has given us an existing secure object to
      // modify, we should just go ahead an grant that particular
      // memdom the write access
      if (cur_smv == MAIN_THREAD) {
          if (!dalloc->writable_main) {
              memdom_priv_add(dalloc->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
              dalloc->writable_main = true;
              rlog("[%s] Granted main thread write access to obj in memdom %d\n", __func__, dalloc->memdom_id);
          }
          runtime->nested_grants++;
      }
      else {
          if (!dalloc->pyr_thread_refcnt) {
              memdom_priv_add(dalloc->memdom_id, pyr_smv_id, MEMDOM_WRITE);
              rlog("[%s] Granted Pyr thread write access to obj in memdom %d\n", __func__, dalloc->memdom_id);
          }
          dalloc->pyr_thread_refcnt++;
      }
      goto out;
    }

    rlog("[%s] Grants: %d\n", __func__, runtime->nested_grants);

    // slight optimization: if we've already granted access
    // let's avoid another downcall to change the memdom privileges
    // and simply keep track of how many times we've granted access
    dalloc = runtime->interp_doms;
    if (cur_smv == MAIN_THREAD) {
        if (runtime->nested_grants == 0) {
            while(dalloc) {
                if (dalloc->has_space) {
                    memdom_priv_add(dalloc->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
                    dalloc->writable_main = true;
                    rlog("[%s] Granted main thread write access to memdom %d\n", __func__, dalloc->memdom_id);
                }
                dalloc = dalloc->next;
            }
        }
        runtime->nested_grants++;
    }
    else {
        while(dalloc) {
            if (dalloc->pyr_thread_refcnt == 0) {
                memdom_priv_add(dalloc->memdom_id, pyr_smv_id, MEMDOM_WRITE);
                rlog("[%s] Granted Pyr thread write access to memdom %d\n", __func__, dalloc->memdom_id);
            }
            dalloc->pyr_thread_refcnt++;
            dalloc = dalloc->next;
        }
    }
 out:
    pthread_mutex_unlock(&security_ctx_mutex);
}

/** Revokes the main thread's write privileges to the interpreter domain.
 */
void pyr_revoke_critical_state_write(void *op) {
    int i = 0;
    pyr_dom_alloc_t *dalloc = NULL;
    int cur_smv = -1;
                        
    if (is_build)
      return;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return;
    }

    pthread_mutex_lock(&security_ctx_mutex);
    // make sure we only call this function from main or pyr_smv
    if (num_pyr_threads > 0) {
        struct pyr_thread *th = NULL;
        th = get_cur_pyr_thread();
        if (!th)
            goto out;
        cur_smv = th->smv_id;

        if (cur_smv != MAIN_THREAD && cur_smv != pyr_smv_id) {
            printf("[%s] Current thread with policy ID %d is not authorized\n",
                   __func__, cur_smv);
            goto out;
        }
    }
    else {
        cur_smv = MAIN_THREAD;
    }

    // if the caller has given us an insecure object, exit
    if (op) {
      dalloc = get_dom_alloc(op, runtime->interp_doms);
      rlog("[%s] revoke access from obj %p?\n", __func__, op);
      if (!dalloc || dalloc->memdom_id <= 0) {
	pthread_mutex_unlock(&security_ctx_mutex);
	return;
      }

      if (cur_smv == MAIN_THREAD) {
          runtime->nested_grants--;
          if (!runtime->nested_grants) {
              memdom_priv_del(dalloc->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
              dalloc->writable_main = false;
              rlog("[%s] Revoked write access for obj in domain %d\n", __func__, dalloc->memdom_id);
          }
      }
      else {
          dalloc->pyr_thread_refcnt--;
          if (!dalloc->pyr_thread_refcnt) {
              memdom_priv_del(dalloc->memdom_id, pyr_smv_id, MEMDOM_WRITE);
              rlog("[%s] Revoked Pyr thread write access to obj in memdom %d\n", __func__, dalloc->memdom_id);
          }
      }
      goto out;
    }

    // same optimization as above
    dalloc = runtime->interp_doms;
    if (cur_smv == MAIN_THREAD) {
        runtime->nested_grants--;
        if (runtime->nested_grants == 0) {
            while(dalloc) {
                if (dalloc->writable_main) {
                    memdom_priv_del(dalloc->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
                    dalloc->writable_main = false;
                    rlog("[%s] Revoked main thread write access to memdom %d\n", __func__, dalloc->memdom_id);
                }
                dalloc = dalloc->next;
            }
        }
    }
    else {
        while(dalloc) {
            dalloc->pyr_thread_refcnt--;
            if (dalloc->pyr_thread_refcnt == 0) {
                memdom_priv_del(dalloc->memdom_id, pyr_smv_id, MEMDOM_WRITE);
                rlog("[%s] Revoked Pyr thread write access to memdom %d\n", __func__, dalloc->memdom_id);
            }
            dalloc = dalloc->next;
        }
    }
 out:
    pthread_mutex_unlock(&security_ctx_mutex);
}

/**** DATA OBJECT DOMAIN MEMORY MANAGEMENT ****/

static void new_data_obj_memdom(char *label) {
  pyr_dom_alloc_t *new_dom = NULL;

  pyr_data_obj_domain_t *obj_dom = find_domain(label, runtime->obj_domains_list);
  if (!obj_dom)
    return;
  
  if (obj_dom->pool_size+1 > MAX_OBJ_DOM_POOL_SIZE)
    return;

  if (new_dom_alloc(&new_dom)) {
    printf("[%s] Could not create data obj dom # %d\n", __func__, obj_dom->pool_size+1);
    goto fail;
  }

  // since this is only going to be called within a sandbox
  // we can safely add write access if the rest of the domain has write access
  if (obj_dom->memdom_pool->writable_main) {
    new_dom->writable_main = true;
  }
  memdom_priv_add(new_dom->memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
  
  // insert at tail
  obj_dom->pool_tail->next = new_dom;
  obj_dom->pool_tail = new_dom;
  obj_dom->pool_size++;
  rlog("[%s] Memdom ID %d for domain %s\n", __func__, new_dom->memdom_id, label);
  return;
 fail:
  if (new_dom)
    free(new_dom);
}

/** Wrapper around memdom_alloc for protected in-memory data objects.
 */
void *pyr_data_object_alloc(char *obj_name, size_t size) {
    void *new_block = NULL;
    pyr_data_obj_t *obj = NULL;
    pyr_data_obj_domain_t *domain = NULL;

    if (is_build)
      return malloc(size);

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

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

    new_block = alloc_memdom_pool(domain->memdom_pool, domain->pool_size,
				  false, domain->label, size);
    rlog("[%s] Allocated obj %p in domain %s\n", __func__, new_block, domain->label);
 out:
    pthread_mutex_unlock(&security_ctx_mutex);
    return new_block;
}

static pyr_dom_alloc_t *get_data_obj_domain(void *addr) {
  dom_list_t *dom_item = runtime->obj_domains_list;
  pyr_dom_alloc_t *dalloc = NULL;
  
  pthread_mutex_lock(&security_ctx_mutex);
  while(dom_item) {
    dalloc = get_dom_alloc(addr, dom_item->domain->memdom_pool);
    if (dalloc) {
      goto out;
    }
    dom_item = dom_item->next;
  }
 out:
  pthread_mutex_unlock(&security_ctx_mutex);
  return dalloc;
}

void pyr_data_obj_free(void *addr) {
    pyr_data_obj_t *obj = NULL;
    pyr_dom_alloc_t *dalloc = NULL;

    if (is_build)
      free(addr);

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    if (!runtime)
        return;

    dalloc = get_data_obj_domain(addr);
    if (!dalloc)
        goto out;

    pthread_mutex_lock(&security_ctx_mutex);
    rlog("[%s] Obj at %p in domain %d\n", __func__, addr, dalloc->memdom_id);
    if (!dalloc->writable_main)
      memdom_priv_add(dalloc->memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
    memdom_free(addr);
    if (!dalloc->writable_main)
      memdom_priv_del(dalloc->memdom_id, MAIN_THREAD, MEMDOM_WRITE);

 out:
    pthread_mutex_unlock(&security_ctx_mutex);
}

// This is likely going to be used by the interpreter's garbage collector
int pyr_is_isolated_data_obj(void *addr) {
    int is_data_obj = 0;

    if (is_build)
        return 0;

    if (!runtime)
        return 0;
    
    return (get_data_obj_domain(addr) != NULL);
}

int pyr_is_sandboxed(char *sandbox_name) {
  pyr_func_sandbox_t *sb = NULL;

  if (is_build)
    return 0;
  
  // suspend if the stack tracer thread is running
  pyr_is_inspecting();
  
  // let's skip adding write privs if our runtime
  // doesn't have a domain or our domain is invalid
  if (!runtime) {
    return 0;
  }
 
  pthread_mutex_lock(&security_ctx_mutex);
  sb = find_sandbox(sandbox_name, runtime->func_sandboxes);
  pthread_mutex_unlock(&security_ctx_mutex);
  
  return (sb != NULL);
}

void pyr_grant_data_obj_write(void *op) {
  pyr_dom_alloc_t * obj_dom = NULL;
  
  if (is_build)
    return;
  
  // suspend if the stack tracer thread is running
  pyr_is_inspecting();
  
  // let's skip adding write privs if our runtime
  // doesn't have a domain or our domain is invalid
  if (!runtime) {
    return;
  }
  
  if (!op) 
    return;

  obj_dom = get_data_obj_domain(op);
  if (!obj_dom)
    return;
  
  pthread_mutex_lock(&security_ctx_mutex);
  if (!obj_dom->writable_main) {
    memdom_priv_add(obj_dom->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
    // don't set writable flag to true since it's used to be on
    // iff the interpreter is executing within a sandbox that has write
    // access to this domain
    rlog("[%s] Object %p\n", __func__, op);
  }
  pthread_mutex_unlock(&security_ctx_mutex);
}

void pyr_revoke_data_obj_write(void *op) {
  pyr_dom_alloc_t * obj_dom = NULL;
  
  if (is_build)
    return;
  
  // suspend if the stack tracer thread is running
  pyr_is_inspecting();
  
  // let's skip adding write privs if our runtime
  // doesn't have a domain or our domain is invalid
  if (!runtime) {
    return;
  }
  
  if (!op) 
    return;

  obj_dom = get_data_obj_domain(op);
  if (!obj_dom)
    return;
  
  pthread_mutex_lock(&security_ctx_mutex);
  if (!obj_dom->writable_main) {
    memdom_priv_del(obj_dom->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
    rlog("[%s] Object %p\n", __func__, op);
  }
  pthread_mutex_unlock(&security_ctx_mutex);
}

/** Grants the main thread write access to the data object domains
 * for the given function sandbox.
 */
static pyr_func_sandbox_t *pyr_grant_sandbox_access(char *sandbox_name) {
    pyr_func_sandbox_t *sb = NULL;

    /*    if (!strncmp(sandbox_name, "tweepy", 6))
          printf("[%s] Function FQN %s\n", __func__, sandbox_name);*/

    pthread_mutex_lock(&security_ctx_mutex);
    sb = find_sandbox(sandbox_name, runtime->func_sandboxes);
    if (!sb)
        goto out;

    if (sb->in_sandbox) {
        printf("[%s] already in sandbox\n", __func__);
        goto out;
    }

    obj_list_t *ro_objs = sb->read_only;
    while (ro_objs) {
        pyr_data_obj_t *ro_obj = ro_objs->obj;
        pyr_data_obj_domain_t *dom = find_domain(ro_obj->domain_label, runtime->obj_domains_list);
	if (dom) {
	  pyr_dom_alloc_t *dalloc = dom->memdom_pool;
	  while(dalloc) {
	    if (dalloc->has_space) {
	      memdom_priv_add(dalloc->memdom_id, MAIN_THREAD, MEMDOM_READ);
	    }
	    dalloc = dalloc->next;
	  }
	  rlog("[%s] Add read privilege to domain %s for sandbox %s\n",
	       __func__, dom->label, sandbox_name);
	}
        ro_objs = ro_objs->next;
    }

    pyr_data_obj_t *rw_obj = sb->read_write;
    if (rw_obj) {
        pyr_data_obj_domain_t *dom = find_domain(rw_obj->domain_label, runtime->obj_domains_list);
        if (dom) {
	  pyr_dom_alloc_t *dalloc = dom->memdom_pool;
	  while(dalloc) {
	    if (dalloc->has_space && !dalloc->writable_main) {
	      memdom_priv_add(dalloc->memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
	      dalloc->writable_main = true;
	    }
	    dalloc = dalloc->next;
	  }
	  rlog("[%s] Add read/write privilege to domain %s for sandbox %s\n",
		 __func__, dom->label, sandbox_name);
        }
    }

    sb->in_sandbox = true;
 out:
    pthread_mutex_unlock(&security_ctx_mutex);
    return sb;
}

// Abstract away all operations that need to happen before
// entering a function sandbox
void pyr_enter_sandbox(char *sandbox_name) {
    pyr_func_sandbox_t *sb = NULL;
    if (is_build)
      return;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    if (!runtime) {
        return;
    }

    sb = pyr_grant_sandbox_access(sandbox_name);
    if (sb) {
        cur_sandbox = sb;
    }
}

/** Revokes the main thread write access to the data object domains
 * for the given function sandbox.
 */
static void pyr_revoke_sandbox_access(char *sandbox_name) {
    pyr_func_sandbox_t *sb = NULL;

    pthread_mutex_lock(&security_ctx_mutex);
    sb = find_sandbox(sandbox_name, runtime->func_sandboxes);
    if (!sb)
        goto out;

    if (!sb->in_sandbox)
        goto out;

    obj_list_t *ro_objs = sb->read_only;
    while (ro_objs) {
        pyr_data_obj_t *ro_obj = ro_objs->obj;
        pyr_data_obj_domain_t *dom = find_domain(ro_obj->domain_label, runtime->obj_domains_list);
	if (dom) {
	  pyr_dom_alloc_t *dalloc = dom->memdom_pool;
	  while(dalloc) {
	    if (dalloc->has_space) {
	      //memdom_priv_del(dalloc->memdom_id, MAIN_THREAD, MEMDOM_READ);
	    }
	    dalloc = dalloc->next;
	  }
	  rlog("[%s] Revoked read privilege to domain %s for sandbox %s\n",
	       __func__, dom->label, sandbox_name);
	}
        ro_objs = ro_objs->next;
    }

    pyr_data_obj_t *rw_obj = sb->read_write;
    if (rw_obj) {
        pyr_data_obj_domain_t *dom = find_domain(rw_obj->domain_label, runtime->obj_domains_list);
        if (dom) {
	  pyr_dom_alloc_t *dalloc = dom->memdom_pool;
	  while(dalloc) {
	    if (dalloc->writable_main) {
	      memdom_priv_del(dalloc->memdom_id, MAIN_THREAD, MEMDOM_WRITE);
	      dalloc->writable_main = false;
	    }
	    dalloc = dalloc->next;
	  }
	  rlog("[%s] Revoked read/write privilege to domain %s for sandbox %s\n",
		 __func__, dom->label, sandbox_name);
        }
    }

    sb->in_sandbox = false;
 out:
    pthread_mutex_unlock(&security_ctx_mutex);
}

void pyr_exit_sandbox() {
    pyr_func_sandbox_t *sb = NULL;
    bool in_sb = false;

    if (is_build)
      return;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return;
    }

    if (!cur_sandbox)
      return;
    
    pyr_revoke_sandbox_access(cur_sandbox->func_name);
    cur_sandbox = NULL;
}

int pyr_in_sandbox() {
    pyr_func_sandbox_t *sb = NULL;
    bool in_sb = false;

    if (is_build)
      return false;

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return false;
    }

    pthread_mutex_lock(&security_ctx_mutex);
    if (!cur_sandbox)
      goto out;

    in_sb = cur_sandbox->in_sandbox;
 out:
    pthread_mutex_unlock(&security_ctx_mutex);
    return in_sb;
}

pyr_data_obj_t *pyr_get_sandbox_rw_obj() {
    pyr_func_sandbox_t *sb = NULL;
    pyr_data_obj_t *rw_obj = NULL;

    if (is_build)
      return NULL;

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime) {
        return NULL;
    }

    pthread_mutex_lock(&security_ctx_mutex);
    if (!cur_sandbox)
      goto out;

    rw_obj = cur_sandbox->read_write;
    if (rw_obj) {
        rlog("[%s] Found RW object %s in domain %s for current sandbox %s\n",
               __func__, rw_obj->name, rw_obj->domain_label,
               cur_sandbox->func_name);
    }

 out:
    pthread_mutex_unlock(&security_ctx_mutex);
    return rw_obj;
}

/**** PYRONIA THREAD API ****/

/** Starts an SMV thread that has access to the MAIN_THREAD memdom.
 * I.e. this is a wrapper for smvthread_create that is supposed to be used
 * in the language runtime as a replacement for all pthread_create calls.
 * This is needed because SMV doesn't allow you to spawn other smvthreads
 * to run in the MAIN_THREAD smv.
 */
int pyr_thread_create(pthread_t* tid, const pthread_attr_t *attr,
                      void*(fn)(void*), void* args) {
    int ret = 0;
    struct pyr_thread *new_th = NULL;
#ifdef PYR_INTERCEPT_PTHREAD_CREATE
#undef pthread_create
#endif

    // suspend if the stack tracer thread is running
    pyr_is_inspecting();

    ret = smvthread_create_attr(pyr_smv_id, tid, attr, fn, args);
#ifdef PYR_INTERCEPT_PTHREAD_CREATE
    if (ret > 0)
      ret = 0; // users of pthread_create expect status 0 on success
#define pthread_create(tid, attr, fn, args) pyr_thread_create(tid, attr, fn, args)
#endif
    ret = new_pyr_thread(&new_th, *tid, pyr_smv_id);
    pthread_mutex_lock(&security_ctx_mutex);
    if (!ret) {
      new_th->next = runtime->pyr_threads;
      runtime->pyr_threads = new_th;
      printf("[%s] Added new Pyr thread %lu\n", __func__, new_th->self);
    }
    num_pyr_threads++;
    pthread_mutex_unlock(&security_ctx_mutex);
    
    printf("[%s] Created new Pyronia thread to run in SMV %d\n", __func__, pyr_smv_id);
    return ret;
}

static void pyr_thread_setup() {
  // create another SMV to be used by threads originally created by
  // pthread_create. We won't allow mixing pthreads woth smvthreads
  pyr_smv_id = smv_create();
  if (pyr_smv_id == -1) {
    printf("[%s] Could not create an SMV for pyronia threads\n", __func__);
    return;
  }

  // We need this SMV to be able to access any Python functions
  smv_join_domain(MAIN_THREAD, pyr_smv_id);
  memdom_priv_add(MAIN_THREAD, pyr_smv_id, MEMDOM_READ | MEMDOM_WRITE);

  pyr_dom_alloc_t *dalloc = runtime->interp_doms;
  while(dalloc) {
    smv_join_domain(dalloc->memdom_id, pyr_smv_id);
    memdom_priv_add(dalloc->memdom_id, pyr_smv_id, MEMDOM_READ);
    dalloc = dalloc->next;
  }
}

// Assumes caller holds security_ctx_mutex
static struct pyr_thread *get_cur_pyr_thread() {
    struct pyr_thread *th = runtime->pyr_threads;
    pthread_t cur_thread = pthread_self();

    while (th != NULL) {
        if (pthread_equal(th->self, cur_thread)) {
            return th;
        }
    }
    return NULL;
}

/**** SI API ****/

/** Starts the SI listener and dispatch thread.
 */
void pyr_callstack_req_listen() {
    pthread_attr_t attr;
    int i = 0;
    si_memdom = -1;

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

    si_memdom = memdom_create();
    if (si_memdom == -1) {
        printf("[%s] Could not create SI thread memdom\n", __func__);
    }
    rlog("SI memdom = %d\n", si_memdom);
    smv_join_domain(si_memdom, si_smv_id);
    memdom_priv_add(si_memdom, si_smv_id, MEMDOM_READ | MEMDOM_WRITE);

    pyr_dom_alloc_t *dalloc = runtime->interp_doms;
    while(dalloc) {
      smv_join_domain(dalloc->memdom_id, si_smv_id);
      memdom_priv_add(dalloc->memdom_id, si_smv_id, MEMDOM_READ);
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
    memdom_kill(si_memdom);
    pyr_grant_critical_state_write((void *)runtime->main_path);
    if (runtime->main_path)
      pyr_free_critical_state(runtime->main_path);
    pyr_security_context_free(&runtime);
    rlog("[%s] Done\n", __func__);
}

/** Wrapper around the runtime callstack collection callback
 * to be called by the si_comm component in handle_callstack_request.
 */
pyr_cg_node_t *pyr_collect_runtime_callstack() {
    pyr_cg_node_t *cg = NULL;
    bool in_sb = false;
    if (!runtime)
      return NULL;
    // if we're inspecting, we don't want sandbox memory mgmt
    // to apply, so save the sandbox status, and proceed
    if (cur_sandbox && cur_sandbox->in_sandbox) {
      in_sb = true;
      cur_sandbox->in_sandbox = false;
    }
    runtime->interpreter_lock_acquire_cb();
    cg = runtime->collect_callstack_cb();
    runtime->interpreter_lock_release_cb();
    // restore the sandbox status
    if (in_sb)
      cur_sandbox->in_sandbox = true;
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

    pyr_cg_node_t *n = memdom_alloc(si_memdom, sizeof(pyr_cg_node_t));

    if (n == NULL) {
        goto fail;
    }

    n->lib = memdom_alloc(si_memdom, strlen(lib)+1);
    if (!n->lib) {
        goto fail;
    }

    memset(n->lib, 0, strlen(lib)+1);
    memcpy(n->lib, lib, strlen(lib));
    n->data_type = data_type;
    n->child = child;

    *cg_root = n;
    return 0;
 fail:
    memdom_free(n);
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

    memdom_free(n->lib);
    memdom_free(n);
    *node = NULL;
}

// Free a callgraph
void pyr_free_callgraph(pyr_cg_node_t **cg_root) {
    free_node(cg_root);
}
