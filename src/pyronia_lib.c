/* Main Pyronia userspace API.
*
*@author Marcela S. Melara
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
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
#include "cpython_exts.h"

static struct pyr_security_context *runtime;
static pthread_mutex_t security_ctx_mutex;
static int pyr_smv_id = -1;

/** Do all the necessary setup for a language runtime to use
 * the Pyronia extensions: open the stack inspection communication
 * channel and initialize the SMV backend.
 * Note: This function revokes access to the interpreter domain at the end.
 */
int pyr_init(const char *lib_policy_file,
             pyr_cg_node_t *(*collect_callstack_cb)(void)) {
    int err = 0;
    char *policy = NULL;

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

    /* Initialize the runtime's security context */
    err = pyr_security_context_alloc(&runtime, collect_callstack_cb);
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

    pthread_mutex_init(&security_ctx_mutex, NULL);

    pyr_callstack_req_listen();

 out:
    if (policy)
      pyr_free_critical_state(policy);
    /* Revoke access to the interpreter domain now */
    pyr_revoke_critical_state_write();
    return err;
}

/** Wrapper around memdom_alloc in the interpreter domain.
 */
void *pyr_alloc_critical_runtime_state(size_t size) {
    void *new_block = NULL;

    if (!runtime || runtime->interp_dom < 1)
        return NULL;

    printf("[%s] %lu bytes\n", __func__, size);

    pthread_mutex_lock(&security_ctx_mutex);

    new_block = memdom_alloc(runtime->interp_dom, size);
    if (!new_block)
        return NULL;

    if (pyr_add_new_alloc_record(runtime, new_block) == -1) {
        memdom_free(new_block);
        new_block = NULL;
    }
    pthread_mutex_unlock(&security_ctx_mutex);

    return new_block;
}

/** Wrapper around memdom_free in the interpreter domain.
 * Returns 1 if the state was freed, 0 otherwise.
 */
int pyr_free_critical_state(void *op) {
    if (!runtime)
        return 0;

    if (runtime->interp_dom > 0 && pyr_is_critical_state(op)) {
        pyr_grant_critical_state_write();
        pthread_mutex_lock(&security_ctx_mutex);
        pyr_remove_allocation_record(runtime, op);
        memdom_free(op);
        pthread_mutex_unlock(&security_ctx_mutex);
        printf("[%s] Freed %p\n", __func__, op);
        pyr_revoke_critical_state_write();
        return 1;
    }
    return 0;
}

/** Wrapper around memdom_query_id. Returns 1 if the
 * given pointer is in the interpreter_dom, 0 otherwise.
 */
int pyr_is_critical_state(void *op) {
    struct allocation_record *runner;
    int ret = 0;
    if (!runtime)
        return 0;

    pthread_mutex_lock(&security_ctx_mutex);
    runner = runtime->alloc_blocks;
    while(runner) {
        if (runner->addr == op) {
          printf("[%s] Found interpreter memory block for addr %p at %p\n", __func__, runner->addr, runner);
            ret = 1;
            goto out;
        }
        runner = runner->next;
    }
 out:
    pthread_mutex_unlock(&security_ctx_mutex);
    return ret;
}

/** Grants the main thread write access to the interpreter domain.
 */
void pyr_grant_critical_state_write() {
    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime || runtime->interp_dom < 1) {
        return;
    }

    pthread_mutex_lock(&security_ctx_mutex);

    // slight optimization: if we've already granted access
    // let's avoid another downcall to change the memdom privileges
    // and simply keep track of how many times we've granted access
    if (runtime->nested_grants == 0) {
      memdom_priv_add(runtime->interp_dom, MAIN_THREAD, MEMDOM_WRITE);
    }

    runtime->nested_grants++;
    pthread_mutex_unlock(&security_ctx_mutex);
}

/** Revokes the main thread's write privileges to the interpreter domain.
 */
void pyr_revoke_critical_state_write() {
    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime || runtime->interp_dom < 1) {
        return;
    }

    pthread_mutex_lock(&security_ctx_mutex);
    runtime->nested_grants--;

    // same optimization as above
    if (runtime->nested_grants == 0) {
      memdom_priv_del(runtime->interp_dom, MAIN_THREAD, MEMDOM_WRITE);
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
    ret = smvthread_create_attr(pyr_smv_id, tid, attr, fn, args);
#ifdef PYR_INTERCEPT_PTHREAD_CREATE
#define pthread_create(tid, attr, fn, args) pyr_thread_create(tid, attr, fn, args)
#endif
    printf("[%s] Created new Pyronia thread to run in SMV %d\n", __func__, pyr_smv_id);
    return ret;
}

/** Loads the given native library into its own memory domain.
 */
int pyr_load_native_lib_isolated(const char *lib) {
    // FIXME
    return 0;
}

/** Runs the given python function belonging to the given library in
 * in an isolated compartment (i.e. SMV).
 */
void *pyr_run_native_func_isolated_python(char *lib, void *func, void* self,
                                          void *args, void *kwargs) {
    int smv_id = -1;
    pthread_t tid;
    void *ret = NULL;
    struct python_wrapper_args *wrapper_args = NULL;

    pthread_mutex_lock(&security_ctx_mutex);
    smv_id = pyr_find_native_lib_smv(runtime->native_libs, lib);
    if (smv_id <= pyr_smv_id) {
        goto out;
    }

    wrapper_args = pyr_python_make_wrapper_args(lib, func, self, args, kwargs);

    if (!wrapper_args)
        goto out;

    smvthread_create(smv_id, &tid, pyr_python_func_wrapper, wrapper_args);
    pthread_join(tid, &ret);
out:
    pthread_mutex_unlock(&security_ctx_mutex);
    return ret;
}

/** Starts the SI listener and dispatch thread.
 */
void pyr_callstack_req_listen() {
    pthread_attr_t attr;
    int smv_id = -1;
    pthread_t recv_th;

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
    smv_join_domain(runtime->interp_dom, smv_id);
    memdom_priv_add(runtime->interp_dom, smv_id, MEMDOM_READ | MEMDOM_WRITE);

    smvthread_create_attr(smv_id, &recv_th, &attr, pyr_recv_from_kernel, NULL);
}

/* Do all necessary teardown actions. */
void pyr_exit() {
    int interp_dom = runtime->interp_dom;

    printf("[%s] Exiting Pyronia runtime\n", __func__);

    pyr_teardown_si_comm();
    pyr_grant_critical_state_write();
    pyr_security_context_free(&runtime);
    memdom_kill(interp_dom);
    pyr_revoke_critical_state_write();
    pthread_mutex_destroy(&security_ctx_mutex);
}

/** Wrapper around the runtime callstack collection callback
 * to be called by the si_comm component in handle_callstack_request.
 */
pyr_cg_node_t *pyr_collect_runtime_callstack() {
    return runtime->collect_callstack_cb();
}

/** Getter for the native library contexts */
pyr_native_ctx_t *pyr_get_native_library_contexts() {
    return runtime->native_libs;
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
