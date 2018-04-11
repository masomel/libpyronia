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
#include <sys/syscall.h>
#include <linux/pyronia_mac.h>
#include <smv_lib.h>
#include <memdom_lib.h>

#include "pyronia_lib.h"
#include "security_context.h"
#include "serialization.h"
#include "si_comm.h"
#include "util.h"

static struct pyr_runtime *runtime;

static void free_runtime(struct pyr_runtime **rtp) {
    struct pyr_runtime *r = *rtp;

    if (!r)
        return;

    pyr_security_context_free(&r->security_context);
    r->collect_callstack_cb = NULL;
    memdom_free(r);
    *rtp = NULL;
}

static int init_runtime(pyr_cg_node_t *(*collect_callstack)(void)) {
    struct pyr_runtime *r = NULL;
    int err = 0;
    int interp_memdom = -1;

    if ((interp_memdom = memdom_create()) == -1) {
        goto fail;
    }

    // don't forget to add the main thread to this memdom
    smv_join_domain(interp_memdom, MAIN_THREAD);
    memdom_priv_add(interp_memdom, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);

    // we want this to be allocated this in the interpreter memdom
    r = memdom_alloc(interp_memdom, sizeof(struct pyr_runtime));
    if (!r) {
        printf("[%s] No memory for runtime properties\n", __func__);
        err = -ENOMEM;
        goto fail;
    }

    err = pyr_security_context_alloc(&r->security_context, interp_memdom);
    if (err)
        goto fail;

    if (!collect_callstack) {
        printf("[%s] Need non-null callstack collect callback\n", __func__);
        err = -EINVAL;
        goto fail;
    }
    r->collect_callstack_cb = collect_callstack;

    runtime = r;

    printf("[%s] Successfully initialized the runtime\n", __func__);
    return 0;
 fail:
    free_runtime(&r);
    runtime = NULL;
    return err;
}

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

    /* Initialize the runtime metadata */
    err = init_runtime(collect_callstack_cb);
    if (err) {
        printf("[%s] Runtime initialization failure\n", __func__);
        goto out;
    }

    /* Parse the library policy from disk */
    err = pyr_parse_lib_policy(lib_policy_file, &policy);
    if (err < 0) {
        printf("[%s] Parsing lib policy failure\n", __func__);
        goto out;
    }

    /* Initialize the stack inspection communication channel with
     * the kernel */
    err = pyr_init_si_comm(policy);
    if (err) {
        printf("[%s] SI comm channel initialization failed\n", __func__);
        goto out;
    }

 out:
    if (policy)
      memdom_free(policy);
    /* Revoke access to the interpreter domain now */
    pyr_revoke_critical_state_write();
    return err;
}

/** Wrapper around memdom_alloc in the interpreter domain.
 */
void *pyr_alloc_critical_runtime_state(size_t size) {
    if (!runtime || runtime->interp_dom < 1)
        return NULL;

    printf("[%s] %lu bytes\n", __func__, size);

    return memdom_alloc(runtime->interp_dom, size);
}

/** Grants the main thread write access to the interpreter domain.
 */
void pyr_grant_critical_state_write() {
    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime || runtime->interp_dom < 1) {
        return;
    }

    printf("[%s]\n", __func__);

    memdom_priv_add(runtime->interp_dom, MAIN_THREAD, MEMDOM_WRITE);
}

/** Revokes the main thread's write privileges to the interpreter domain.
 */
void pyr_revoke_critical_state_write() {
    // let's skip adding write privs if our runtime
    // doesn't have a domain or our domain is invalid
    if (!runtime || runtime->interp_dom < 1) {
        return;
    }

    printf("[%s]\n", __func__);

    memdom_priv_delete(runtime->interp_dom, MAIN_THREAD, MEMDOM_WRITE);
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

/* Do all necessary teardown actions. */
void pyr_exit() {
    int interp_dom = runtime->interp_dom;

    printf("[%s] Exiting Pyronia runtime\n", __func__);

    pyr_teardown_si_comm();
    free_runtime(&runtime);
    smv_leave_domain(interp_dom, MAIN_THREAD);
}

/** Wrapper around the runtime callstack collection callback
 * to be called by the si_comm component in handle_callstack_request.
 */
pyr_cg_node_t *pyr_runtime_collect_callstack() {
    return runtime->collect_callstack_cb();
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
