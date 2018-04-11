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

#include "pyronia_lib.h"
#include "serialization.h"
#include "si_comm.h"
#include "util.h"

static struct pyr_runtime *runtime;

static int init_runtime(pyr_cg_node_t *(*collect_callstack)(void)) {
    struct pyr_runtime *r;
    int err = 0;

    // TODO: allocate this in the secure memdom
    r = malloc(sizeof(struct pyr_runtime));
    if (!r) {
        printf("[%s] No memory for runtime properties\n", __func__);
        err = -ENOMEM;
        goto fail;
    }

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
    if (r)
        free(r);
    return err;
}

/* Do all the necessary setup for a language runtime to use
 * the Pyronia extensions: open the stack inspection communication
 * channel and initialize the SMV backend.
 */
int pyr_init(const char *lib_policy_file,
             pyr_cg_node_t *(*collect_callstack_cb)(void)) {
    int err = 0;
    char *policy = NULL;

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

    printf("[%s] Sent registration message %s (%lu bytes)\n", __func__, reg_str, strlen(reg_str));
    
    /* Start the callstack request receiver thread */
    pyr_callstack_req_listen();

    // We don't want the main thread's memdom to be
    // globally accessible, so init with 0.
    //err = smv_main_init(0);

 out:
    if (policy)
      free(policy);
    return err;
}

// Wrapper around the runtime callstack collection callback
// to be called by the si_comm component in handle_callstack_request.
pyr_cg_node_t *pyr_runtime_collect_callstack() {
    return runtime->collect_callstack_cb();
}

/* Do all necessary teardown actions. */
void pyr_exit() {
  printf("[%s] Exiting Pyronia runtime\n", __func__);

  pyr_teardown_si_comm();
}

/* CALLGRAPH ALLOCATION AND FREE */
/* These mirror the callgraph allocation and free functions.
 * Until we register a new syscall, we need to be careful
 * to keep them in sync. */

// Allocate a new callgraph node
int pyr_new_cg_node(pyr_cg_node_t **cg_root, const char* lib,
                        enum pyr_data_types data_type,
                        pyr_cg_node_t *child) {

    pyr_cg_node_t *n = malloc(sizeof(pyr_cg_node_t));

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
    free(n);
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

    free(n->lib);
    free(n);
    *node = NULL;
}

// Free a callgraph
void pyr_free_callgraph(pyr_cg_node_t **cg_root) {
    free_node(cg_root);
}
