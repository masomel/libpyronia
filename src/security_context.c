/** Implements the Pyronia security context library used for
 * isolating security-critical runtime state and native libraries
 * into memory domains in Pyronia-aware language runtimes.
 *
 *@author Marcela S. Melara
 */
#include <stdlib.h>
#include <errno.h>
#include <memdom_lib.h>

#include "security_context.h"
#include "util.h"

static void pyr_native_lib_context_free(pyr_native_ctx_t **ctxp) {
    pyr_native_ctx_t *c = *ctxp;

    if (!c)
        return;

    if (c->next != NULL)
        pyr_native_lib_context_free(&c->next);

    if (c->library_name)
        memdom_free(c->library_name);
    if (c->memdom_id > 0)
        memdom_kill(c->memdom_id);
    memdom_free(c);
    *ctxp = NULL;
}

/* This functions allocates a new native library context.
 * A new memory domain is created as part of this process
 * so the native library can loaded into the memory domain
 * on dynload time.
 * Note: This function must be called BEFORE the native module
 * is loaded */
int pyr_new_native_lib_context(pyr_native_ctx_t **ctxp, const char *lib,
                               pyr_native_ctx_t *next) {
    int err = -1;
    pyr_native_ctx_t *c = NULL;

    c = pyr_alloc_critical_runtime_state(sizeof(pyr_native_ctx_t));
    if (!c)
        return -ENOMEM;

    if (set_str(lib, &c->library_name))
        goto fail;

    c->memdom_id = memdom_create();
    if (c->memdom_id == -1) {
        err = -EINVAL;
        goto fail;
    }

    c->next = next;

    *ctxp = c;
    return 0;
 fail:
    pyr_native_lib_context_free(&c);
    *ctxp = NULL;
    return err;
}

int pyr_security_context_alloc(struct pyr_security_context **ctxp,
			       pyr_cg_node_t *(*collect_callstack_cb)(void)) {
    int err = 0;
    struct pyr_security_context *c = NULL;
    int interp_memdom = -1;

    // create the memdom first so this struct
    // can also be allocated in interp_dom
    if ((interp_memdom = memdom_create()) == -1) {
        goto fail;
    }

    // don't forget to add the main thread to this memdom
    smv_join_domain(interp_memdom, MAIN_THREAD);
    memdom_priv_add(interp_memdom, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);

    // we want this to be allocated in the interpreter memdom
    c = memdom_alloc(interp_memdom, sizeof(struct pyr_security_context));
    if (!c) {
        printf("[%s] No memory for runtime security context\n", __func__);
        err = -ENOMEM;
        goto fail;
    }

    c->interp_dom = interp_memdom;
    
    if (!collect_callstack_cb) {
        printf("[%s] Need non-null callstack collect callback\n", __func__);
        err = -EINVAL;
        goto fail;
    }
    c->collect_callstack_cb = collect_callstack_cb;

    // this list will be added to whenever a new non-builtin extenion
    // is loaded via dlopen
    c->native_libs = NULL;

    *ctxp = c;
    return 0;
 fail:
    if (c)
        memdom_free(c);
    *ctxp = NULL;
    return err;
}

int pyr_find_native_lib_memdom(pyr_native_ctx_t *start, const char *lib) {
    pyr_native_ctx_t *runner = start;

    while (runner != NULL) {
        if (!strncmp(runner->library_name, lib, strlen(lib))) {
	    printf("[%s] Found memdom %d\n", __func__, runner->memdom_id);
            return runner->memdom_id;
        }
    }
    return -1;
}

void pyr_security_context_free(struct pyr_security_context **ctxp) {
    struct pyr_security_context *c = *ctxp;

    if (!c)
        return;

    pyr_native_lib_context_free(&c->native_libs);

    if (c->interp_dom > 0)
        memdom_kill(c->interp_dom);

    memdom_free(c);
    *ctxp = NULL;
}
