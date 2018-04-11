/** Contains the Pyronia security context library used in Pyronia-aware
 * language runtimes to isolate security-critical runtime state and
 * native libraries into memory domains.
 *
 *@author Marcela S. Melara
 */
#include <stdlib.h>
#include <errno.h>
#include <memdom_lib.h>

#include "security_context.h"

int pyr_native_lib_context_alloc(pyr_native_ctx_t **ctxp, void *mod,
                                 pyr_native_ctx_t *next) {
    int err;
    pyr_native_ctx_t *c;

    c = malloc(sizeof(pyr_native_ctx_t));
    if (!c)
        return -ENOMEM;

    c->native_dom = memdom_create();
    if (c->native_dom == -1) {
        err = -EINVAL;
        goto fail;
    }

    c->native_module = mod;
    c->next = next;

    *ctxp = c;
    return 0;
 fail:
    if (c)
        free(c);
    return err;
}

int pyr_security_context_alloc(struct pyr_security_context **ctxp) {
    int err;
    struct pyr_security_context *c;

    c = malloc(sizeof(struct pyr_security_context));
    if (!c)
        return -ENOMEM;

    c->interp_dom = memdom_create();
    if (c->interp_dom == -1) {
        err = -EINVAL;
        goto fail;
    }

    // this list will be added to whenever a new non-builtin extenion
    // is loaded via dlopen
    c->native_libs = NULL;

    *ctxp = c;
    return 0;
 fail:
    if (c)
        free(c);
    return err;
}

void pyr_native_lib_context_free(pyr_native_ctx_t **ctxp) {

}

void pyr_security_context_free(struct pyr_security_context **ctxp) {

}
