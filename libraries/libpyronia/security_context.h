/** Contains the Pyronia security context definitions used in Pyronia-aware
 * language runtimes to isolate security-critical runtime state and
 * native libraries into memory domains.
 *
 *@author Marcela S. Melara
 */

#ifndef __PYR_SEC_CTX_H
#define __PYR_SEC_CTX_H

struct pyr_native_lib_context {
    int native_dom; // the memdom this native module belongs to
    void *native_module; // a pointer to the native module
    // points to the next native lib context in the linked list
    struct pyr_native_lib_context *next;
};

typedef struct pyr_native_lib_context pyr_native_ctx_t;

struct pyr_security_context {
    int interp_dom;
    pyr_native_ctx_t *native_libs;
};

#ifdef __cplusplus
extern "C" {
#endif

    int pyr_native_lib_context_alloc(pyr_native_ctx_t **ctxp, void *mod,
                                     pyr_native_ctx_t *next);
    int pyr_security_context_alloc(struct pyr_security_context **ctxp);
    void pyr_native_lib_context_free(pyr_native_ctx_t **ctxp);
    void pyr_security_context_free(struct pyr_security_context **ctxp);

#ifdef __cplusplus
}
#endif

#endif
