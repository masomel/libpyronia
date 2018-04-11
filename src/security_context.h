/** Contains the Pyronia security context definitions used in Pyronia-aware
 * language runtimes to isolate security-critical runtime state and
 * native libraries into memory domains.
 *
 *@author Marcela S. Melara
 */

#ifndef __PYR_SEC_CTX_H
#define __PYR_SEC_CTX_H

struct pyr_native_lib_context {
    char *library_name; // runtimes also identify libraries by string name
    int memdom_id; // the memdom this native library belongs to
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

    int pyr_new_native_lib_context(pyr_native_ctx_t **ctxp, const char *lib,
                                   pyr_native_ctx_t *next);
    int pyr_security_context_alloc(struct pyr_security_context **ctxp,
                                   int memdom_id);
    int pyr_find_native_lib_memdom(pyr_native_ctx_t *start, const char *lib);
    void pyr_security_context_free(struct pyr_security_context **ctxp);

#ifdef __cplusplus
}
#endif

#endif
