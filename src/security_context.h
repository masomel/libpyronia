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
    int smv_id; // the smv defining this native library's memdom access
    // points to the next native lib context in the linked list
    struct pyr_native_lib_context *next;
};

typedef struct pyr_native_lib_context pyr_native_ctx_t;

/* Used to keep track of memory blocks allocated
 * in the interpreter domain. This metadata structure helps
 * avoid downcalls querying for an isolated buffer's memdom. */
struct allocation_record {
    void *addr;
    struct allocation_record *next;
};

// foward declaration
struct pyr_cg_node;
typedef struct pyr_cg_node pyr_cg_node_t;

/* A language runtime's security context:
 * Used for pyronia-related bookkeeping */
struct pyr_security_context {
    int interp_dom;
    pyr_native_ctx_t *native_libs;
    /* The runtime may grant write access to the critical state
     * in a function that calls another function that grants access
     * itself. To make sure we don't revoke access to the outer
     * functions, let's basically keep a reference count. */
    uint32_t nested_grants;
    struct allocation_record *alloc_blocks;

    /* The function used to collect a language runtime-specific
     * callstack. This callback needs to be set at initialization time. */
    pyr_cg_node_t *(*collect_callstack_cb)(void);
};

#ifdef __cplusplus
extern "C" {
#endif

    int pyr_new_native_lib_context(pyr_native_ctx_t **ctxp, const char *lib);
    int pyr_security_context_alloc(struct pyr_security_context **ctxp,
                                   pyr_cg_node_t *(*collect_callstack_cb)(void));
    int pyr_add_new_alloc_record(struct pyr_security_context *ctx,
                                 void *addr);
    void pyr_remove_allocation_record(struct pyr_security_context *ctx, void *addr);
    int pyr_find_native_lib_smv(pyr_native_ctx_t *start, const char *lib);
    void pyr_security_context_free(struct pyr_security_context **ctxp);

#ifdef __cplusplus
}
#endif

#endif
