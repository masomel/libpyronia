/** Contains the Pyronia security context definitions used in Pyronia-aware
 * language runtimes to isolate security-critical runtime state and
 * native libraries into memory domains.
 *
 *@author Marcela S. Melara
 */

#ifndef __PYR_SEC_CTX_H
#define __PYR_SEC_CTX_H

#include <stdbool.h>

#define MAX_NUM_INTERP_DOMS 256
#define MAX_OBJ_DOM_POOL_SIZE 5

struct pyr_thread {
  pthread_t self;
  int smv_id;
  struct pyr_thread *next;
};

struct pyr_dom_alloc {
    int memdom_id;
    void *start;
    size_t size;
    bool has_space;
    bool writable_main;
    int pyr_thread_refcnt;
    struct pyr_dom_alloc *next;
};

typedef struct pyr_dom_alloc pyr_dom_alloc_t;

// foward declaration
struct pyr_cg_node;
typedef struct pyr_cg_node pyr_cg_node_t;

#include "data_obj.h"

/* A language runtime's security context:
 * Used for pyronia-related bookkeeping */
struct pyr_security_context {
    char *main_path;
    pyr_func_sandbox_t *func_sandboxes;
    obj_list_t *data_objs_list;
    dom_list_t *obj_domains_list;
    pyr_dom_alloc_t *interp_doms;
    /* The runtime may grant write access to the critical state
     * in a function that calls another function that grants access
     * itself. To make sure we don't revoke access to the outer
     * functions, let's basically keep a reference count. */
    uint32_t nested_grants;

    struct pyr_thread *pyr_threads;
  
    /* The function used to collect a language runtime-specific
     * callstack. This callback needs to be set at initialization time. */
    pyr_cg_node_t *(*collect_callstack_cb)(void);
    void (*interpreter_lock_acquire_cb)(void);
    void (*interpreter_lock_release_cb)(void);
};

#ifdef __cplusplus
extern "C" {
#endif

    int pyr_security_context_alloc(struct pyr_security_context **ctxp,
                                   pyr_cg_node_t *(*collect_callstack_cb)(void),
                                   void (*interpreter_lock_acquire_cb)(void),
                                   void (*interpreter_lock_release_cb)(void));
    void pyr_security_context_free(struct pyr_security_context **ctxp);
    int pyr_parse_data_obj_rules(char **obj_rules, int num_rules,
                                 struct pyr_security_context **ctx);
    int new_dom_alloc(pyr_dom_alloc_t **domp);
    int new_pyr_thread(struct pyr_thread **thp, pthread_t tid, int smv_id);

#ifdef __cplusplus
}
#endif

#endif
