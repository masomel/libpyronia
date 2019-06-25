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
    int memdom_id = -1;

    if (!c)
        return;

    if (c->next != NULL)
        pyr_native_lib_context_free(&c->next);

    printf("[%s] Native context for lib %s\n", __func__, c->library_name);

    if (c->library_name)
        memdom_free(c->library_name);
    if (c->memdom_id > 0) {
        memdom_id = c->memdom_id;
        memdom_free(c);
        memdom_kill(memdom_id);
    }
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

/* Insert a new allocation record at the head of the list.
 * Note: expects caller to hold the memdom lock and the context mutex.
int pyr_add_new_alloc_record(struct pyr_security_context *ctx,
                                void *addr) {
    struct allocation_record *r = NULL;
    if (!ctx || !addr)
      return -1;

    r = memdom_alloc(ctx->interp_dom, sizeof(struct allocation_record));
    if (!r) {
      return -1;
    }

    r->addr = addr;
    r->next = ctx->alloc_blocks;
    ctx->alloc_blocks = r;
    printf("[%s] Allocated new block for addr %p at %p\n", __func__, addr, r);
    return 0;
}

/* Remove the allocation record for the given address.
 * Assumes the address will be freed by the caller.
 * Note: expects the caller to hold the context mutex
void pyr_remove_allocation_record(struct pyr_security_context *ctx, void *addr) {
  struct allocation_record *runner = NULL, *tmp = NULL;

  if (!ctx || !ctx->alloc_blocks)
    return;
  
  runner = ctx->alloc_blocks;

  // check if first entry is the one we need to remove
  if (runner && runner->addr == addr) {
    ctx->alloc_blocks = runner->next;
    memdom_free(runner);
    return;
  }
  
  while(runner->next) {
    if (runner->next->addr == addr) {
      tmp = runner->next;
      runner->next = tmp->next;
      memdom_free(tmp);
      tmp = NULL;
      printf("[%s] Removed block for addr %p\n", __func__, addr);
      break;
    }
    runner = runner->next;
  }
  }*/

int pyr_security_context_alloc(struct pyr_security_context **ctxp,
                               pyr_cg_node_t *(*collect_callstack_cb)(void),
			       void (*interpreter_lock_acquire_cb)(void),
			       void (*interpreter_lock_release_cb)(void)) {
    int err = -1;
    struct pyr_security_context *c = NULL;
    int interp_memdom = -1;
    int i = 0;

    // we want this to be allocated in the interpreter memdom
    c = malloc(sizeof(struct pyr_security_context));
    if (!c)
      goto fail;

    memset(c->interp_doms, 0, MAX_NUM_INTERP_DOMS*sizeof(pyr_interp_dom_alloc_t));
    c->interp_doms[0] = malloc(sizeof(pyr_interp_dom_alloc_t));
    if (!c->interp_doms[0])
      goto fail;
    if ((interp_memdom = memdom_create()) == -1) {
      printf("[%s] Could not create interpreter dom # %d\n", __func__, 1);
      goto fail;
    }
    
    // don't forget to add the main thread to this memdom
    smv_join_domain(interp_memdom, MAIN_THREAD);
    memdom_priv_add(interp_memdom, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
    
    c->interp_doms[0]->memdom_id = interp_memdom;
    c->interp_doms[0]->start = NULL;
    c->interp_doms[0]->end = NULL;
    c->interp_doms[0]->has_space = true;
    c->interp_doms[0]->writable = true;
    c->interp_doms[0]->next = NULL;

    c->main_path = NULL;
    // this ensures that we really do revoke write access at the end of pyr_init
    c->nested_grants = 1;

    /*if (!collect_callstack_cb) {
        printf("[%s] Need non-null callstack collect callback\n", __func__);
        err = -EINVAL;
        goto fail;
	}*/
    c->collect_callstack_cb = collect_callstack_cb;
    c->interpreter_lock_acquire_cb = interpreter_lock_acquire_cb;
    c->interpreter_lock_release_cb = interpreter_lock_release_cb;

    // this list will be added to whenever a new non-builtin extenion
    // is loaded via dlopen
    c->native_libs = NULL;
    
    *ctxp = c;
    return 0;
 fail:
    if (c)
      free(c);
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

static void free_interp_doms(struct pyr_security_context *ctx) {
    int memdom_id = -1;
    pyr_interp_dom_alloc_t *d = NULL;
    int i = 0;

    if (!ctx)
        return;

    for (i = 0; i < MAX_NUM_INTERP_DOMS; i++) {
        d = ctx->interp_doms[i];
        if (d) {
            printf("[%s] Interpreter allocation meta for memdom %d\n", __func__, d->memdom_id);
            if (d->start)
                memdom_free(d->start);
            memdom_kill(d->memdom_id);
            free(d);
        }
        ctx->interp_doms[i] = NULL;
    }

}

void pyr_security_context_free(struct pyr_security_context **ctxp) {
    struct pyr_security_context *c = *ctxp;
    int i = 0;

    if (!c)
        return;

    rlog("[%s] Freeing security context %p\n", __func__, c);

    //pyr_native_lib_context_free(&c->native_libs);

    free_interp_doms(c);
    free(c);
    *ctxp = NULL;
}
