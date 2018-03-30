#ifndef PYR_LIB_H
#define PYR_LIB_H

#include <linux/pyronia_mac.h>

struct pyr_runtime {
  /* The function used to collect a language runtime-specific
   * callstack. This callback needs to be set at initialization time. */
  pyr_cg_node_t *(*collect_callstack_cb)(void);
};

#ifdef __cplusplus
extern "C" {
#endif

int pyr_init(void);
void pyr_exit(void);
void pyr_recv_from_kernel(void);
int pyr_init_runtime(pyr_cg_node_t *(*collect_callstack)(void));

#ifdef __cplusplus
}
#endif

#endif
