/** Contains the Pyronia kernel communication library used for
 * receiving callstack requests and sending back serialized callgraphs.
 *
 *@author Marcela S. Melara
 */

#ifndef __PYR_KERNEL_COMM_H
#define __PYR_KERNEL_COMM_H

#include <linux/pyronia_mac.h>

#define FAMILY_STR "SI_COMM"

// let's place these here since they're really
// only shared between the main library API and the
// SI comm channel
extern pthread_mutex_t security_ctx_mutex;
extern pthread_cond_t si_cond_var;
extern int is_inspecting_stack;

#ifdef __cplusplus
extern "C" {
#endif

    int pyr_init_si_comm(char *policy);
    extern pyr_cg_node_t *pyr_collect_runtime_callstack(void);
    void pyr_teardown_si_comm(void);
    void *pyr_recv_from_kernel(void *args);
    void pyr_callstack_req_listen(void);
    void pyr_is_inspecting(void);

#ifdef __cplusplus
}
#endif

#endif
