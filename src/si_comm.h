/** Contains the Pyronia kernel communication library used for
 * receiving callstack requests and sending back serialized callgraphs.
 *
 *@author Marcela S. Melara
 */

#ifndef __PYR_KERNEL_COMM_H
#define __PYR_KERNEL_COMM_H

#include <linux/pyronia_mac.h>

#define FAMILY_STR "SI_COMM"

#ifdef __cplusplus
extern "C" {
#endif

    int pyr_init_si_comm(char *policy);
    pyr_cg_node_t *pyr_runtime_collect_callstack(void);
    void pyr_callstack_req_listen(void);
    void pyr_teardown_si_comm(void);

#ifdef __cplusplus
}
#endif

#endif
