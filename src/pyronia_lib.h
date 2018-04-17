/* Contains the main Pyronia userspace API definitions.
*
*@author Marcela S. Melara
*/

#ifndef __PYR_LIB_H
#define __PYR_LIB_H

#include <stdlib.h>
#include <linux/pyronia_mac.h>

#define MAIN_THREAD 0

#ifdef __cplusplus
extern "C" {
#endif

    int pyr_init(const char *lib_policy_file,
                 pyr_cg_node_t *(*collect_callstack_cb)(void));
    void *pyr_alloc_critical_runtime_state(size_t size);
    int pyr_is_critical_state(void *op);
    void pyr_grant_critical_state_write(void);
    void pyr_revoke_critical_state_write(void);
    int pyr_load_native_lib_isolated(const char *lib);
    int pyr_run_native_func_isolated(const char *lib, void *(*func)(void));
    void pyr_exit(void);

#ifdef __cplusplus
}
#endif

#endif
