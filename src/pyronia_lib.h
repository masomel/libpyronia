/* Contains the main Pyronia userspace API definitions.
*
*@author Marcela S. Melara
*/

#ifndef __PYR_LIB_H
#define __PYR_LIB_H

#include <stdlib.h>
#include <linux/pyronia_mac.h>

#define PYR_INTERCEPT_PTHREAD_CREATE
#ifdef PYR_INTERCEPT_PTHREAD_CREATE
#define pthread_create(tid, attr, fn, args) pyr_thread_create(tid, attr, fn, args)
#endif

#ifdef __cplusplus
extern "C" {
#endif

    int pyr_init(const char *lib_policy_file,
                 pyr_cg_node_t *(*collect_callstack_cb)(void));
    void *pyr_alloc_critical_runtime_state(size_t size);
    int pyr_is_critical_state(void *op);
    void pyr_grant_critical_state_write(void);
    void pyr_revoke_critical_state_write(void);
    int pyr_free_critical_state(void *op);
    int pyr_thread_create(pthread_t* tid, const pthread_attr_t *attr,
                        void*(fn)(void*), void* args);
    int pyr_load_native_lib_isolated(const char *lib);
    void *pyr_run_native_func_isolated_python(char *lib, void *func,
                                       void *self, void *args, void *kwargs);
    void pyr_exit(void);

#ifdef __cplusplus
}
#endif

#endif
