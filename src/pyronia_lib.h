/* Contains the main Pyronia userspace API definitions.
*
*@author Marcela S. Melara
*/

#ifndef __PYR_LIB_H
#define __PYR_LIB_H

#include <stdlib.h>
#include <linux/pyronia_mac.h>

struct pyr_data_obj {
    char *name;
    void *addr;
    size_t size;
    char *domain_label;
};

typedef struct pyr_data_obj pyr_data_obj_t;

//#define PYR_INTERCEPT_PTHREAD_CREATE
#ifdef PYR_INTERCEPT_PTHREAD_CREATE
#define pthread_create(tid, attr, fn, args) pyr_thread_create(tid, attr, fn, args)
#endif

#ifdef __cplusplus
extern "C" {
#endif

    int pyr_init(const char *main_mod_path,
                 const char *lib_policy_file,
                 pyr_cg_node_t *(*collect_callstack_cb)(void),
                 void (*interpreter_lock_acquire_cb)(void),
                 void (*interpreter_lock_release_cb)(void));
    void *pyr_alloc_critical_runtime_state(size_t size);
    int pyr_is_critical_state(void *op);
    void pyr_grant_critical_state_write(void *op);
    void pyr_revoke_critical_state_write(void *op);
    int pyr_free_critical_state(void *op);
    void *pyr_data_object_alloc(char *name, size_t size);
    void pyr_data_obj_free(void *addr);
    int pyr_is_isolated_data_obj(void *addr);
    pyr_data_obj_t *pyr_get_sandbox_rw_obj(void);
    void pyr_grant_sandbox_access(char *sandbox_name);
    void pyr_revoke_sandbox_access(char *sandbox_name);
    int pyr_in_sandbox(void);
    int pyr_thread_create(pthread_t* tid, const pthread_attr_t *attr,
                        void*(fn)(void*), void* args);
    int pyr_load_native_lib_isolated(const char *lib);
    int pyr_run_native_func_isolated(const char *lib, void *(*func)(void));
    int pyr_is_interpreter_build(void);
    void pyr_exit(void);

#ifdef __cplusplus
}
#endif

#endif
