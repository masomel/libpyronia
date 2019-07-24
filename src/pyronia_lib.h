/* Contains the main Pyronia userspace API definitions.
*
*@author Marcela S. Melara
*/

#ifndef __PYR_LIB_H
#define __PYR_LIB_H

#include <stdlib.h>
#include <memdom_lib.h>
#include "stack_log.h"
#include "benchmarking_util.h"

#define PYRONIA_BENCH // uncomment for benchmarking

#define PYR_INTERCEPT_PTHREAD_CREATE
#ifdef PYR_INTERCEPT_PTHREAD_CREATE
#define pthread_create(tid, attr, fn, args) pyr_thread_create(tid, attr, fn, args)
#endif

#ifdef __cplusplus
extern "C" {
#endif

    int pyr_init(const char *main_mod_path,
		 const char *lib_policy_file,
                 int (*collect_callstack_cb)(void),
		 void (*interpreter_lock_acquire_cb)(void),
		 void (*interpreter_lock_release_cb)(void),
		 int is_child);
    void *pyr_alloc_critical_runtime_state(size_t size);
    int pyr_is_critical_state(void *op);
    void pyr_grant_critical_state_write(void *op);
    void pyr_revoke_critical_state_write(void *op);
    int pyr_free_critical_state(void *op);
    int pyr_serialize_callstack(const char *func_fqn);
    int pyr_thread_create(pthread_t* tid, const pthread_attr_t *attr,
			void*(fn)(void*), void* args);
    int pyr_load_native_lib_isolated(const char *lib);
    int pyr_run_native_func_isolated(const char *lib, void *(*func)(void));
    int pyr_is_interpreter_build(void);
    void pyr_exit(void);
    struct pyr_security_context *pyr_get_runtime_sec_ctx(void);

#ifdef __cplusplus
}
#endif

#endif
