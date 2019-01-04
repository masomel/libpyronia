/** Contains the Pyronia protected in-memory data object API.
 *
 *@author Marcela S. Melara
 */

#ifndef __PYR_DATA_OBJ_H
#define __PYR_DATA_OBJ_H

#include <stdbool.h>

struct data_obj_domain {
    char *label;
    int pool_size;
    struct pyr_dom_alloc *memdom_pool;
    struct pyr_dom_alloc *pool_tail;
};

typedef struct data_obj_domain pyr_data_obj_domain_t;

struct pyr_data_obj;
typedef struct pyr_data_obj pyr_data_obj_t;

struct obj_list {
    pyr_data_obj_t *obj;
    struct obj_list *next;
};

typedef struct obj_list obj_list_t;

struct dom_list {
    pyr_data_obj_domain_t *domain;
    struct dom_list *next;
};

typedef struct dom_list dom_list_t;

struct func_sandbox {
    char *func_name;
    obj_list_t *read_only;
    pyr_data_obj_t *read_write; // FIXME: support more than one output/RW object
    bool in_sandbox;
    struct func_sandbox *next;
};

typedef struct func_sandbox pyr_func_sandbox_t;

#ifdef __cplusplus
extern "C" {
#endif

    pyr_data_obj_t *find_data_obj(char *name, obj_list_t *obj_list);
    pyr_data_obj_t *find_data_obj_in_dom(char *domain_label, obj_list_t *obj_list);
    pyr_data_obj_domain_t *find_domain(char *domain_label, dom_list_t *dom_list);
    pyr_func_sandbox_t *find_sandbox(char *func_name,
                                     pyr_func_sandbox_t *sb_list);

#ifdef __cplusplus
}
#endif

#endif /* __PYR_DATA_OBJ_H */
