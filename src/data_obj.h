/** Contains the Pyronia protected in-memory data object API.
 *
 *@author Marcela S. Melara
 */

#ifndef __PYR_DATA_OBJ_H
#define __PYR_DATA_OBJ_H

struct data_obj_domain {
    int memdom_id;
    char *label;
};

typedef struct data_obj_domain pyr_data_obj_domain_t;

struct pyr_data_obj {
    char *name;
    void *addr;
    char *domain_label;
};

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
    dom_list_t *read_only;
    dom_list_t *read_write;
    struct func_sandbox *next;
};

typedef struct func_sandbox pyr_func_sandbox_t;

#ifdef __cplusplus
extern "C" {
#endif

    void *pyr_data_obj_alloc(char *name, size_t size);
    void pyr_data_obj_free(char *name, void *addr);

#ifdef __cplusplus
}
#endif

#endif /* __PYR_DATA_OBJ_H */
