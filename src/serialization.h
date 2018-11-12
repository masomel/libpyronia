/** Defines the API for parsing and serializing a Pyronia-secured
 * application's callstack and library-level access policies.
 *
 *@author Marcela S. Melara
 */

#ifndef PYR_SERIALIZE_H
#define PYR_SERIALIZE_H

#include <linux/pyronia_mac.h>
#include "data_obj.h"

#define INT32_STR_SIZE 12
#define RO_DATA_OBJ_MARKER "-"
#define RW_DATA_OBJ_MARKER "+"
#define DOMAIN_DELIM ":"
#define FUNC_NAME_DELIM " "
#define LIB_RULE_DELIM ","

#ifdef __cplusplus
extern "C" {
#endif

    int pyr_serialize_callstack(char **cs_str, pyr_cg_node_t *callstack);
    int pyr_parse_lib_policy(const char *policy_fname, char **parsed,
                             char **parsed_obj_rules, int *num_rules);

#ifdef __cplusplus
}
#endif

#endif /* PYR_SERIALIZE_H */
