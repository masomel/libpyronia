/** Contains Pyronia userspace API utility function definitions.
 *
 *@author Marcela S. Melara
 */

#ifndef __PYR_UTIL_H
#define __PYR_UTIL_H

#include <string.h>
#include <stdlib.h>

#include "pyronia_lib.h"

/**
 * set_str - copy the src string into the dest string
 * in a clean buffer. This is used to cleanly set the
 * string fields in the various Pyronia data structures.
 */
static inline int set_str(const char *src, char **dest) {
  char *str = NULL;
  int err = 0;

  // let's make sure to not override a non-null
  // destination
  if (*dest)
    return 0;

  str = pyr_alloc_critical_runtime_state(strlen(src)+1);
  if (!str) {
    err = -1;
    goto out;
  }

  memset(str, 0, strlen(src)+1);
  memcpy(str, src, strlen(src));

 out:
  *dest = str;
  return err;
}

static inline int copy_str(char *src, char **dest) {
    char *str = NULL;
    int err = 0;

    // let's make sure to not override a non-null
    // destination
    if (*dest)
        return 0;

    str = malloc(strlen(src)+1);
    if (!str) {
        err = -1;
        goto out;
    }

    memset(str, 0, strlen(src)+1);
    memcpy(str, src, strlen(src));

    printf("[%s] copied string: %s (%p)\n", __func__,
	   str, &str);
    
 out:
    *dest = str;
    return err;
}

#endif /* __PYR_UTIL_H */
