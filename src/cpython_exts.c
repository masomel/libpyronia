/** Implments Python-specific extensions needed to make CPython Pyronia-aware
 *
 *@author Marcela S. Melara
 */

#include <stdlib.h>

#include "cpython_exts.h"

int pyr_python_make_wrapper_args(void *(func)(void *, void *), void *self,
                                 void *args) {
    // FIXME
    return 0;
}

void *pyr_python_func_wrapper(void *wrapper_args) {
    // FIXME
    return NULL;
}
