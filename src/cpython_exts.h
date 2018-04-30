/** Contains Python-specific extensions needed to make CPython Pyronia-aware
 *
 *@author Marcela S. Melara
 */

#ifndef __PYR_CPYTHON_H
#define __PYR_CPYTHON_H

/* Used to pass PyCFunction information to the thread run function
   to run native Python functions in an isolated compartment.
   Note: these void pointers will actually point to PyObjects
   at runtime. We use void pointers here to avoid importing Python.h
*/
struct python_wrapper_args {
    void *func;
    void *self;
    void *args;
    void *kwargs;
};

void *pyr_python_func_wrapper(void *wrapper_args);
struct python_wrapper_args *pyr_python_make_wrapper_args(char *lib, void *func,
                                                         void *self, void *args, void *kwargs);

#endif /* __PYR_CPYTHON_H */
