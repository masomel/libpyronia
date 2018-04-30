/** Implments Python-specific extensions needed to make CPython Pyronia-aware
 *
 *@author Marcela S. Melara
 */

#include <stdlib.h>
#include <stdio.h>
#include <Python.h>
#include <memdom_lib.h>

#include "cpython_exts.h"
#include "security_context.h"

/** Wraps the given Python CFunction poitner and arguments to pass them
 * to the thread run function to be run in an isolated compartment.
 * Pass NULL for kwargs for any case in which the CFunction only needs to be called
 * with self and zero or more varargs, but no kwargs.
 */
struct python_wrapper_args *pyr_python_make_wrapper_args(char *lib, void *func,
                                                         void *self, void *args, void *kwargs) {
    struct python_wrapper_args *a = NULL;
    int memdom_id = -1;

    // Let's sanity check our inputs: mostly we care that func is a PyCFunction
    if (!PyCFunction_Check(func) || !self) {
        fprintf(stderr, "[%s] Trying to wrap a non-CFunction or got a NULL self\n", __func__);
        goto out;
    }

    a = pyr_alloc_in_native_context(pyr_get_native_library_contexts(), lib, sizeof(struct python_wrapper_args));
    if (!a) {
        fprintf(stderr, "[%s] No memory for args\n", __func__);
        goto out;
    }

    a->func = func;
    a->self = self;
    a->args = args;
    a->kwargs = kwargs;

 out:
    return a;
}

/** Unwraps the Python CFunction pointer and arguments, and makes the function call
 * according to the found arguments.
 */
void *pyr_python_func_wrapper(void *wrapper_args) {
    struct python_wrapper_args *a = (struct python_wrapper_args *)wrapper_args;
    void *ret = NULL;

    if (!a) {
        fprintf(stderr, "[%s] NULL wrapper_args\n", __func__);
    }

    // Let's sanity check our inputs: mostly we care that func is a PyCFunction
    if (!PyCFunction_Check(a->func) || !a->self) {
        fprintf(stderr, "[%s] Trying to wrap a non-CFunction or got a NULL self\n", __func__);
        goto out;
    }

    if (!a->kwargs) {
        // this case covers the METH_O, METH_NOARGS, and METH_VARARGS cases
        ret = (*(PyCFunction)a->func)((PyObject *)a->self, (PyObject *)a->args);
    }
    else {
        ret = (*(PyCFunctionWithKeywords)a->func)((PyObject *)a->self, (PyObject *)a->args, (PyObject *)a->kwargs);
    }

 out:
    memdom_free(a);
    return ret;
}
