#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <limits.h>
#include <smv_lib.h>
#include "kernel_comm.h"

/* Do all the necessary setup for a language runtime to use
 * the Pyronia extensions: open the stack inspection communication
 * channel and initialize the SMV backend.
 */
int pyr_init() {
    int err = 0;

    err = init_si_kernel_comm();

    // We don't want the main thread's memdom to be
    // globally accessible, so init with 0.
    // err = smv_main_init(0);

    return err;
}
