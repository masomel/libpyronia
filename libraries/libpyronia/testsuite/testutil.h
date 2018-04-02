/** Provides utility functions and definitions for performing end-to-end
 * tests of the Pyronia LSM.
 *
 *@author Marcela S. Melara
 */

#ifndef __TESTUTIL_H
#define __TESTUTIL_H

#include <linux/pyronia_mac.h>

static const char *test_libs[3];

static const char *test_names[2];

#define NUM_DEFAULT 8

static const char *default_names[NUM_DEFAULT];

static inline void init_testlibs(void) {
    test_libs[0] = "cam";
    test_libs[1] = "http";
    test_libs[2] = "img_processing";
}

static inline void init_testnames(void) {
    test_names[0] = "/tmp/cam0";
    test_names[1] = "127.0.0.1";
}

// these files should be allowed for all libs by default
static inline void init_default(void) {
  default_names[0] = "/etc/ld.so.cache";
  default_names[1] = "/lib/x86_64-linux-gnu/libc-2.23.so";
  default_names[2] = "/lib/x86_64-linux-gnu/libpyronia.so";
  default_names[3] = "/lib/x86_64-linux-gnu/libsmv.so";
  default_names[4] = "/lib/x86_64-linux-gnu/libpthread-2.23.so";
  default_names[5] = "/lib/x86_64-linux-gnu/libnl-genl-3.so.200.22.0";
  default_names[6] = "/lib/x86_64-linux-gnu/libnl-3.so.200.22.0";
  default_names[7] = "/lib/x86_64-linux-gnu/libm-2.23.so";
}

#endif
