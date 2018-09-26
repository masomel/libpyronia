#include <stdio.h>
#include <string.h>
#include <pyronia_lib.h>
#include <error.h>
#include <errno.h>
#include <linux/pyronia_mac.h>

#include "testutil.h"

#define LIB_POLICY "/home/pyronia/libpyronia/testsuite/home.pyronia.callgraph_perms_fail_test-lib.prof"

static int test_type = 0;

// return a different callgraph depending on which test we're
// about to run
pyr_cg_node_t *test_callgraph_creation() {
    pyr_cg_node_t *child = NULL;
    int i, err;
    int len = 3;
    
    if (!test_type) {
      // insert the libs in reverse order to mimic
      // traversing up the call stack
      for (i = len-1; i >= 0; i--) {
        pyr_cg_node_t *next;
	
        err = pyr_new_cg_node(&next, test_libs[i], CAM_DATA, child);
        if (err) {
          printf("[%s] Could not create cg node for lib %s\n", __func__, test_libs[i]);
          return NULL;
        }
        child = next;
      }
    }
    else {
      err = pyr_new_cg_node(&child, test_libs[2], CAM_DATA, NULL);
        if (err) {
          printf("[%s] Could not create cg node for lib %s\n", __func__, test_libs[1]);
          return NULL;
        }
    }

    return child;
}

int main (int argc, char *argv[]) {
  int ret = 0;
  int i;

  printf("******* Callgraph Perms Fail Test ********\n");
  
  init_testlibs();

  ret = pyr_init("callgraph_perms_fail_test", LIB_POLICY, test_callgraph_creation);
  if (ret) {
    printf("Error initializing Pyronia: %d\n", ret);
    goto out;
  }
  
  printf("---Testing hidden network connection open\n");
  
  test_type = 0;
  ret = test_connect();
  if (!ret)
    goto out;

  printf("---Testing hidden file open\n");

  test_type = 0;
  ret = test_file_open();
  if (!ret)
    goto out;

  printf("---Testing unknown lib alone\n");
  
  test_type = 1;
  ret = test_file_open();

 out:
  pyr_exit();
  return ret;
}
