#include <stdio.h>
#include <string.h>
#include <pyronia_lib.h>
#include <error.h>
#include <errno.h>
#include <linux/pyronia_mac.h>

#include "testutil.h"

#define LIB_POLICY "/home/pyronia/libpyronia/testsuite/home.pyronia.kernel_upcall_test-lib.prof"

static int test_type = 0;

// return a different callgraph depending on which test we're
// about to run
static pyr_cg_node_t *test_callgraph_creation() {
    pyr_cg_node_t *child = NULL;
    int i, err;
    int len = 3;
    
    if (!test_type) {
      // insert the camera libs in reverse order to mimic
      // traversing up the call stack
      for (i = len-1; i >= 0; i--) {
        pyr_cg_node_t *next;
	
        err = pyr_new_cg_node(&next, test_libs[i], CAM_DATA, child);
        if (err) {
          printf("[%s] Could not create cg node for lib %s\n", __func__, test_libs[i]);
          return NULL;
        }
        child = next;
        i--;
      }
    }
    else {
      err = pyr_new_cg_node(&child, test_libs[1], CAM_DATA, NULL);
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

  printf("******* Kernel Upcall Test ********\n");
  
  init_testlibs();

  ret = pyr_init("kernel_upcall_test", LIB_POLICY, test_callgraph_creation);
  if (ret) {
    printf("Error initializing Pyronia: %d\n", ret);
    goto out;
  }
  /*
  printf("---Testing authorized file open\n");
  
  test_type = 0;
  ret = test_file_open();
  if (ret)
    goto out;

  printf("---Testing authorized network access\n");

  test_type = 1;
  ret = test_connect();
  if (ret)
    goto out;

  printf("---Testing unauthorized file open\n");
  
  test_type = 0;
  ret = test_file_open_fail();
  if (ret) {
    goto out;
  }

  printf("---Testing authorized file open, bad permissions\n");
  ret = test_file_open_write();
  if (ret) {
    goto out;
  }

  test_type = 1;
  printf("---Testing unauthorized network access\n");

  ret = test_connect_fail();
  */
 out:
  pyr_exit();
  return ret;
}
