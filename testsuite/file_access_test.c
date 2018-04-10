#include <stdio.h>
#include <string.h>
#include <pyronia_lib.h>
#include <error.h>
#include <errno.h>
#include <linux/pyronia_mac.h>

#include "testutil.h"

#define LIB_POLICY "/home/pyronia/libpyronia/testsuite/home.pyronia.file_access_test-lib.prof"

#define NUM_ITERS 5

static pyr_cg_node_t *test_callgraph_creation() {
    pyr_cg_node_t *node = NULL;
    int err;

    err = pyr_new_cg_node(&node, test_libs[0], CAM_DATA, NULL);
    if (err) {
      printf("[%s] Could not create cg node for lib %s\n", __func__, test_libs[0]);
      return NULL;
    }
    
    return node;
}

int main (int argc, char *argv[]) {
  int ret = 0;
  int i;

  init_testlibs();

  ret = pyr_init(LIB_POLICY, test_callgraph_creation);
  if (ret) {
    printf("Error initializing Pyronia: %d\n", ret);
    goto out;
  }

  ret = test_file_open_name("/tmp/cam0");
  if (ret)
    goto out;
  
  ret = test_file_open_name("/tmp/cam1");
  if (ret)
    goto out;

  ret = test_file_open_name("/tmp/cam2");
  if (ret)
    goto out;
  
  // make sure it can't access the network
  ret = test_connect();
  
 out:
  return ret;
}
