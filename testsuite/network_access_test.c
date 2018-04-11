#include <stdio.h>
#include <string.h>
#include <pyronia_lib.h>
#include <error.h>
#include <errno.h>
#include <linux/pyronia_mac.h>

#include "testutil.h"

#define LIB_POLICY "/home/pyronia/libpyronia/testsuite/home.pyronia.network_access_test-lib.prof"

#define NUM_ITERS 5

static pyr_cg_node_t *test_callgraph_creation() {
    pyr_cg_node_t *node = NULL;
    int err;

    err = pyr_new_cg_node(&node, test_libs[1], CAM_DATA, NULL);
    if (err) {
      printf("[%s] Could not create cg node for lib %s\n", __func__, test_libs[1]);
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

  pyr_callstack_req_listen();
  
  for (i = 0; i < NUM_ITERS; i++) {
    ret = test_connect();
    if (ret)
      goto out;
  }

  // make sure it can't access the fake camera
  ret = test_file_open();
  
 out:
  return ret;
}
