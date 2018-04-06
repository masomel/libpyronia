#include <stdio.h>
#include <string.h>
#include <pyronia_lib.h>
#include <error.h>
#include <errno.h>
#include <linux/pyronia_mac.h>

#include "testutil.h"

#define LIB_POLICY "/home/pyronia/libpyronia/testsuite/home.pyronia.kernel_upcall_test-lib.prof"

pyr_cg_node_t *test_callgraph_creation() {
    pyr_cg_node_t *child = NULL;
    int i, err;
    int len = 3;
    
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
	i--;
    }

    return child;
}

static int test_file_open() {
  //printf("-- Test: authorized file open for reading... ");
    FILE *f;
    f = fopen("/tmp/cam0", "r");

    if (f == NULL) {
        printf("%s\n", strerror(errno));
        return -1;
    }

    //printf("success\n");
    fclose(f);
    return 0;
}

int main (int argc, char *argv[]) {
  int ret = 0;

  init_testlibs();
  
  ret = pyr_init(LIB_POLICY, test_callgraph_creation);
  if (ret) {
    printf("Error initializing Pyronia: %d\n", ret);
    goto out;
  }
 
  test_file_open();
  test_file_open();
 out:
  return ret;
}
