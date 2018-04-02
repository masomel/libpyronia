#include <stdio.h>
#include <string.h>
#include <pyronia_lib.h>
#include <error.h>
#include <errno.h>

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
  
  ret = pyr_init();
  if (ret) {
    // Throw an error
    printf("Got error %d\n", ret);
    goto out;
  }
 
  test_file_open();
 out:
  return ret;
}
