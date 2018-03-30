#include <stdio.h>
#include <pyronia_lib.h>
#include <error.h>
#include <errno.h>
#include <pthread.h>

void *wait_for_kernel_reqs(void *args){
    pyr_recv_from_kernel();
    return NULL;
}

static int test_file_open() {
    printf("-- Test: authorized file open for reading... ");
    FILE *f;
    f = fopen("/tmp/cam0", "r");

    if (f == NULL) {
        printf("%s\n", strerror(errno));
        return -1;
    }

    printf("success\n");
    fclose(f);
    return 0;
}

int main (int argc, char *argv[]) {
  int ret = 0;
  pthread_t tid;

  printf("Initializing Pyronia userland extensions\n");

  ret = pyr_init();

  if (ret) {
    // Throw an error
    printf("Got error %d\n", ret);
    goto out;
  }

  pthread_create(&tid, NULL, wait_for_kernel_reqs, NULL);

  test_file_open();
 out:
  pthread_join(tid, NULL);
  pyr_exit();
  return ret;
}
