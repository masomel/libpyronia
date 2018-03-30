#include <stdio.h>
#include <pyronia_lib.h>

int main (int argc, char *argv[]) {
  int ret = 0;
  
  printf("Initializing Pyronia userland extensions\n");
  
  ret = pyr_init();

  if (ret) {
    // Throw an error
    printf("Got error %d\n", ret);
    goto out;
  }

  pyr_recv_from_kernel();
  
 out:
  //pyr_exit();
  return ret;
}
