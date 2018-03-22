#include <stdio.h>
#include <pyronia_lib.h>

int main (int argc, char *argv[]) {
  int ret = 0;
  
  printf("Initializing Pyronia userland extensions\n");
  
  ret = pyr_init();

  if (ret) {
    // Throw an error
    goto out;
  }

 out:
  pyr_exit();
  return ret;
}
