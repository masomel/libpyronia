#include <stdio.h>
#include <string.h>
#include <pyronia_lib.h>
#include <error.h>
#include <errno.h>
#include <linux/pyronia_mac.h>
#include <memdom_lib.h>

#include "testutil.h"

#define LIB_POLICY "/home/pyronia/libpyronia/testsuite/home.pyronia.critical_state_alloc_test-lib.prof"

int main() {
  int i = 0;
  int memdom_id = -1;
  char *to_copy = "Vanishing into thin air";
  char *secure_alloc[1000];
  int oom = 1000;

  printf("******* Critical state alloc Test ********\n");
  
  if (pyr_init("critical_state_alloc", LIB_POLICY, NULL)) {
    goto out;
  }
    
  for (i = 0; i < 1000; i++) {
    pyr_grant_critical_state_write(NULL);
    secure_alloc[i] = pyr_alloc_critical_runtime_state(strlen(to_copy)+1);
    if (secure_alloc[i] == NULL) {
      oom = i+1;
      pyr_revoke_critical_state_write(NULL);
      break;
    }
    memcpy(secure_alloc[i], to_copy, strlen(to_copy)+1);
    pyr_revoke_critical_state_write(NULL);
    printf("Allocated string %s:%d in secure memdom\n", secure_alloc[i], i);
  }

  pyr_grant_critical_state_write(NULL);
  for (i = 0; i < oom; i++) {
    pyr_free_critical_state(secure_alloc[i]);
  }
  pyr_revoke_critical_state_write(NULL);

 out:
  pyr_exit();
  return 0;
}
