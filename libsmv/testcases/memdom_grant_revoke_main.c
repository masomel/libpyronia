/* Tests the SMV memory domain faults. Adapted from the original
 * SMV userland testcases.
 *
 *@author Marcela S. Melara
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <smv_lib.h>
#include <memdom_lib.h>
#include <pthread.h>

#define MAIN_THREAD 0

static void *memdom_read_trigger(void *buf) {
  printf("reading buffer: %s\n", (char *)buf);
  return NULL;
}

static void *memdom_write_trigger(char *buf) {
  buf[0] = 'b';
  return NULL;
}

int main(){
  
    printf("-- Test: thread memdom grant-revoke write fault... ");
    int memdom_id = -1;
    int err = 0;
    pthread_t tid1, tid2;
    char *str;

    smv_main_init(1);

    memdom_id = memdom_create();
    if (memdom_id == -1) {
        printf("memdom_create returned %d\n", memdom_id);
        err = -1;
    }

    // add this memory domain to the main thread SMV
    smv_join_domain(memdom_id, MAIN_THREAD);
    memdom_priv_add(memdom_id, MAIN_THREAD, MEMDOM_WRITE | MEMDOM_READ);

    str = memdom_alloc(memdom_id, 6*sizeof(char));
    sprintf(str, "hello");

    // read and write the domain
    printf("reading str: %s\n", str);
    str[0] = 'b';
    
    // revoke write access to the domain
    memdom_priv_del(memdom_id, MAIN_THREAD, MEMDOM_WRITE);

    printf("reading str: %s\n", str);
    
    printf("smv %d privs %lu memdom %d\n", MAIN_THREAD, memdom_priv_get(memdom_id, MAIN_THREAD), memdom_id);

    str[3] = '1';
    
    memdom_free(str);
    
 out:
    if (err == -1) {
      printf("failed\n");
    }

    return 0;
}
