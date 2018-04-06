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

int main(){
  
    printf("-- Test: thread memdom read fault... ");
    int memdom_id = -1;
    int smv_id = -1;
    int err = -1;
    pthread_t tid;
    char *str;

    smv_main_init(1);

    memdom_id = memdom_create();
    if (memdom_id == -1) {
        printf("memdom_create returned %d\n", memdom_id);
        err = -1;
    }

    smv_id = smv_create();
    if (smv_id == -1) {
        printf("memdom_create returned %d\n", memdom_id);
        err = -1;
	goto out;
    }

    // add this memory domain to the main thread SMV
    smv_join_domain(memdom_id, MAIN_THREAD);
    memdom_priv_add(memdom_id, MAIN_THREAD, MEMDOM_WRITE | MEMDOM_READ);

    str = memdom_alloc(memdom_id, 6*sizeof(char));
    sprintf(str, "hello");

    // child thread without privs tries to read the buffer in this domain
    smv_join_domain(memdom_id, smv_id);
    memdom_priv_add(memdom_id, smv_id, 0);
    // trigger memdom read segfault
    err = smvthread_create(smv_id, &tid, memdom_read_trigger, str);
    if (err == -1) {
      printf("smvthread_create returned %d\n", err);
    }
    pthread_join(tid, NULL);

 out:
    if (err != 0) {
      printf("failed\n");
    }

    return 0;
}
