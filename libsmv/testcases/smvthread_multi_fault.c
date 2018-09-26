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
#define NUM_THREADS 10

static void *memdom_read_trigger(void *buf) {
  printf("reading buffer: %s\n", (char *)buf);
  return NULL;
}

static void *memdom_write_trigger(char *buf) {
  buf[0] = 'b';
  return NULL;
}

int main(){
    printf("-- Test: thread memdom multi smv thread access fault... \n");
    int i = 0;
    int rv = 0;
    int smv_id[NUM_THREADS];
    pthread_t tid[NUM_THREADS];
    char *str;

    smv_main_init(0);

    int memdom_id = memdom_create();
    int privs = 0;

    // add this memory domain to the main thread SMV
    smv_join_domain(memdom_id, MAIN_THREAD);
    memdom_priv_add(memdom_id, MAIN_THREAD, MEMDOM_WRITE | MEMDOM_READ);

    str = memdom_alloc(memdom_id, 6*sizeof(char));
    sprintf(str, "hello");
    
    // main thread create smvs
    for (i = 0; i < NUM_THREADS; i++) {
        smv_id[i] = smv_create();
        smv_join_domain(MAIN_THREAD, smv_id[i]);
	smv_join_domain(memdom_id, smv_id[i]);
        memdom_priv_add(MAIN_THREAD, smv_id[i], MEMDOM_READ | MEMDOM_WRITE);
    }

    for (i = 0; i < NUM_THREADS; i++) {
      if (i % 2 == 0) {
	memdom_priv_add(memdom_id, smv_id[i], MEMDOM_READ | MEMDOM_WRITE);
      }
      else {
	memdom_priv_add(memdom_id, smv_id[i], MEMDOM_READ);
      }
      rv = smvthread_create(smv_id[i], &tid[i], memdom_write_trigger, str);
      if (rv == -1) {
	printf("smvthread_create error\n");
      }
    }

    // wait for child threads
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(tid[i], NULL);
        printf("waited thread %d\n", i);
    }

    return 0;
}
