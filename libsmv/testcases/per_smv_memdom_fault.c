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

int main(){
  printf("-- Test: per smv thread memdom access fault... \n");
    int i = 0;
    int rv = 0;
    int smv_id[NUM_THREADS];
    int memdom_id[NUM_THREADS];
    pthread_t tid[NUM_THREADS];
    char *str[NUM_THREADS];

    smv_main_init(0);
    
    // main thread create smvs
    for (i = 0; i < NUM_THREADS; i++) {
        smv_id[i] = smv_create();
	memdom_id[i] = memdom_create();
	smv_join_domain(memdom_id[i], MAIN_THREAD);
	memdom_priv_add(memdom_id[i], MAIN_THREAD, MEMDOM_WRITE);
        smv_join_domain(MAIN_THREAD, smv_id[i]);
	smv_join_domain(memdom_id[i], smv_id[i]);
        memdom_priv_add(MAIN_THREAD, smv_id[i], MEMDOM_READ | MEMDOM_WRITE);
	memdom_priv_add(memdom_id[i], smv_id[i], MEMDOM_READ | MEMDOM_WRITE);

	str[i] = memdom_alloc(memdom_id[i], 6*sizeof(char));
	sprintf(str[i], "from %d", i);
    }

    printf("each smv reads from its own memdom\n");
    
    // this loop should succeed 
    for (i = 0; i < NUM_THREADS; i++) {
      rv = smvthread_create(smv_id[i], &tid[i], memdom_read_trigger, str[i]);
      if (rv == -1) {
	printf("smvthread_create error\n");
      }
    }

    // wait for child threads
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(tid[i], NULL);
        printf("waited thread %d\n", i);
    }

    printf("try reading from another memdom\n");

    // this loop will cause even numbered SMV threads to read
    // from the (i-1)-th memdom --> should cause fault
    int j;
    for (i = 2; i < NUM_THREADS; i++) {
      if (i % 2 == 0)
	j = i;
      else
	j = i-1;
      rv = smvthread_create(smv_id[i], &tid[i], memdom_read_trigger, str[j]);
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
