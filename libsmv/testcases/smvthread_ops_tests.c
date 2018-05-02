/* Tests the SMV system. Adapted from the original
 * SMV userland testcases.
 *
 *@author Marcela S. Melara
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <smv_lib.h>
#include <pthread.h>
#include <memdom_lib.h>
#include <errno.h>

#define MAIN_THREAD 0
#define NUM_THREADS 500

void *fn(void *args) {
    printf("Hello from smv thread!\n");
    return NULL;
}

static int test_smvthread_create() {
    printf("-- Test: main thread smvthread create... ");
    int smv_id = -1;
    int ret = 0;
    int err = 0;
    pthread_t tid;
    int func_id = -1;

    // main thread create smv
    smv_id = smv_create();
    if (smv_id == -1) {
        printf("smv_create returned %d\n", smv_id);
        return -1;
    }

    smv_join_domain(MAIN_THREAD, smv_id);
    memdom_priv_add(MAIN_THREAD, smv_id, MEMDOM_READ | MEMDOM_WRITE);

    ret = smvthread_create(smv_id, &tid, fn, NULL);
    if (ret == -1) {
        printf("smvthread_create returned %d\n", ret);
        err = -1;
    }

    ret = pthread_join(tid, NULL);
    if (ret) {
      printf("join returned an error: %s\n", strerror(errno));
      err = -1;
    }

 out:
    if (smv_kill(smv_id)) {
      printf("smv_kill failed for %d\n", smv_id);
      err = -1;
    }

    if (!err)
        printf("success\n");
    return err;
}

static int test_smvthread_own_memdom() {
  printf("-- Test: smvthread create in separate memdom... ");
    int smv_id = -1;
    int dom_id = -1;
    int ret = 0;
    int err = 0;
    pthread_t tid;
    int func_id = -1;

    // main thread create smv
    smv_id = smv_create();
    if (smv_id == -1) {
        printf("smv_create returned %d\n", smv_id);
        return -1;
    }

    dom_id = memdom_create();
    if (dom_id == -1) {
      printf ("memdom_create returned %d\n", dom_id);
      err = -1;
      goto out;
    }

    smv_join_domain(MAIN_THREAD, smv_id);
    memdom_priv_add(MAIN_THREAD, smv_id, MEMDOM_READ | MEMDOM_WRITE);

    smv_join_domain(dom_id, smv_id);
    memdom_priv_add(dom_id, smv_id, MEMDOM_READ | MEMDOM_WRITE);

    ret = smvthread_create(smv_id, &tid, fn, NULL);
    if (ret == -1) {
        printf("smvthread_create returned %d\n", ret);
        err = -1;
    }

    ret = pthread_join(tid, NULL);
    if (ret) {
      printf("join returned an error: %s\n", strerror(errno));
    }

 out:
    if (smv_kill(smv_id)) {
        printf("smv_kill failed for %d\n", smv_id);
        err = -1;
    }

    if (!err)
        printf("success\n");
    return err;
}

static int test_smvthread_create_max() {
    printf("-- Test: smvthread create max out smvs... ");
    int ret = 0;
    int err = 0;
    int i = -1;
    int smv_id[NUM_THREADS];
    pthread_t tid[NUM_THREADS];

    for (i = 0; i < NUM_THREADS; i++) {
      // main thread create smv
      smv_id[i] = smv_create();
      if (smv_id[i] == -1) {
        printf("smv_create %d returned %d\n", i, smv_id[i]);
        return -1;
      }

      smv_join_domain(MAIN_THREAD, smv_id[i]);
      memdom_priv_add(MAIN_THREAD, smv_id[i], MEMDOM_READ | MEMDOM_WRITE);

      ret = smvthread_create(smv_id[i], &tid[i], fn, NULL);
      if (ret == -1) {
        printf("smvthread_create returned %d\n", ret);
        err = -1;
      }
    }

    for (i = 0; i < NUM_THREADS; i++) {
      ret = pthread_join(tid[i], NULL);
      if (ret) {
	printf("join %d returned an error: %s\n", i, strerror(errno));
	err = -1;
      }
      smv_kill(smv_id[i]);
    }

 out:
    if (!err)
        printf("success\n");
    return err;
}

int main(){

    smv_main_init(0);

    int success = 0;
    int total_tests = 3;

    // single smvthread_create --> expect success
    /*    if (!test_smvthread_create()) {
        success++;
    }

    // smvthread_create to run in its own memdom --> expect success
    if (!test_smvthread_own_memdom()) {
        success++;
	}*/
    
    // single smvthread_create for max number of smvs --> expect success
    if (!test_smvthread_create_max()) {
        success++;
    }

    printf("%d / %d smv thread operations tests passed\n", success, total_tests);

    return 0;
}
