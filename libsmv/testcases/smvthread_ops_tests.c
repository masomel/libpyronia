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

void * fn(void *args) {
    printf("Hello from smv thread!\n");
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
  printf("-- Test: main thread smvthread create... ");
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

    /*ret = pthread_join(tid, NULL);
    if (ret) {
      printf("join returned an error: %s\n", strerror(errno));
    }
    */

 out:
    if (smv_kill(smv_id)) {
        printf("smv_kill failed for %d\n", smv_id);
        err = -1;
    }

    if (!err)
        printf("success\n");
    return err;
}

int main(){

    smv_main_init(0);

    int success = 0;
    int total_tests = 1;

    // single smvthread_create --> expect success
    if (!test_smvthread_create()) {
        success++;
    }

    printf("%d / %d smv thread operations tests passed\n", success, total_tests);

    return 0;
}
