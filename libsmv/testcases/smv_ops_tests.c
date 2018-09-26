/* Tests the SMV system. Adapted from the original
 * SMV userland testcases.
 *
 *@author Marcela S. Melara
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <smv_lib.h>
#include <memdom_lib.h>

#define MAIN_THREAD 0

static int test_smv_create() {
    printf("-- Test: main thread smv create... ");
    int smv_id = -1;

    // main thread create smv
    smv_id = smv_create();
    if (smv_id == -1) {
        printf("smv_create returned %d\n", smv_id);
        return -1;
    }

    if (smv_kill(smv_id)) {
        printf("smv_kill failed for %d\n", smv_id);
        return -1;
    }

    printf("success\n");
    return 0;
}

static int test_smv_create_fail() {
    printf("-- Test: main thread smv create fail... ");
    int smv_id = -1;
    int i = 0;
    int j = 0;
    int err = 0;

    // main thread create memdoms
    for (i = 0; i < 1024; i++) {
        smv_id = smv_create();

        if (smv_id == -1) {
            printf("smv_create returned %d\n", smv_id);
            err = -1;
            goto out;
        }
    }

    smv_id = smv_create();
    if (smv_id != -1) {
        printf("Expected %d, got %d\n", -1, smv_id);
        err = -1;
    }

 out:
    for (j = 1; j < 1025; j++) {
      if (smv_kill(j)) {
        printf("smv_kill failed for %d\n", j);
        err = -1;
      }
    }

    if (!err)
        printf("success\n");
    return err;
}

static int test_smv_join() {
    printf("-- Test: main thread join memdom... ");
    int memdom_id = -1;
    char *str;
    int err = 0;

    // main thread create memdom
    memdom_id = memdom_create();
    if (memdom_id == -1) {
        printf("memdom_create returned %d\n", memdom_id);
        return -1;
    }

    // need to add this domain to the main thread
    smv_join_domain(memdom_id, MAIN_THREAD);
    memdom_priv_add(memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);

    str = memdom_alloc(memdom_id, 6*sizeof(char));
    if (str == NULL) {
        err = -1;
        goto out;
    }

    memdom_free(str);
    smv_leave_domain(memdom_id, MAIN_THREAD);

 out:
    if (memdom_kill(memdom_id)) {
        printf("memdom_kill failed for %d\n", memdom_id);
        err = -1;
    }
    if (!err)
        printf("success\n");
    return err;
}

static int test_smv_queries() {
    printf("-- Test: main thread smv queries... ");
    int memdom_id = -1;
    int err = 0;

    if (!smv_is_in_domain(memdom_main_id(), MAIN_THREAD)) {
        printf("Expected true, got false, for main memdom\n");
        return -1;
    }

    if (smv_is_in_domain(42, MAIN_THREAD)) {
        printf("Expected false, got true, for memdom 42\n");
        return -1;
    }

    memdom_id = memdom_create();
    if (memdom_id == -1) {
        printf("memdom_create returned %d\n", memdom_id);
        return -1;
    }

    // need to add this domain to the main thread SMV
    smv_join_domain(memdom_id, MAIN_THREAD);

    if (!smv_is_in_domain(memdom_id, MAIN_THREAD)) {
        printf("Expected true, got false, for memdom %d\n", memdom_id);
        err = -1;
        goto out;
    }

    smv_leave_domain(memdom_id, MAIN_THREAD);

    if (smv_is_in_domain(memdom_id, MAIN_THREAD)) {
        printf("Expected false, got true, for memdom %d\n", memdom_id);
        err = -1;
    }

 out:
    if (memdom_kill(memdom_id)) {
        printf("memdom_kill failed for %d\n", memdom_id);
        err = -1;
    }
    if (!err)
        printf("success\n");
    return err;
}

static int test_smv_exists() {
     printf("-- Test: main thread smv exist checks... ");
     int smv_id = -1;
     int err = 0;

     if (!smv_exists(MAIN_THREAD)) {
         printf("Expected true, got false, for main smv\n");
         return -1;
     }

     if (smv_exists(900)) {
         printf("Expected false, got true, for smv 900\n");
         return -1;
     }

     smv_id = smv_create();
     if (smv_id == -1) {
        printf("smv_create returned %d\n", smv_id);
        return -1;
    }

     if (!smv_exists(smv_id)) {
         printf("Expected true, got false, for smv %d\n", smv_id);
         err = -1;
     }

     if (smv_kill(smv_id)) {
         printf("smv_kill failed for %d\n", smv_id);
         err = -1;
         goto out;
     }

     // skip the last test if we've already hit an error
     if (err == -1)
         goto out;

     if (smv_exists(smv_id)) {
         printf("Expected false, got true, for smv %d\n", smv_id);
         err = -1;
     }

 out:
     if (!err)
         printf("success\n");

     return err;
}

static int test_max_memdom_join() {
    printf("-- Test: main thread join max memdoms... ");
    int memdom_id = -1;
    int i = 0;
    int j = 0;
    int err = 0;

    // main thread create memdoms
    for (i = 0; i < MAX_MEMDOM; i++) {
        memdom_id = memdom_create();
	
        if (memdom_id == -1) {
            printf("memdom_create returned %d\n", memdom_id);
            err = -1;
            goto out;
        }

	// need to add this domain to the main thread
	smv_join_domain(memdom_id, MAIN_THREAD);
	memdom_priv_add(memdom_id, MAIN_THREAD, MEMDOM_READ | MEMDOM_WRITE);
    }
    
 out:
    
    if (!err)
        printf("success\n");
    return err;
}

int main(){

    smv_main_init(0);

    int success = 0;
    int total_tests = 6;

    // single smv_create --> expect success
    if (!test_smv_create()) {
        success++;
    }

    // create all possible smv + one out of bounds --> expect fail
    if (!test_smv_create_fail()) {
        success++;
    }

    // single smv memdom join --> expect success
    if (!test_smv_join()) {
        success++;
    }

    // test smv memdom queries
    if (!test_smv_queries()) {
        success++;
    }

    // test smv exist queries
    if (!test_smv_exists()) {
        success++;
    }

    // test context swithcing between all possible memdoms
    if (!test_max_memdom_join()) {
        success++;
    }

    printf("%d / %d smv operations tests passed\n", success, total_tests);

    return 0;
}
