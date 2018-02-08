/* Tests the SMV memory domain system. Adapted from the original
 * SMV userland testcases.
 *
 *@author Marcela S. Melara
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <smv_lib.h>
#include <memdom_lib.h>

static int test_memdom_create() {
    printf("-- Test: main thread memdom create... ");
    int memdom_id = -1;

    // main thread create memdoms
    memdom_id = memdom_create();

    if (memdom_id == -1) {
        printf("memdom_create returned %d\n", memdom_id);
        return -1;
    }
    
    if (memdom_kill(memdom_id)) {
        printf("memdom_kill returned %d\n", memdom_id);
        return -1;
    }

    printf("success\n");
    return 0;
}

static int test_memdom_create_fail() {
    printf("-- Test: main thread memdom create fail... ");
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
    }
    
    memdom_id = memdom_create();
    if (memdom_id != -1) {
        printf("Expected %d, got %d\n", -1, memdom_id);
        err = -1;
    }

 out:
    for (j = 0; j < i; j++) {
      err = memdom_kill(j); 
      if (err) {
            printf("memdom_kill returned %d\n", err);
            err = -1;
        }
    }

    if (!err)
        printf("success\n");
    return err;
}

int main(){
    int success = 0;
    int total_tests = 5;

    smv_main_init(1);
    
    // single memdom_create --> expect success
    if (!test_memdom_create()) {
        success++;
    }

    // create all possible memdoms + one out of bounds --> expect fail
    if (!test_memdom_create_fail()) {
        success++;
    }

    printf("%d / %d memdom operations tests passed\n", success, total_tests);

    return 0;
}
