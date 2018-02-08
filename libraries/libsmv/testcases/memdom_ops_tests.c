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
    for (j = 1; j < i; j++) {
      if (memdom_kill(j)) {
	printf("memdom_kill returned %d\n", j);
	err = -1;
      }
    }
    
    if (!err)
        printf("success\n");
    return err;
}

static int test_memdom_alloc() {
    printf("-- Test: main thread memdom alloc... ");
    int memdom_id = -1;
    char *str;
    int err = 0;

    memdom_id = memdom_create();
    if (memdom_id == -1) {
        printf("memdom_create returned %d\n", memdom_id);
        return -1;
    }

    str = memdom_alloc(memdom_id, 6*sizeof(char));
    if (str == NULL) {
        err = -1;
        goto out;
    }

    sprintf(str, "hello");
    printf("allocated: %s\n", str);

    memdom_free(str);

 out:
    if (memdom_kill(memdom_id)) {
        printf("memdom_kill returned %d\n", memdom_id);
        err = -1;
    }
    if (!err)
        printf("success\n");
    return err;
}

static int test_memdom_queries() {
    printf("-- Test: main thread memdom queries... ");
    int memdom_id = -1;
    int str_memdom_id = -1;
    char *str;
    int err = 0;

    memdom_id = memdom_main_id();
    if (memdom_id != 0) {
        printf("Expected %d, got %d\n", 0, memdom_id);
        return -1;
    }

    memdom_id = memdom_create();
    if (memdom_id == -1) {
        printf("memdom_create returned %d\n", memdom_id);
        return -1;
    }

    str = memdom_alloc(memdom_id, 6*sizeof(char));
    if (str == NULL) {
        err = -1;
        str_memdom_id = memdom_id;
        goto out;
    }

    sprintf(str, "hello");

    str_memdom_id = memdom_query_id(str);
    if (str_memdom_id != memdom_id) {
        printf("Expected memdom_id %d, got %d\n", memdom_id, str_memdom_id);
        memdom_free(str);
        err = -1;
        goto out;
    }

    memdom_free(str);

    memdom_id = memdom_private_id();
    if (memdom_id != 0) {
        printf("Expected %d, got %d\n", 0, memdom_id);
        err = -1;
    }

 out:
    if (memdom_kill(str_memdom_id)) {
        printf("memdom_kill returned %d\n", str_memdom_id);
        err = -1;
    }
    if (!err)
        printf("success\n");
    return err;
}

int main(){

    smv_main_init(0);

    int success = 0;
    int total_tests = 4;

    smv_main_init(1);
    
    // single memdom_create --> expect success
    if (!test_memdom_create()) {
        success++;
    }

    // create all possible memdoms + one out of bounds --> expect fail
    if (!test_memdom_create_fail()) {
        success++;
    }

    // allocate a buffer in main thread's memory domain --> expect success
    if (!test_memdom_alloc()) {
        success++;
    }

    // query the memdom id for different parts of the system --> expect success
    if (!test_memdom_queries()) {
        success++;
    }

    printf("%d / %d memdom operations tests passed\n", success, total_tests);

    return 0;
}
