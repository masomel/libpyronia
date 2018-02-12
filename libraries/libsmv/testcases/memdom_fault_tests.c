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
#include <signal.h>
#include <setjmp.h>

#define MAIN_THREAD 0

sigjmp_buf point;

static void handler(int sig, siginfo_t *dont_care, void *dont_care_either)
{
   longjmp(point, 1);
}

static void prep_handler()
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(sigaction));
  sigemptyset(&sa.sa_mask);

  sa.sa_flags     = SA_NODEFER;
  sa.sa_sigaction = handler;

  sigaction(SIGSEGV, &sa, NULL); /* ignore whether it works or not */

}

static void memdom_write_trigger(const char c, char *buf) {
  buf[0] = c;
}

static int test_memdom_read_fault() {
    printf("-- Test: main thread memdom read fault... ");
    int memdom_id = -1;
    char *str;
    int err = -1;

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

    // need to add this domain to the main thread
    smv_join_domain(memdom_id, MAIN_THREAD);
    memdom_priv_add(memdom_id, MAIN_THREAD, MEMDOM_WRITE);

    printf("current memdom privs: %lu\n", memdom_priv_get(memdom_id, MAIN_THREAD));

    str = memdom_alloc(memdom_id, 6*sizeof(char));
    if (str == NULL) {
        goto out;
    }

    sprintf(str, "hello");
    memdom_priv_del(memdom_id, MAIN_THREAD, MEMDOM_WRITE);
    str[0] = 'b';
    printf("after write: %s\n", str);

    memdom_priv_add(memdom_id, MAIN_THREAD, MEMDOM_WRITE);

    
    /*
    memdom_priv_del(memdom_id, MAIN_THREAD, MEMDOM_WRITE);
    printf("current memdom privs: %lu\n", memdom_priv_get(memdom_id, MAIN_THREAD));

    prep_handler();
    if (setjmp(point) == 0)
      sprintf(str, "evil!");
    else {
        printf("caught segfault\n");
        err = 0;
	}*/

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

int main(){

    smv_main_init(0);

    int success = 0;
    int total_tests = 1;

    // trigger memdom read segfault
    if (!test_memdom_read_fault()) {
        success++;
    }

    /*
    // create all possible memdoms + one out of bounds --> expect fail
    if (!test_memdom_create_fail()) {
        success++;
    }

    // query the memdom id for different parts of the system --> expect success
    if (!test_memdom_queries()) {
        success++;
    }

    // allocate a buffer in main thread's memory domain --> expect success
    if (!test_memdom_alloc()) {
        success++;
        }*/

    printf("%d / %d memdom operations tests passed\n", success, total_tests);

    return 0;
}
