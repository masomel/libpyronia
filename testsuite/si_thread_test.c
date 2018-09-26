#include <stdio.h>
#include <string.h>
#include <pyronia_lib.h>
#include <error.h>
#include <errno.h>
#include <linux/pyronia_mac.h>
#include <smv_lib.h>
#include <pthread.h>

#define LIB_POLICY "/home/pyronia/libpyronia/testsuite/home.pyronia.si_thread_test-lib.prof"

static pthread_mutex_t mtx;
static pthread_cond_t cond_var;
static int i = 0;
static char *str = NULL;

void *f(void *args) {
  
  while (1) {
    pthread_mutex_lock(&mtx);
    i++;
    pthread_cond_signal(&cond_var);
    pthread_mutex_unlock(&mtx);
    pthread_mutex_lock(&mtx);
    printf("%d: hi from smv %d\n", i, smvthread_get_id());
    pthread_mutex_unlock(&mtx);
  }
  return NULL;
}

int main() {
  int smv_id1 = -1, smv_id2 = -1;
  int memdom_id = -1;
  char *to_copy = "Vanishing into thin air";
  pthread_t th;
  int err = 0;
  pthread_mutexattr_t attr;

  printf("******* SI Thread Test ********\n");
  
  smv_main_init(0);
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
  err = pthread_mutex_init(&mtx, &attr);
  printf("initialized mutex: %d\n", err);
  if (err)
    return -1;
  err = pthread_cond_init(&cond_var, NULL);
  printf("initialized cond_var: %d\n", err);
  if (err)
    return -1;
  
  smv_id1 = smv_create();
  if (smv_id1 == -1) {
    printf("smv ID 1 is -1\n");
    return -1;
  }

  smv_join_domain(0, smv_id1);
  memdom_priv_add(0, smv_id1, MEMDOM_READ | MEMDOM_WRITE);

  memdom_id = memdom_create();
  if (memdom_id == -1) {
    printf("memdom_id is -1\n");
    return -1;
  }

  smv_join_domain(memdom_id, 0);
  memdom_priv_add(memdom_id, 0, MEMDOM_READ | MEMDOM_WRITE);

  str = memdom_alloc(memdom_id, strlen(to_copy)+1);
  memcpy(str, to_copy, strlen(to_copy)+1);
  
  smv_id2 = smv_create();
  if (smv_id2 == -1) {
    printf("smv ID 2 is -1\n");
    return -1;
  }

  smv_join_domain(0, smv_id2);
  memdom_priv_add(0, smv_id2, MEMDOM_READ | MEMDOM_WRITE);
  smv_join_domain(memdom_id, smv_id2);
  memdom_priv_add(memdom_id, smv_id2, MEMDOM_READ | MEMDOM_WRITE);
  
  smvthread_create(smv_id2, &th, f, NULL);

  pthread_mutex_lock(&mtx);
  while (i < 5) {
    pthread_cond_wait(&cond_var, &mtx);
  }
  pthread_mutex_unlock(&mtx);

  pthread_mutex_lock(&mtx);
  printf("Done waiting for other thread\n");
  pthread_mutex_unlock(&mtx);

  printf("Final cleanup\n");
  
  pthread_cancel(th);

  printf("SI thread cancelled\n");
  memdom_free(str);
  //smv_kill(smv_id);

  return 0;
}
