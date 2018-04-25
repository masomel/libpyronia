#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <limits.h>
#include "memdom_lib.h"

struct memdom_metadata_struct *memdom[MAX_MEMDOM];

// defined in smv_lib.c
int message_to_kernel(char *message);

/* Create memory domain and return it to user */
int memdom_create(){
    int memdom_id;
    memdom_id = message_to_kernel("memdom,create");
    if( memdom_id == -1 ){
      fprintf(stderr, "memdom_create() failed\n");
      return -1;
    }
    /* Allocate metadata to hold memdom info */
#ifdef INTERCEPT_MALLOC
#undef malloc
#endif
    memdom[memdom_id] = (struct memdom_metadata_struct*) malloc(sizeof(struct memdom_metadata_struct));
#ifdef INTERCEPT_MALLOC
#define malloc(sz) memdom_alloc(memdom_private_id(), sz)
#endif
    memdom[memdom_id]->memdom_id = memdom_id;
    memdom[memdom_id]->mmap_blocks = NULL; // memdom_alloc will do the actual mmap
    memdom[memdom_id]->free_list_head = NULL;
    memdom[memdom_id]->free_list_tail = NULL;
    memdom[memdom_id]->alloc_list = NULL;
    pthread_mutex_init(&memdom[memdom_id]->mlock, NULL);

    return memdom_id;
}

/* Remove memory domain memdom from kernel */
int memdom_kill(int memdom_id){
    int rv = 0;
    char buf[50];
    struct free_list_struct *free_list;
    struct alloc_record *alloc_list, *mmap_block;

    /* Bound checking */
    if( memdom_id < 0 || memdom_id > MAX_MEMDOM ) {
      fprintf(stderr, "memdom_kill(%d) failed\n", memdom_id);
        return -1;
    }

    /* Checking for null memdom */
    if (memdom[memdom_id] == NULL) {
        fprintf(stderr, "memdom_kill(%d) failed\n", memdom_id);
        return -1;
    }

    /* Free mmap */
    mmap_block = memdom[memdom_id]->mmap_blocks;
    while (mmap_block) {
        rv = munmap(mmap_block->addr, mmap_block->size);
        if( rv != 0 ) {
            fprintf(stderr, "memdom munmap failed, start: %p, sz: 0x%lx bytes\n", mmap_block->addr, mmap_block->size);
        }
	mmap_block = mmap_block->next;
    }

    /* Free all free_list_struct in this memdom */
    free_list = memdom[memdom_id]->free_list_head;
    while( free_list ) {
        struct free_list_struct *tmp = free_list;
        free_list = free_list->next;
        rlog("freeing free_list addr: %p, size: 0x%lx bytes\n", tmp->addr, tmp->size);
        free(tmp);
    }

    /* Free all alloc_list_struct in this memdom */
    alloc_list = memdom[memdom_id]->alloc_list;
    while (alloc_list) {
        struct alloc_record *tmp = alloc_list;
        alloc_list = alloc_list->next;
        rlog("freeing alloc record for addr: %p, size: 0x%lx bytes\n", tmp->addr, tmp->size);
        free(tmp);
    }

    /* Free memdom metadata */
    free(memdom[memdom_id]);

    /* Send kill memdom info to kernel */
    sprintf(buf, "memdom,kill,%d", memdom_id);
    rv = message_to_kernel(buf);
    if( rv == -1 ){
        fprintf(stderr, "memdom_kill(%d) failed\n", memdom_id);
        return -1;
    }
    rlog("Memdom ID %d killed\n", memdom_id);
    return rv;
}

/* Insert a new allocation record at the head of the list.
 * Note: expects caller to hold the memdom lock.
 */
void add_new_alloc(struct alloc_record **head, void *addr, unsigned long size){
    struct alloc_record *new_record = NULL;

#ifdef INTERCEPT_MALLOC
#undef malloc
#endif
    new_record = malloc(sizeof(struct alloc_record));
#ifdef INTERCEPT_MALLOC
#define malloc(sz) memdom_alloc(memdom_private_id(), sz)
#endif

    new_record->addr = addr;
    new_record->size = size;
    new_record->next = *head;
    *head = new_record;
}

/* Search for the allocation record in the given memdom for the given
 * address.
 * Note: expects caller to hold the memdom lock.
 */
struct alloc_record *find_alloc_record(struct alloc_record *head,
				       void *addr) {
  struct alloc_record *runner = head;

  while(runner) {
    if (runner->addr == addr) {
      rlog("[%s] Found allocation for address %p\n", __func__, addr);
      return runner;
    }
    runner = runner->next;
  }
  return NULL;
}

/* Remove the allocation record in the given memdom for the given
 * address.
 * Note: expects caller to hold the memdom lock.
 */
void remove_alloc(struct alloc_record *head, void *addr) {
  struct alloc_record *runner = head;
  struct alloc_record *prev = NULL;

  while(runner) {
    if (runner->addr == addr) {
      if (prev)
	prev->next = runner->next;
      free(runner);
      break;
    }
    prev = runner;
    runner = runner->next;
  }
}

/* mmap memory in memdom
 * Caller should hold memdom lock
 */
void *memdom_mmap(int memdom_id,
                  unsigned long addr, unsigned long len,
                  unsigned long prot, unsigned long flags,
                  unsigned long fd, unsigned long pgoff){
    void *base = NULL;
    int rv = 0;
    char buf[50];

    /* Store memdom id in current->mmap_memdom_id in kernel */
    sprintf(buf, "memdom,mmapregister,%d", memdom_id);
    rv = message_to_kernel(buf);
    if( rv == -1 ){
        fprintf(stderr, "memdom_mmap_register(%d) failed\n", memdom_id);
        return NULL;
    }
    rlog("Memdom ID %d registered for mmap\n", memdom_id);

    /* Call the actual mmap with memdom flag */
    flags |= MAP_MEMDOM;
    base = (void*) mmap(NULL, len, prot, flags, fd, pgoff);
    if( base == MAP_FAILED ) {
        perror("memdom_mmap: ");
        return NULL;
    }

    add_new_alloc(&memdom[memdom_id]->mmap_blocks, base, len);
    
    rlog("Memdom ID %d mmaped at %p\n", memdom_id, memdom[memdom_id]->mmap_blocks->addr);

    rlog("[%s] memdom %d mmaped 0x%lx bytes at %p\n", __func__, memdom_id, len, base);
    return base;
}

/* Return privilege status of smv rib in memory domain memdom */
unsigned long memdom_priv_get(int memdom_id, int smv_id){
    int rv = 0;
    char buf[100];
    sprintf(buf, "memdom,priv,%d,%d,get", memdom_id, smv_id);
    rv = message_to_kernel(buf);
    if( rv == -1 ){
        rlog("kernel responded error\n");
        return -1;
    }
    rlog("smv %d in memdom %d has privilege: 0x%x\n", smv_id, memdom_id, rv);
    // ! should return privilege
    return rv;
}

/* Add privilege of smv rib in memory domain memdom */
int memdom_priv_add(int memdom_id, int smv_id, unsigned long privs){
    int rv = 0;
    char buf[100];
    sprintf(buf, "memdom,priv,%d,%d,add,%lu", memdom_id, smv_id, privs);
    rv = message_to_kernel(buf);
    if( rv == -1 ){
        rlog("kernel responded error\n");
        return -1;
    }
    rlog("smv %d in memdom %d has new privilege after add\n", smv_id, memdom_id);
    return rv;
}

/* Delete privilege of smv rib in memory domain memdom */
int memdom_priv_del(int memdom_id, int smv_id, unsigned long privs){
    int rv = 0;
    char buf[100];
    sprintf(buf, "memdom,priv,%d,%d,del,%lu", memdom_id, smv_id, privs);
    rv = message_to_kernel(buf);
    if( rv == -1 ){
        rlog("kernel responded error\n");
        return -1;
    }
    rlog("smv %d in memdom %d has new privilege after delete\n", smv_id, memdom_id);
    return rv;
}

/* Get the memdom id for global memory used by main thread */
int memdom_main_id(void){
    int rv = 0;
    char buf[100];
    sprintf(buf, "memdom,mainid");
    rv = message_to_kernel(buf);
    if( rv == -1 ){
        rlog("kernel responded error\n");
        return -1;
    }
    rlog("Global memdom id: %d\n", rv);
    return rv;
}

/* Get the memdom id of a memory address */
int memdom_query_id(void *obj){
    int rv = 0;
    char buf[1024];
    unsigned long addr;
    addr = (unsigned long)obj;
    sprintf(buf, "memdom,queryid,%lu", addr);
    rv = message_to_kernel(buf);
    if( rv == -1 ){
        rlog("kernel responded error\n");
        return -1;
    }
    //rlog("obj in memdom %d\n", rv);
    return rv;
}

/* Get calling thread's defualt memdom id */
int memdom_private_id(void){
    int rv = 0;
    char buf[1024];
#ifdef THREAD_PRIVATE_STACK
    sprintf(buf, "memdom,privateid");
    rv = message_to_kernel(buf);
    if( rv == -1 ){
        rlog("kernel responded error\n");
        return -1;
    }
#else
    rv = 0;
#endif
    rlog("private memdom id: %d\n", rv);
    return rv;
}

void dumpFreeListHead(int memdom_id){
    struct free_list_struct *walk = memdom[memdom_id]->free_list_head;
    while ( walk ) {
        rlog("[%s] memdom %d free_list addr: %p, sz: 0x%lx\n",
                __func__, memdom_id, walk->addr, walk->size);
        walk = walk->next;
    }
}

/* Insert a free list struct to the head of memdom free list
 * Reclaimed chunks are inserted to head
 */
void free_list_insert_to_head(int memdom_id, struct free_list_struct *new_free_list){
    int rv;
    struct free_list_struct *head = memdom[memdom_id]->free_list_head;
    if( head ) {
        new_free_list->next = head;
    }
    memdom[memdom_id]->free_list_head = new_free_list;
    rlog("[%s] memdom %d inserted free list addr: %p, size: 0x%lx\n", __func__, memdom_id, new_free_list->addr, new_free_list->size);
}

/* Initialize free list */
void free_list_init(struct alloc_record *head, int memdom_id){
    struct free_list_struct *new_free_list;

    /* The first free list should be the entire mmap region */
#ifdef INTERCEPT_MALLOC
#undef malloc
#endif
    new_free_list = (struct free_list_struct*) malloc (sizeof(struct free_list_struct));
#ifdef INTERCEPT_MALLOC
#define malloc(sz) memdom_alloc(memdom_private_id(), sz)
#endif
    new_free_list->addr = head->addr;
    new_free_list->size = head->size;
    new_free_list->next = NULL;
    if (memdom[memdom_id]->free_list_tail)
      memdom[memdom_id]->free_list_tail->next = new_free_list;
    memdom[memdom_id]->free_list_tail = new_free_list;
    rlog("[%s] memdom %d: free_list addr: %p, size: 0x%lx bytes\n", __func__, memdom_id, new_free_list->addr, new_free_list->size);
}

/* Round up the number to the nearest multiple */
unsigned long round_up(unsigned long numToRound, int multiple){
    int remainder = 0;
    if( multiple == 0 ) {
        return 0;
    }
    remainder = numToRound % multiple;
    if( remainder == 0 ) {
        return numToRound;
    }
    return numToRound + multiple - remainder;
}

/* Allocate memory in memory domain memdom */
void *memdom_alloc(int memdom_id, unsigned long sz){
    void *memblock = NULL;
    struct free_list_struct *free_list = NULL;
    int alloc_retry = 0;
    
    /* Memdom 0 is in global memdom, Memdom -1 when defined THREAD_PRIVATE_STACK, use malloc */
    if(memdom_id == 0){
#ifdef INTERCEPT_MALLOC
#undef malloc
#endif
      memblock = malloc(sz);
#ifdef INTERCEPT_MALLOC
#define malloc(sz) memdom_alloc(memdom_private_id(), sz)
#endif
        return memblock;
    }

    pthread_mutex_lock(&memdom[memdom_id]->mlock);

    rlog("[%s] memdom %d allocating sz 0x%lx bytes\n", __func__, memdom_id, sz);

    /* First time this memdom allocates memory */
    if (!memdom[memdom_id]->mmap_blocks) {
        /* Call mmap to set up initial memory region */

        memblock = memdom_mmap(memdom_id, 0, MEMDOM_HEAP_SIZE,
			       PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_MEMDOM, 0, 0);
        if( memblock == MAP_FAILED ) {
	    fprintf(stderr, "Failed to memdom_alloc using mmap for memdom %d\n", memdom_id);
	    memblock = NULL;
	    goto out;
	}

	/* Initialize free list  */
	free_list_init(memdom[memdom_id]->mmap_blocks, memdom_id);
	memdom[memdom_id]->free_list_head = NULL;   // reclaimed chunk are inserted to head    
    }

 alloc_try:
    /* Round up size to multiple of cache line size: 64B
     * Note that the size of should block_header + the actual data
     * --------------------------------------
     * | block header |      your data       |
     * --------------------------------------
     */
    sz = round_up(sz, CHUNK_SIZE);
    rlog("[%s] request rounded to 0x%lx bytes\n", __func__, sz);

    /* Get memory from the tail of free list, if the last free list is not available for allocation,
     * start searching the free list from the head until first fit is found.
     */
    free_list = memdom[memdom_id]->free_list_tail;

    /* Allocate from tail:
     * check if the last element in free list is available,
     * allocate memory from it */
    rlog("[%s] memdom %d search from tail for 0x%lx bytes in free_list %p\n", __func__, memdom_id, sz, free_list);
    if ( free_list && sz <= free_list->size ) {
        memblock = free_list->addr;

        /* Adjust the last free list addr and size */
        free_list->addr = (char*)free_list->addr + sz;
        free_list->size = free_list->size - sz;

        rlog("[%s] memdom %d last free list available, free_list addr: %p, remaining sz: 0x%lx bytes\n",
                __func__, memdom_id, free_list->addr, free_list->size);
        /* Last chunk is now allocated, tail is not available from now */
        if( free_list->size == 0 ) {
            free(free_list);
            memdom[memdom_id]->free_list_tail = NULL;
            rlog("[%s] free_list size is 0, freed this free_list_struct, the next allocate should request from free_list_head\n", __func__);
        }
        goto out;
    }

    /* Allocate from head:
     * ok the last free list is not available,
     * let's start searching from the head for the first fit */
    rlog("[%s] memdom %d search from head for 0x%lx bytes\n", __func__, memdom_id, sz);
    dumpFreeListHead(memdom_id);
    free_list = memdom[memdom_id]->free_list_head;
    struct free_list_struct *prev = NULL;
    while (free_list) {
        if( prev ) {
            rlog("[%s] memdom %d prev->addr %p, prev->size 0x%lx bytes\n", __func__, memdom_id, prev->addr, prev->size);
        }
        if( free_list ) {
            rlog("[%s] memdom %d free_list->addr %p, free_list->size 0x%lx bytes\n", __func__, memdom_id, free_list->addr, free_list->size);
        }

        /* Found free list! */
        if( sz <= free_list->size ) {

	     /* Get memory address */
            memblock = (char*)free_list->addr;

            /* Adjust free list:
             * if the remaining chunk size if greater then CHUNK_SIZE
             */
            if( free_list->size - sz >= CHUNK_SIZE ) {
                char *ptr = (char*)free_list->addr;
                ptr = ptr + sz;
                free_list->addr = (void*)ptr;
                free_list->size = free_list->size - sz;
                rlog("[%s] Adjust free list to addr %p, sz 0x%lx\n",
                        __func__, free_list->addr, free_list->size);
            }
            /* Remove this free list struct:
             * since there's no memory to allcoate from here anymore
             */
            else{
                if ( free_list == memdom[memdom_id]->free_list_head ) {
                    memdom[memdom_id]->free_list_head = memdom[memdom_id]->free_list_head->next;
                    rlog("[%s] memdom %d set free_list_head to free_list_head->next\n", __func__, memdom_id);
                }
                else {
                    prev->next = free_list->next;
                    rlog("[%s] memdom %d set prev->next to free_list->next\n", __func__, memdom_id);
                }
                free(free_list);

                rlog("[%s] memdom %d removed free list\n", __func__, memdom_id);
            }
            goto out;
        }
        else {
          // we can try to merge this free list with the previous one
          if (prev && (prev->addr+prev->size+1 == free_list->addr)) {
            // if we get here, we likely have another small
            // free list before us, so let's merge them
            prev->size += free_list->size;
            prev->next = free_list->next;
            printf("[%s] Merge free lists to addr %p with list addr %p, sz 0x%lx\n",
                 __func__, free_list->addr, prev->addr, prev->size);
            free(free_list);
            free_list = prev;
          }
          else {
            /* Move pointer forward */
            prev = free_list;
            free_list = free_list->next;
          }
        }
    }

out:
    if( !memblock ) {
        fprintf(stderr, "memdom_alloc failed: no memory can be allocated in memdom %d\n", memdom_id);
	memblock = memdom_mmap(memdom_id, 0, MEMDOM_HEAP_SIZE,
			       PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_MEMDOM, 0, 0);
        if (memblock == MAP_FAILED && alloc_retry) {
	  fprintf(stderr, "Failed to memdom_alloc using mmap for memdom %d\n", memdom_id);
	  memblock = NULL;
	}
	else {
	  rlog("[%s] Allocated new mmap block %p\n", __func__, memblock);
	  free_list_init(memdom[memdom_id]->mmap_blocks, memdom_id);
	  alloc_retry = 1;
	  goto alloc_try;
	}
    }
    else{
        /* Record allocated memory in an allocation record for free to use later */
        add_new_alloc(&memdom[memdom_id]->alloc_list, memblock, sz);
	rlog("[%s] allocated 0x%lx bytes and returning data addr %p\n", __func__, sz, memblock);
    }

    pthread_mutex_unlock(&memdom[memdom_id]->mlock);
    return memblock;
}

/* Deallocate data in memory domain memdom */
void memdom_free(void* data){
    struct alloc_record *record;
    int memdom_id = -1;

    /* Let's figure out first if this data even is allocated in
     * a memdom. */
    memdom_id = memdom_query_id(data);
    if (memdom_id <= 0) {
        rlog("[%s] Attempted to free non-memdom data %p\n", __func__, data);
        return;
    }

    pthread_mutex_lock(&memdom[memdom_id]->mlock);

    /* Find the corresponding allocation record */
    record = find_alloc_record(memdom[memdom_id]->alloc_list, data);
    if (!record) {
        rlog("[%s] Oops, could not find an allocation record for data %p\n", __func__, data);
        pthread_mutex_unlock(&memdom[memdom_id]->mlock);
        return;
    }

    /* Free the memory */
    rlog("[%s] Freeing 0x%lx bytes at %p in memdom %d\n", __func__, record->size, data, memdom_id);
    memset(data, 0, record->size);

    /* Create a new free list node */
#ifdef INTERCEPT_MALLOC
#undef malloc
#endif
    struct free_list_struct *free_list = (struct free_list_struct *) malloc(sizeof(struct free_list_struct));
#ifdef INTERCEPT_MALLOC
#define malloc(sz) memdom_alloc(memdom_private_id(), sz)
#endif
    free_list->addr = record->addr;
    free_list->size = record->size;
    free_list->next = NULL;

    /* Insert the block into free list head */
    free_list_insert_to_head(memdom_id, free_list);

    /* Remove the allocation record */
    remove_alloc(memdom[memdom_id]->alloc_list, record->addr);

    pthread_mutex_unlock(&memdom[memdom_id]->mlock);
}
