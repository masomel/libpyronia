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
  memdom[memdom_id]->start = NULL; // memdom_alloc will do the actual mmap
  memdom[memdom_id]->total_size = MEMDOM_HEAP_SIZE;
  memdom[memdom_id]->free_list_head = NULL;
  memdom[memdom_id]->free_list_tail = NULL;
  memdom[memdom_id]->allocs = NULL;
  memdom[memdom_id]->cur_alloc = 0;
  memdom[memdom_id]->peak_alloc = 0;
  pthread_mutex_init(&memdom[memdom_id]->mlock, NULL);

  return memdom_id;
}

/* Remove memory domain memdom from kernel */
int memdom_kill(int memdom_id){
  int rv = 0;
  char buf[50];
  struct alloc_metadata *free_list;

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

  printf("[%s] Memdom %d peak allocation: %lu bytes\n", __func__, memdom_id, memdom[memdom_id]->peak_alloc);

  /* Free mmap */
  if( memdom[memdom_id]->start ) {
    rv = munmap(memdom[memdom_id]->start, memdom[memdom_id]->total_size);
    if( rv != 0 ) {
      fprintf(stderr, "memdom munmap failed, start: %p, sz: %lu bytes\n", memdom[memdom_id]->start, memdom[memdom_id]->total_size);
    }
  }

  /* Free all free alloc_metadata in this memdom */
  free_list = memdom[memdom_id]->free_list_head;
  while( free_list ) {
    struct alloc_metadata *tmp = free_list;
    free_list = free_list->next;
    rlog("freeing free_list %p addr: %p, size: %lu bytes\n", tmp, tmp->addr, tmp->size);
    free(tmp);
  }

  /* Free any remaining allocated alloc_metadata in this memdom */
  free_list = memdom[memdom_id]->allocs;
  while( free_list ) {
    struct alloc_metadata *tmp = free_list;
    free_list = free_list->next;
    rlog("freeing remaining allocated block %p at addr: %p, size: %lu bytes\n", tmp, tmp->addr, tmp->size);
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
  memdom[memdom_id]->start = base;
  memdom[memdom_id]->total_size = len;

  rlog("Memdom ID %d mmaped at %p\n", memdom_id, base);

  rlog("[%s] memdom %d mmaped %lu bytes at %p\n", __func__, memdom_id, len, base);
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

static void dumpFreeListHead(int memdom_id) {
  struct alloc_metadata *walk = memdom[memdom_id]->free_list_head;
  while ( walk ) {
      rlog("[%s] memdom %d free_list addr: %p, sz: %lu\n",
           __func__, memdom_id, walk->addr, walk->size);
      walk = walk->next;
  }
}

struct alloc_metadata *walkAllocsList(int memdom_id, void *addr, int dump) {
  struct alloc_metadata *walk = memdom[memdom_id]->allocs;
  while ( walk ) {
      if (dump)
          rlog("[%s] memdom %d allocation addr: %p, sz: %lu\n",
               __func__, memdom_id, walk->addr, walk->size);
      if (walk->addr == addr)
          break;
      walk = walk->next;
  }
  return walk;
}

static struct alloc_metadata *alloc_metadata_init(void *addr, size_t size) {
    struct alloc_metadata *alloc = NULL;

    /* The first free list should be the entire mmap region */
#ifdef INTERCEPT_MALLOC
#undef malloc
#endif
    alloc = (struct alloc_metadata*) malloc (sizeof(struct alloc_metadata));
#ifdef INTERCEPT_MALLOC
#define malloc(sz) memdom_alloc(memdom_private_id(), sz)
#endif
    if (!alloc)
        return NULL;
    alloc->addr = addr;
    alloc->size = size;
    alloc->next = NULL;
    return alloc;
}

/* Insert a free chunk into the memdom free list in increasing by increasing start 
 * address.
 */
void free_list_insert(int memdom_id, struct alloc_metadata *new_free){
  int rv;
  struct alloc_metadata *head = memdom[memdom_id]->free_list_head;
  struct alloc_metadata *cur, *prev;
  
  if (!head) {
    new_free->next = head;
    memdom[memdom_id]->free_list_head = new_free;
    rlog("[%s] Reclaiming first free chunk in memdom %d\n", __func__, memdom_id);
    goto out;
  }
  cur = memdom[memdom_id]->free_list_head;
  prev = NULL;

  while (cur) {
    if (new_free->addr < cur->addr) {
      new_free->next = cur;
      rlog("[%s] Free chunk %p in memdom %d fits before current chunk %p\n", __func__, new_free->addr, memdom_id, cur->addr);

      if (new_free->addr + new_free->size == cur->addr) {
	// the new free chunk can be merged with cur
	new_free->size += cur->size;
	new_free->next = cur->next;
	free(cur);
	cur = new_free;
	rlog("[%s] Merging free chunk %p with current in memdom %d\n", __func__, new_free->addr, memdom_id);
      }
      
      if (!prev) {
	// we're inserting a chunk before the current head of the list
	memdom[memdom_id]->free_list_head = new_free;
	rlog("[%s] Inserting free chunk %p in memdom %d at the head\n", __func__, new_free->addr, memdom_id);
      }
      else if (prev && new_free->addr > prev->addr) {
	// we're inserting a chunk between two existing reclaimed chunks
	prev->next = new_free;

	rlog("[%s] Free chunk in memdom %d fits after previous chunk %p\n", __func__, memdom_id, prev->addr);

	if (prev->addr + prev->size == new_free->addr) {
	  // the new free chunk can be merged with prev
	  prev->size += new_free->size;
	  prev->next = new_free->next;
	  free(new_free);
	  cur = prev;

	  rlog("[%s] Merging free chunk in memdom %d with previous\n",  __func__, memdom_id);
	}
      }    

      goto out;
    }
    else if (cur->next == NULL && new_free->addr > cur->addr) {
      // we're inserting the new chunk at the end of the free list
      cur->next = new_free;

      rlog("[%s] Inserting free chunk %p in memdom %d after free list tail %p \n", __func__, new_free->addr, memdom_id, cur->addr);
      
      if (cur->addr + cur->size == new_free->addr) {
	// the new free chunk can be merged with cur
	cur->size += new_free->size;
	cur->next = new_free->next;
	free(new_free);

	rlog("[%s] Merging free chunk in memdom %d with current\n", __func__, memdom_id);
      }
      goto out;
    }

    prev = cur;
    cur = cur->next;
  }

 out:
  rlog("[%s] Free list head in memdom %d points at %p\n", __func__, memdom_id, memdom[memdom_id]->free_list_head->addr);
  return;
}

/* Insert a free list struct to the head of memdom free list
 * Reclaimed chunks are inserted to head
 */
void allocs_insert_to_head(int memdom_id, struct alloc_metadata *new_alloc){
  int rv;
  struct alloc_metadata *head = memdom[memdom_id]->allocs;
  if( head ) {
    new_alloc->next = head;
  }
  memdom[memdom_id]->allocs = new_alloc;
  rlog("[%s] memdom %d inserted allocation %p addr: %p, size: %lu, next: %p\n", __func__, memdom_id, new_alloc, new_alloc->addr, new_alloc->size, new_alloc->next);
}

// removes the reference, but does not free!
void remove_alloc_metadata_from(struct alloc_metadata *to_remove, struct alloc_metadata **src_list) {
    struct alloc_metadata *walk = *src_list;

    // in this case, we're trying to remove the head
    if (walk->addr == to_remove->addr) {
        *src_list = to_remove->next;
	if (*src_list)
	  rlog("[%s] New head of the list is %p with %lu bytes\n", __func__, (*src_list)->addr, (*src_list)->size);
	to_remove->next = NULL; // detach this block from the list
        return;
    }

    while (walk) {
        if (walk->next && walk->next->addr == to_remove->addr) {
            walk->next = to_remove->next;
	    to_remove->next = NULL; // detach this block from the list
            break;
        }
        walk = walk->next;
    }
}

/* Initialize free list */
void free_list_init(int memdom_id){
  struct alloc_metadata *new_free_list;

  new_free_list = alloc_metadata_init(memdom[memdom_id]->start, memdom[memdom_id]->total_size);
  memdom[memdom_id]->free_list_head = NULL;   // reclaimed chunk are inserted to head
  memdom[memdom_id]->free_list_tail = new_free_list;
  rlog("[%s] memdom %d: free_list addr: %p, size: %lu bytes\n", __func__, memdom_id, new_free_list->addr, new_free_list->size);
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
  struct alloc_metadata *free_list = NULL;
  struct alloc_metadata *new_alloc = NULL;

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

  rlog("[%s] memdom %d allocating sz %lu bytes\n", __func__, memdom_id, sz);

  /* First time this memdom allocates memory */
  if( !memdom[memdom_id]->start ) {
    /* Call mmap to set up initial memory region */

    memblock = (char*) memdom_mmap(memdom_id, 0, MEMDOM_HEAP_SIZE,
				   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_MEMDOM, 0, 0);
    if( memblock == MAP_FAILED ) {
      fprintf(stderr, "Failed to memdom_alloc using mmap for memdom %d\n", memdom_id);
      memblock = NULL;
      goto out;
    }

    /* Zero out the newly mapped memory block */
    memset(memblock, 0, MEMDOM_HEAP_SIZE);

    /* Initialize free list */
    free_list_init(memdom_id);
  }

  /* Round up size to multiple of cache line size: 64B */
  sz = round_up (sz, CHUNK_SIZE);
  rlog("[%s] request rounded to %lu bytes\n", __func__, sz);

  /* Get memory from the tail of free list, if the last free list is not available for allocation,
   * start searching the free list from the head until first fit is found.
   */
  free_list = memdom[memdom_id]->free_list_tail;

  /* Allocate from tail:
   * check if the last element in free list is available,
   * allocate memory from it */
  rlog("[%s] memdom %d search from tail for %lu bytes\n", __func__, memdom_id, sz);
  if ( free_list && sz <= free_list->size ) {
    memblock = free_list->addr;

    /* Adjust the last free list addr and size*/
    free_list->addr = free_list->addr + sz;
    free_list->size = free_list->size - sz;

    rlog("[%s] memdom %d last free list available, free_list addr: %p, remaining sz: %lu bytes\n",
	 __func__, memdom_id, free_list->addr, free_list->size);
    /* Last chunk is now allocated, tail is not available from now */
    if( free_list->size == 0 ) {
      free(free_list);
      memdom[memdom_id]->free_list_tail = NULL;
      rlog("[%s] free_list size is 0, freed this alloc_metadata, the next allocate should request from free_list_head\n", __func__);
    }
    new_alloc = alloc_metadata_init(memblock, sz);
    allocs_insert_to_head(memdom_id, new_alloc);
    goto out;
  }

  /* Allocate from head:
   * ok the last free list is not available,
   * let's start searching from the head for the first fit */
  rlog("[%s] memdom %d search from head for %lu bytes\n", __func__, memdom_id, sz);
  dumpFreeListHead(memdom_id);
  free_list = memdom[memdom_id]->free_list_head;
  struct alloc_metadata *prev = NULL;
  memblock = NULL;
  while (free_list) {
    if( prev ) {
      rlog("[%s] memdom %d prev->addr %p, prev->size %lu bytes\n", __func__, memdom_id, prev->addr, prev->size);
    }
    if( free_list ) {
      rlog("[%s] memdom %d free_list->addr %p, free_list->size %lu bytes\n", __func__, memdom_id, free_list->addr, free_list->size);
    }

    /* Found free list! */
    if( sz <= free_list->size ) {

      /* Get memory address */
      memblock = free_list->addr;

      // Since we found the perfect block, let's just move this block from the free list
      // into the allocs list
      if( free_list->size == sz ) {
          new_alloc = free_list;
          remove_alloc_metadata_from(free_list, &memdom[memdom_id]->free_list_head);
          rlog("[%s] Found perfect block. Move free list to allocs list\n", __func__);
      }
      /* Adjust free list:
       * if the remaining chunk size if greater then CHUNK_SIZE
       */
      else {
	char *ptr = (char*)free_list->addr;
	ptr = ptr + sz;
	free_list->addr = (void*)ptr;
	free_list->size = free_list->size - sz;
        new_alloc = alloc_metadata_init(memblock, sz);
	rlog("[%s] Adjust free list to addr %p, sz %lu\n",
	     __func__, free_list->addr, free_list->size);
      }
      allocs_insert_to_head(memdom_id, new_alloc);
      goto out;
    }

    /* Move pointer forward */
    prev = free_list;
    free_list = free_list->next;
  }

 out:
  if( !memblock ) {
    rlog("[%s] memdom_alloc failed: no memory can be allocated in memdom %d\n", __func__, memdom_id);
  }
  else{
    rlog("[%s] new_alloc in memdom %d: addr %p, allocated %lu bytes\n", __func__, memdom_id, new_alloc->addr, new_alloc->size);
    memdom[memdom_id]->cur_alloc += new_alloc->size;
    if (memdom[memdom_id]->cur_alloc > memdom[memdom_id]->peak_alloc)
      memdom[memdom_id]->peak_alloc = memdom[memdom_id]->cur_alloc;
    rlog("Current allocations: %lu bytes\n", memdom[memdom_id]->cur_alloc);
  }
  pthread_mutex_unlock(&memdom[memdom_id]->mlock);
  return memblock;
}

/* Deallocate data in memory domain memdom */
void memdom_free(void* data){
  int memdom_id = -1;
  struct alloc_metadata *alloc = NULL;
  
  if (!data) {
    rlog("[%s] Data block is NULL\n", __func__);
    return;
  }

  memdom_id = memdom_query_id(data);

  if (memdom_id == -1) {
    rlog("[%s] Data block at %p not in memdom\n", __func__, data);
    return;
  }
  else if (memdom_id == 0) {
    rlog("[%s] Freeing memory in main thread memdom\n", __func__);
    free(data);
    return;
  }

  rlog("[%s] Freeing for memdom %d\n", __func__, memdom_id);

  pthread_mutex_lock(&memdom[memdom_id]->mlock);

  rlog("[%s] allocs head: %p\n", __func__, memdom[memdom_id]->allocs);
  alloc = walkAllocsList(memdom_id, data, 1);
  if (!alloc) {
      rlog("[%s] Something went wrong. Data block at %p not found\n", __func__, data);
    return;
  }

  /* Free the memory */
  rlog("[%s] block addr: %p, freeing %lu bytes in memdom %d\n", __func__, alloc->addr, alloc->size, memdom_id);
  memset(data, 0, alloc->size);

  /* Move this metadata from the allocs to the free list */
  remove_alloc_metadata_from(alloc, &memdom[memdom_id]->allocs);
  memdom[memdom_id]->cur_alloc -= alloc->size;
  dumpFreeListHead(memdom_id);
  free_list_insert(memdom_id, alloc);
  rlog("[%s] allocs head: %p\n", __func__, memdom[memdom_id]->allocs);
  rlog("[%s] Move alloc to free list\n", __func__);
  rlog("Current allocations: %lu bytes\n", memdom[memdom_id]->cur_alloc);

  pthread_mutex_unlock(&memdom[memdom_id]->mlock);
}

/* Get the number of free bytes in a memdom */
unsigned long memdom_get_free_bytes(int memdom_id) {
    if (!memdom[memdom_id])
        return 0;
    return memdom[memdom_id]->total_size - memdom[memdom_id]->cur_alloc;
}
