#include "userswap.h"
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>



struct mem_size_list { 
  struct mem_size_node *head;
};

 struct mem_size_node {
  void* starting_addr;
  int size;
  struct mem_size_node *next;
};

struct mem_size_list *lst_tracker;

void insert_new_node(void* addr, int size) {
  struct mem_size_node *newNode, *temp;
  newNode = (struct mem_size_node*) malloc(sizeof(struct mem_size_node));
  newNode->starting_addr = addr;
  newNode->size = size;
  newNode->next = NULL;

  if (lst_tracker->head == NULL) {
    lst_tracker->head = newNode;
  } else {
    temp = lst_tracker->head;
    
    // Traverse to last node
    while (temp != NULL && temp->next != NULL) {
      temp = temp->next;
    }
    temp->next = newNode;
  }
}

void page_fault_handler(void* fault_address) {
  mprotect(fault_address, 1, PROT_READ);
}

static void sigsegv_handler(int signal, siginfo_t* info, void* context) {
  // TODO: NEED TO CHECK IF FAULTING MEMORY ADDRESS IS TO A CONTROLLED MEMORY REGION
  // IF NOT, RESET ACTION  TAKEN FOR A SIGSEGV SIGNAL, RETURN IMMEDIATELY,
  // ALLOW PROGRAM TO CRASH AS IT WOULD WITHOUT THE USER SPACE SWAP LIBRARY
  printf("Signal %d received\n", signal);
  page_fault_handler(info->si_addr);
  abort();
}


// This function sets the LORM to size.
// If size is not a multiple of the page size, size should be rounded up to the next
// multiple of the page size.
// If the total size of resident memory in all controlled regions is above the new
// LORM, then the minimum number of pages should be evicted according to the
// page eviction algorithm until the total size is under or equal to the LORM. 
void userswap_set_size(size_t size) {

}

// This function should allocate size bytes of memory that is controlled by the
// swap scheme described above in the “Controlled memory regions” section, and
// return a pointer to the start of the memory.
// This function may be called multiple times without any intervening
// userswap_free, i.e., there may be multiple memory allocations active at any
// given time.
// If the SIGSEGV handler has not yet been installed when this function is called,
// then this function should do so. 
void *userswap_alloc(size_t size) {
  // Initialize linked list for tracking if does not exist
  if (lst_tracker == NULL) {
    lst_tracker = (struct mem_size_list*) malloc(sizeof(struct mem_size_list));
  }

  printf("Checkpoint 1");

  // Install sigsev
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = sigsegv_handler;
  sigaction(SIGSEGV, &sa, NULL);

  printf("Checkpoint 2");

  void *addr;
  // If size is not a multiple of the page size, size should be rounded up to the next
  // multiple of the page size.
  // ============TODO: SIZEFORMMAP LOGIC IS WRONG===========================
  size_t sizeForMmap = 0;
  size_t pagesize = sysconf(_SC_PAGE_SIZE);
  if (size <= pagesize) {
    sizeForMmap = pagesize;
  } else {
    sizeForMmap = ceil(size / pagesize) * pagesize;
  }
  addr = mmap(NULL, sizeForMmap, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);

  printf("Checkpoint 3");

  // =========================================================================
  if (addr == MAP_FAILED) {
    printf("Mapping failed");
  } else {
    // successful mapping
    insert_new_node(addr, sizeForMmap);
  }

  printf("Checkpoint 4");


  return addr;
}


// mem can be assumed to be a pointer previously returned by userswap_alloc
// or userswap_map, and that has not been previously freed.
// If the memory region was allocated by userswap_map, then any changes made
// to the memory region must be written to the file accordingly. The file descriptor
// should not be closed. 
void userswap_free(void *mem) {
  // TODO: SHOULD BE FREEING ONE NODE OF MEM PASSED IN THE PARAM.
  struct mem_size_node *ptr = lst_tracker->head;
  struct mem_size_node *ptr_prev = lst_tracker->head;
  if (ptr != NULL && ptr == mem) {
    munmap(ptr->starting_addr, ptr->size);
    free(ptr);
  }
  while (ptr != NULL && ptr != mem) {
    ptr_prev = ptr;
    ptr = ptr->next;
  }
  if (ptr == NULL) {
    return;
  }
  ptr_prev->next = ptr->next;
  munmap(ptr->starting_addr, ptr->size);
  free(ptr);
}

// This function should map the first size bytes of the file open in the file descriptor
// fd, using the swap scheme described above in the “Controlled memory regions”
// section. fd should always be -1
// If size is not a multiple of the page size, size should be rounded up to the next
// multiple of the page size.
// The file shall be known as the backing file. fd can be assumed to be a valid
// file descriptor opened in read-write mode using the open syscall, but no
// assumptions should be made as to the current offset of the file descriptor. The
// file descriptor, once handed to userswap_map, can be assumed to be fully
// controlled by your library, i.e., no other code will perform operations using the
// file descriptor.
// If the file is shorter than size bytes, then this function should also cause the file
// to be zero-filled to size bytes.
// Like userswap_alloc, this function may be called multiple times without any
// intervening userswap_free, i.e., there may be multiple memory allocations
// active at any given time.
// If the SIGSEGV handler has not yet been installed when this function is called,
// then this function should do so. 
void *userswap_map(int fd, size_t size) {
  return NULL;
}
