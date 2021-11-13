#include "userswap.h"
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>

#define DIRTY 1
#define NOT_DIRTY 0

size_t pagesize = 4096;

size_t LORM = 8626176;

int total_resident_bytes = 0;

struct mem_size_node {
  void* starting_addr;
  int size;
  struct mem_size_node *next;
};

struct resident_node {
  void* starting_addr;
  int is_dirty;
  struct resident_node *next;
};

struct swap_file {
  void* starting_addr;
  int is_resident;
  struct swap_file* next;
};

struct mem_size_list { 
  struct mem_size_node *head;
};

struct resident_mem_list {
  struct resident_node *head;
};

struct mem_size_list *virtual_mem_list;

// all resident page will be stored here
struct resident_mem_list *resident_mem_list;

struct swap_file *swap_file;

void* align_address_to_start_page(void* address) {
  return (void*)(((uintptr_t)address) & ~(pagesize-1));
}

void initialize_mem_list() {
  if (virtual_mem_list == NULL) {
    virtual_mem_list = (struct mem_size_list*) malloc(sizeof(struct mem_size_list));
  }

  if (resident_mem_list == NULL) {
    resident_mem_list = (struct resident_mem_list*) malloc(sizeof(struct resident_mem_list));
  }

  if (swap_file == NULL) {
    swap_file = (struct swap_file*) malloc(sizeof(struct swap_file));
  }
}

// To insert node to virtual memory
void insert_new_node(void* addr, int size) {
  struct mem_size_node *newNode, *temp;
  newNode = (struct mem_size_node*) malloc(sizeof(struct mem_size_node));
  newNode->starting_addr = addr;
  newNode->size = size;
  newNode->next = NULL;

  if (virtual_mem_list->head == NULL) {
    virtual_mem_list->head = newNode;
  } else {
    temp = virtual_mem_list->head;
    
    // Traverse to last node
    while (temp != NULL && temp->next != NULL) {
      temp = temp->next;
    }
    temp->next = newNode;
  }
}

void insert_new_resident_node(void* addr) {
  struct resident_node *newNode, *temp;
  newNode = (struct resident_node*) malloc(sizeof(struct resident_node));
  newNode->starting_addr = addr;
  newNode->is_dirty = NOT_DIRTY;
  newNode->next = NULL;

  if (resident_mem_list->head == NULL) {
    resident_mem_list->head = newNode;
  } else {
    temp = resident_mem_list->head;
    
    // Traverse to last node
    while (temp != NULL && temp->next != NULL) {
      temp = temp->next;
    }
    temp->next = newNode;
  }


  total_resident_bytes += pagesize;
}

// Returns 1 if its in virtual memory region (can be found in virtual memory linked list)
int isInVirtualMemoryRegion(void* fault_address) {
  struct mem_size_node *temp;
  int res = 0;
  char* addr = (char*) fault_address;
  if (virtual_mem_list->head == NULL) {
    return res;
  } 

  temp = virtual_mem_list->head;
  while (temp != NULL) {
    char* temp_starting_address = (char*) temp->starting_addr;
    char* temp_ending_address = temp->size + temp_starting_address;
    if (addr >= temp_starting_address && addr <= temp_ending_address) {
      res = 1;
      break;
    }
    temp = temp->next;
  }
  return res;
}

// Returns the starting address of the resident page
void* get_resident_address(void* address) {
  struct resident_node *temp;
  if (resident_mem_list->head == NULL) {
    return NULL;
  }

  temp = resident_mem_list->head;
  while (temp != NULL) {
    if (address == temp->starting_addr) {
      return address;
    }
    temp = temp->next;
  }
  return NULL;
}

char* existing_swap;

void replace_swap(struct resident_node *resident_node) {

  if (existing_swap != NULL) {
    remove(existing_swap);
  }

  pid_t pid = getpid();
  char* pathname;
  char* filename = (char*)malloc(sizeof(char*));
  sprintf(filename, "%d", (int) pid);
  pathname = malloc(strlen(filename) + 1 + 5);
  // sprintf(pid, "%d", (int) pid);
  strcpy(pathname, filename);
  strcat(pathname, ".swap");
  // pathname += sprintf(pathname, "%d", (int) pid);
  // pathname += sprintf(pathname, "%s", ".swap");
  // char* pathname = strcat((char *) pid, ".swap");
  existing_swap = pathname;
  int fd = open(pathname, O_CREAT, S_IRUSR | S_IWUSR);
  if (write(fd, resident_node->starting_addr, pagesize) == -1) {
    printf("Write error");
  }
}

void evict_page() {

  // Removes the first page in resident linked list
  struct resident_node *temp = resident_mem_list->head;
  void *addr = resident_mem_list->head->starting_addr;

  if (resident_mem_list->head->next != NULL) {
    resident_mem_list->head = resident_mem_list->head->next;
  }

  // Regard, write new contents to a swap file, 
  // physical page is freed by madvise on the page
  // TODO: Write to swap file

  if (temp->is_dirty == DIRTY) {
    replace_swap(temp);
  }

  mprotect(addr, pagesize, PROT_NONE);
  madvise(addr, pagesize, MADV_DONTNEED);

  free(temp);

  total_resident_bytes -= pagesize;

}

struct swap_file* get_swap_file_info(void* address) {
  struct swap_file* temp = swap_file;
  
  if (swap_file->starting_addr == NULL) {
    return NULL;
  }

  while (temp != NULL) {
    if (address == temp->starting_addr) {
      return temp;
    }
    temp = temp->next;
  }
  return NULL;
}

void swap_file_restoration(void* addr, struct swap_file* swap_file) {

}


void page_fault_handler(void* fault_address) {
  fault_address = align_address_to_start_page(fault_address);

  struct resident_node* temp_resident_node = get_resident_address(fault_address);
  int is_resident = temp_resident_node != NULL;

  while (total_resident_bytes + pagesize > LORM) {
    evict_page();
  }

  struct swap_file* swap_file_information = get_swap_file_info(fault_address);
  int is_previously_evicted = swap_file_information != NULL;

  if (!is_resident) {
    if (is_previously_evicted) {
      mprotect(fault_address, pagesize, PROT_READ | PROT_WRITE);
      swap_file_restoration(fault_address, swap_file_information);
    }

    // make the address resident
    insert_new_resident_node(fault_address);
    mprotect(fault_address, pagesize, PROT_READ);
  } else {
    // page becomes dirty
    mprotect(fault_address, pagesize, PROT_READ | PROT_WRITE);
    temp_resident_node->is_dirty = DIRTY;
  }
}

static void sigsegv_handler(int sig, siginfo_t* info, void* context) {
  // TODO: NEED TO CHECK IF FAULTING MEMORY ADDRESS IS TO A CONTROLLED MEMORY REGION
  // IF NOT, RESET ACTION  TAKEN FOR A SIGSEGV SIGNAL, RETURN IMMEDIATELY,
  // ALLOW PROGRAM TO CRASH AS IT WOULD WITHOUT THE USER SPACE SWAP LIBRARY
  if (sig == SIGSEGV) {
    void* addr = align_address_to_start_page(info->si_addr);
    if (isInVirtualMemoryRegion(addr)) {
      page_fault_handler(addr);
    } else {
      signal(SIGSEGV, SIG_DFL);
    }
  }
}


// This function sets the LORM to size.
// If size is not a multiple of the page size, size should be rounded up to the next
// multiple of the page size.
// If the total size of resident memory in all controlled regions is above the new
// LORM, then the minimum number of pages should be evicted according to the
// page eviction algorithm until the total size is under or equal to the LORM. 
void userswap_set_size(size_t size) {
  size = (int)(ceil((double) size / (double) pagesize) * pagesize);
  LORM = size;
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
  // Initialize
  initialize_mem_list();
  void *addr;

  // ========================Install sigsev=================================
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = sigsegv_handler;
  sigaction(SIGSEGV, &sa, NULL);



  // If size is not a multiple of the page size, size should be rounded up to the next
  // multiple of the page size.
  // ========================================================================
  size_t sizeForMmap = 0;

  if (size <= pagesize) {
    sizeForMmap = pagesize;
  } else {
    sizeForMmap = (int) (ceil((double)size / (double)pagesize) * pagesize);
  }

  addr = mmap(NULL, sizeForMmap, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);


  // =========================================================================
  if (addr == MAP_FAILED) {
    printf("Mapping failed");
  } else {
    // successful mapping
    insert_new_node(addr, sizeForMmap);
  }

  return addr;
}


// mem can be assumed to be a pointer previously returned by userswap_alloc
// or userswap_map, and that has not been previously freed.
// If the memory region was allocated by userswap_map, then any changes made
// to the memory region must be written to the file accordingly. The file descriptor
// should not be closed. 
void userswap_free(void *mem) {
  // free virtual memory allocated
  struct mem_size_node *ptr = virtual_mem_list->head;
  struct mem_size_node *ptr_prev = virtual_mem_list->head;
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

  // free resident memory allocated
  struct resident_node *temp = resident_mem_list->head;
  struct resident_node *temp_prev = resident_mem_list->head;
  if (temp != NULL && temp == mem) {
    free(temp);
  }
  while (temp != NULL && temp != mem) {
    temp_prev = temp;
    temp = temp->next;
  }
  if (temp == NULL) {
    return;
  }
  temp_prev->next = temp->next;
  free(temp);
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
