#include "userswap.h"
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>

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
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = sigsegv_handler;
  sigaction(SIGSEGV, &sa, NULL);

  char *addr;
  // If size is not a multiple of the page size, size should be rounded up to the next
  // multiple of the page size.
  long sizeForMmap = 0;
  long pagesize = sysconf(_SC_PAGE_SIZE);
  if (size <= pagesize) {
    sizeForMmap = pagesize;
  } else {
    sizeForMmap = pagesize * 2;
  }
  addr = mmap(NULL, sizeForMmap, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (addr == MAP_FAILED) {
    printf("Mapping failed");
  }

  return addr;
}

void sigsegv_handler(int signal, siginfo_t* info, void* context) {
  printf("Signal %d received\n", signal);
  abort();
}

// mem can be assumed to be a pointer previously returned by userswap_alloc
// or userswap_map, and that has not been previously freed.
// If the memory region was allocated by userswap_map, then any changes made
// to the memory region must be written to the file accordingly. The file descriptor
// should not be closed. 
void userswap_free(void *mem) {

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
