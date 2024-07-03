// --fixed-mmap option usecase example

// triggering case:
// 1. Create a memaligned int (mmap uses page aligned addresses)
// 2. Force mmap to create a mapping on the same address as above int

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include "common.h"

long interation_count = 0;

int main ()
{
    long pagesize = sysconf(_SC_PAGE_SIZE);
    debug_printf("Page Size: %ld\n", pagesize);
    const char *open_filename = "sensitive_information.txt";
    int fd = open(open_filename, O_RDONLY);

    MICROBENCHMARK_LOOP_START

    int *mem = memalign(pagesize, pagesize);
    *mem = 0xffff;
    debug_printf("Variable value (hex): %x\n", *mem);
    debug_printf("Variable address: %p\n", mem);

    int *addr = mmap(mem, pagesize , PROT_READ , MAP_PRIVATE | MAP_FIXED, fd, 0);
    if (addr != mem) {
        debug_printf("sanity mem: %p\n", mem);
        debug_printf("sanity addr: %p. Errno: %d\n", addr, errno);
    }
    assert(addr == mem);
    debug_printf("mmap(ped) address with MAP_FIXED: %p\n", addr);
    debug_printf("Variable value (hex): %x\n", *mem);
    munmap(addr, pagesize);
    debug_printf("Success.\n");

    MICROBENCHMARK_LOOP_END

    close(fd);
    return 0;
}