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
    MICROBENCHMARK_LOOP_START

    int *mem = mmap(0, sizeof(int), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *mem = 0xffff;
    debug_printf("Variable value (hex): %x\n", *mem);
    debug_printf("Variable address: %p\n", mem);

    int *addr = mmap(mem, sizeof(int), PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (addr != mem) {
        debug_printf("sanity mem: %p\n", mem);
        debug_printf("sanity addr: %p. Errno: %d\n", addr, errno);
    }
    assert(addr == mem);
    debug_printf("mmap(ped) address with MAP_FIXED: %p\n", addr);
    debug_printf("Variable value (hex): %x\n", *mem);
    munmap(addr, sizeof(int));
    debug_printf("Success.\n");

    MICROBENCHMARK_LOOP_END

    return 0;
}
