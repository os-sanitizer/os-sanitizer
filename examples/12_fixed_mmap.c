// --fixed-mmap option usecase example

// triggering case:
// 1. Create a memaligned int (mmap uses page aligned addresses)
// 2. Force mmap to create a mapping on the same address as above int

#include <stdio.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

int main ()
{
    long pagesize = sysconf(_SC_PAGE_SIZE);
    printf("Page Size: %ld\n", pagesize);

    int *mem = memalign(pagesize, 4);
    *mem = 0xffff;
    printf("Variable value (hex): %x\n", *mem);
    printf("Variable address: %p\n", mem);

    const char *open_filename = "sensitive_information.txt";
    int fd = open(open_filename, O_RDONLY);
    int *addr = mmap(mem, 4 , PROT_READ , MAP_PRIVATE | MAP_FIXED, fd, 0);
    printf("mmap(ped) address with MAP_FIXED: %p\n", addr);

    printf("Variable value (hex): %x\n", *mem);
    close(fd);

    printf("Success.\n");

    return 0;
}