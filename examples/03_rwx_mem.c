// --rwx-mem option usecase example

// triggering case:
// 1. Allocate some memory
// 2. Set protection to write + execute

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

int main ()
{
    long pagesize = sysconf(_SC_PAGE_SIZE);
    printf("Page Size: %ld\n", pagesize);

    // Fedora didn't like mprotect PROT_EXEC on posix_memalign (ed) location. Ubuntu was fine.
    // https://stackoverflow.com/questions/48106059/calling-mprotect-on-dynamically-allocated-memory-results-in-error-with-error-cod#comment83221695_48106059

    int fd;
    const char *open_filename = "sensitive_information.txt";
    fd = open(open_filename, O_RDONLY);
    int *addr = mmap(NULL, pagesize , PROT_READ , MAP_PRIVATE, fd, 0);
    printf("Pointer to mmap(ped) area : %p\n", addr);

    int ret = mprotect(addr, pagesize, PROT_WRITE | PROT_EXEC);
    if (ret == -1) {
        printf("Error. Errno: %d\n", errno);
    } else {
        printf("mmap(ped) memory set to write + execute.\n");
    }

    munmap(addr, pagesize);
    close(fd);

    printf("Success.\n");

    return 0;
}
