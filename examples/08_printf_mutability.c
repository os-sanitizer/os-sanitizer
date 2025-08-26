// --printf-mutability option usecase example

// triggering case:
// 1. use format string that lies in writable memory

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include "common.h"

long interation_count = 0;

int main (int argc, char **argv)
{
    int fd = open("/dev/null", O_WRONLY);
    if (fd == -1) {
        debug_printf("Error: Can not open file. Errno: %d\n", errno);
        return -1;
    } else {
        debug_printf("fd for reading file: %d\n", fd);
    }
    setvbuf(stdout, NULL, _IONBF, 0);

    MICROBENCHMARK_LOOP_START

    dprintf(fd, argv[0]);
    debug_printf("Success.\n");

    MICROBENCHMARK_LOOP_END

    close(fd);
    return 0;
}
