// --interceptable-path option usecase example

// triggering case:
// 1. Create a directory with permission 777 -> others allowed to write
// 2. Try to open file inside this directory

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "common.h"

long interation_count = 0;

int main ()
{
    // first do $ chmod o+w dir1
    debug_printf("Please do `$ chmod o+w dir1` first.\n");
    debug_printf("Now let's open dir1/dir2/sensitive_information.txt\n");
    const char *open_filename = "dir1/dir2/sensitive_information.txt";

    MICROBENCHMARK_LOOP_START

    int fd = open(open_filename, O_RDONLY);
    if (fd == -1) {
        debug_printf("Error: Can not open file. Errno: %d\n", errno);
        return -1;
    } else {
        debug_printf("fd for reading file: %d\n", fd);
    }
    close(fd);
    debug_printf("Success.\n");

    MICROBENCHMARK_LOOP_END

    return 0;
}