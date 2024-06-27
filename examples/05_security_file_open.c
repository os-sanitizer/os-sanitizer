// --security-file-open option usecase example

// triggering case:
// 1. make file rw- by others
// 2. open file

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "common.h"

int main ()
{
    // first do $ chmod 666 05_demo_file.txt
    debug_printf("Please do `$ chmod 666 05_demo_file.txt` first.\n");
    debug_printf("Now let's open file 05_demo_file.txt\n");
    const char *open_filename = "05_demo_file.txt";

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
