// --interceptable-path option usecase example

// triggering case:
// 1. Create a directory with permission 777 -> others allowed to write
// 2. Try to open file inside this directory

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main ()
{
    // first do $ chmod o+w dir1
    printf("Please do `$ chmod o+w dir1` first.\n");

    printf("Now let's open dir1/dir2/sensitive_information.txt\n");
    const char *open_filename = "dir1/dir2/sensitive_information.txt";
    int fd = open(open_filename, O_RDONLY);
    if (fd == -1) {
        printf("Error: Can not open file. Errno: %d\n", errno);
        return -1;
    } else {
        printf("fd for reading file: %d\n", fd);
    }
    close(fd);

    printf("Success.\n");

    return 0;
}