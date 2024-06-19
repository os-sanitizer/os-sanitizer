// --access option usecase example
// man page warns about it: https://man7.org/linux/man-pages/man2/access.2.html#NOTES

// triggering case:
// 1. access
// 2. open

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main ()
{
    const char *filename = "sensitive_information.txt";
    printf("Let's try access like interaction.\n");
    // done using the calling process's real UID and GID
    // https://man7.org/linux/man-pages/man2/access.2.html#DESCRIPTION
    if(access (filename, R_OK) == 0) {
        printf("Read permission available.\n");
    } else {
        printf("Error: Read permission unavailable. Errno: %d\n", errno);
        return -1;
    }

    printf("Let's open the file.\n");
    // effective ID
    // https://man7.org/linux/man-pages/man2/access.2.html#DESCRIPTION
    int fd = open(filename, O_RDONLY);
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