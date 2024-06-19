// --system-mutability option usecase example

// triggering case:
// 1. use command string that lies in writable memory

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main ()
{
    char s[5];
    strcpy(s, "ls");
    int ret = system(s);
    if (ret == 0) {
        printf("Success.\n");
    } else {
        printf("Error: Can not execute command. Errno: %d\n", errno);
        return -1;
    }

    return 0;
}
