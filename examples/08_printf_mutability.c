// --printf-mutability option usecase example

// triggering case:
// 1. use format string that lies in writable memory

#include <stdio.h>
#include <string.h>

int main (int argc, char **argv)
{
    printf(argv[0]);
    printf("Success.\n");

    return 0;
}
