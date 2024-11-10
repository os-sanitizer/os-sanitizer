// --system-mutability option usecase example

// triggering case:
// 1. use command string that lies in writable memory

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

long interation_count = 0;

int main ()
{
    char s[5];
    strcpy(s, "ls");

    MICROBENCHMARK_LOOP_START

    int ret = system(s);
    if (ret == 0) {
        debug_printf("Success.\n");
    } else {
        debug_printf("Error: Can not execute command. Errno: %d\n", errno);
        return -1;
    }

    MICROBENCHMARK_LOOP_END

    return 0;
}
