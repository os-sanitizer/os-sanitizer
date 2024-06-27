// --system-absolute option usecase example

// triggering case:
// 1. execute command without absolute path

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

int main ()
{
    // char *s = "ls";
    // // "Load bearing" printf
    // // If this printf is not here this case is not detected
    // printf("%s\n", s);
    //
    // int ret = system(s);
    // printf("%d\n", ret);
    // return 0;

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