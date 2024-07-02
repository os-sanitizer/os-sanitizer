// --printf-mutability option usecase example

// triggering case:
// 1. use format string that lies in writable memory

#include <stdio.h>
#include "common.h"

long interation_count = 0;

int main (int argc, char **argv)
{
    MICROBENCHMARK_LOOP_START

    printf(argv[0]);
    printf("Benign print\n");
    debug_printf("Success.\n");

    MICROBENCHMARK_LOOP_END

    return 0;
}
