// --sprintf option usecase example

// triggering case:
// 1. create stack buffer
// 2. sprintf to stack buffer

#include <stdio.h>
#include "common.h"

int main ()
{
    char buffer [16];
    char *s = "aaaaaaaaaaaaaaa";

    MICROBENCHMARK_LOOP_START

    sprintf(buffer, "%s goes", s);
    debug_printf("Success.\n");

    MICROBENCHMARK_LOOP_END

    return 0;
}