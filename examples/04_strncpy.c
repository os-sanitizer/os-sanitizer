// --strncpy option usecase example

// triggering case:
// 1. strncpy copies stlen(source) bytes to destination

#include <stdio.h>
#include <string.h>
#include "common.h"

long interation_count = 0;

int main ()
{
    // stacksmashing case
    // char *s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char *s = "aaaaaaa";
    char d[8];

    MICROBENCHMARK_LOOP_START

    strncpy(d, s, strlen(s));
    debug_printf("Success.\n");

    MICROBENCHMARK_LOOP_END

    return 0;
}