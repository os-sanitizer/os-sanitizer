// --strcpy option usecase example

// triggering case:
// 1. strcpy directly copies to destination without any strlen checks

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

    strcpy(d, s);
    debug_printf("Success.\n");

    MICROBENCHMARK_LOOP_END

    return 0;
}