#include <stdlib.h>
#include <stdio.h>
#include "common.h"

extern long interation_count;

void sigint_handler()
{
    printf("Iterations: %ld\n", interation_count);
    exit(0);
}