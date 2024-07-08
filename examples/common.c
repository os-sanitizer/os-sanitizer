#include <stdlib.h>
#include <stdio.h>
#include "common.h"

#ifdef MICROBENCHMARK_FP_UNL
extern long interation_count_t1;
extern long interation_count_t2;
extern long interation_count_t3;
extern long interation_count_t4;
extern FILE* fp;
#else
extern long interation_count;
#endif

#ifdef MICROBENCHMARK_FP_UNL
void sigint_handler()
{
    printf("Iterations: %ld\n", interation_count_t1 + interation_count_t2 + interation_count_t3 + interation_count_t4);
    fclose(fp);
    exit(0);
}
#else
void sigint_handler()
{
    printf("Iterations: %ld\n", interation_count);
    exit(0);
}
#endif