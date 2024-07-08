#ifndef COMMON_H
#define COMMON_H

void sigint_handler();

#ifdef MICROBENCHMARK
#include <signal.h>
#include <unistd.h>
#define debug_printf(...) (0)
#define MICROBENCHMARK_LOOP_START\
    signal(SIGALRM, sigint_handler);\
    alarm(10);\
    while(1){
#define MICROBENCHMARK_LOOP_END\
    interation_count++;\
    }
#define MICROBENCHMARK_PREREQ_FP_UNL\
    signal(SIGALRM, sigint_handler);\
    alarm(10);
#define MICROBENCHMARK_LOOP_START_FP_UNL\
    while(1){
#define MICROBENCHMARK_LOOP_END_FP_UNL_T1\
    interation_count_t1++;\
    }
#define MICROBENCHMARK_LOOP_END_FP_UNL_T2\
    interation_count_t2++;\
    }
#define MICROBENCHMARK_LOOP_END_FP_UNL_T3\
    interation_count_t3++;\
    }
#define MICROBENCHMARK_LOOP_END_FP_UNL_T4\
    interation_count_t4++;\
    }
#else
#define debug_printf(...) printf(__VA_ARGS__)
#define MICROBENCHMARK_LOOP_START
#define MICROBENCHMARK_LOOP_END
#define MICROBENCHMARK_PREREQ_FP_UNL
#define MICROBENCHMARK_LOOP_START_FP_UNL
#define MICROBENCHMARK_LOOP_END_FP_UNL_T1
#define MICROBENCHMARK_LOOP_END_FP_UNL_T2
#define MICROBENCHMARK_LOOP_END_FP_UNL_T3
#define MICROBENCHMARK_LOOP_END_FP_UNL_T4
#endif

#endif //COMMON_H
