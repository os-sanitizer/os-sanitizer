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
#else
#define debug_printf(...) printf(__VA_ARGS__)
#define MICROBENCHMARK_LOOP_START
#define MICROBENCHMARK_LOOP_END
#endif

#endif //COMMON_H
