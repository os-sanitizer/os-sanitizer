// --filep-unlocked option usecase example

// triggering case:
// 1. force program to use _unlocked functions outside the locks in multiple threads

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include "common.h"

long interation_count = 0;

void *unlocked_function_call_1(void* fp)
{
    debug_printf("Thread 1\n");
    FILE* fp_t = fp;
    fputc_unlocked(65, fp_t);
    return NULL;
}

void *unlocked_function_call_2(void* fp)
{
    debug_printf("Thread 2\n");
    FILE* fp_t = fp;
    fputc_unlocked(66, fp_t);
    return NULL;
}

void *unlocked_function_call_3(void* fp)
{
    debug_printf("Thread 3\n");
    FILE* fp_t = fp;
    fputc_unlocked(67, fp_t);
    return NULL;
}

void *unlocked_function_call_4(void* fp)
{
    debug_printf("Thread 4\n");
    FILE* fp_t = fp;
    fputc_unlocked(68, fp_t);
    return NULL;
}

int main ()
{

    FILE* fp;
    pthread_t thread1, thread2, thread3, thread4;

    fp = fopen("11_filep_unlocked_demo_file.txt", "w");
    debug_printf("Got %p. Errno: %d\n", fp, errno);

    MICROBENCHMARK_LOOP_START

    pthread_create(&thread1, NULL, unlocked_function_call_1, fp);
    pthread_create(&thread2, NULL, unlocked_function_call_2, fp);
    pthread_create(&thread3, NULL, unlocked_function_call_3, fp);
    pthread_create(&thread4, NULL, unlocked_function_call_4, fp);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    pthread_join(thread4, NULL);
    debug_printf("Success.\n");

    MICROBENCHMARK_LOOP_END

    fclose(fp);
    return 0;
}