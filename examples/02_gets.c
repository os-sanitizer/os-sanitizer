// --gets option usecase example

// https://cplusplus.com/reference/cstdio/gets/
// [NOTE: This function is no longer available in C or C++ (as of C11 & C++14)]

// triggering case:
// 1. gets

#include <stdio.h>
#include "common.h"

// forward declare -- this is not provided in stdio and causes a compiler error
extern char *gets(char *s);

long interation_count = 0;

int main ()
{
    debug_printf("Let's try gets.\n");
    char string[10];

    MICROBENCHMARK_LOOP_START

    debug_printf("Type something and press enter.\n");
    // works fine with input: aaaaa
    // stack smashing with: aaaaaaaaaaaaaaaaaaaaaaaaaaaa
    gets(string);
    debug_printf("You entered: %s\n",string);
    debug_printf("Success.\n");

    MICROBENCHMARK_LOOP_END

    return 0;
}
