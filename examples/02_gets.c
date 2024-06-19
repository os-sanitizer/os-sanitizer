// --gets option usecase example

// Compiler warns here:
// $ gcc 02_gets.c -o 02_gets                                                                                                                                                                9:24:27
// 02_gets.c: In function ‘main’:
// 02_gets.c:11:5: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
//    11 |     gets(string);
// |     ^~~~
// |     fgets
// /usr/bin/ld: /tmp/ccHdyF2w.o: in function `main':
// 02_gets.c:(.text+0x46): warning: the `gets' function is dangerous and should not be used.

// https://cplusplus.com/reference/cstdio/gets/
// [NOTE: This function is no longer available in C or C++ (as of C11 & C++14)]

// triggering case:
// 1. gets

#include <stdio.h>

int main ()
{
    printf("Let's try gets.\n");
    char string[10];
    printf("Type something and press enter.\n");
    // works fine with input: aaaaa
    // stack smashing with: aaaaaaaaaaaaaaaaaaaaaaaaaaaa
    gets(string);
    printf("You entered: %s\n",string);

    printf("Success.\n");

    return 0;
}