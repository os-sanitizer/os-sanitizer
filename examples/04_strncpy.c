// --strncpy option usecase example

// triggering case:
// 1. strncpy copies stlen(source) bytes to destination

#include <stdio.h>
#include <string.h>

int main ()
{
    // stacksmashing case
    // char *s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char *s = "aaaaaaa";
    char d[8];
    strncpy(d, s, strlen(s));

    printf("Success.\n");

    return 0;
}