// --strcpy option usecase example

// triggering case:
// 1. strcpy directly copies to destination without any strlen checks

#include <stdio.h>
#include <string.h>

int main ()
{
    // stacksmashing case
    // char *s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char *s = "aaaaaaa";
    char d[8];

    strcpy(d, s);

    printf("Success.\n");

    return 0;
}