// --sprintf option usecase example

// triggering case:
// 1. create stack buffer
// 2. sprintf to stack buffer

#include <stdio.h>

int main ()
{
    char buffer [16];
    char *s = "aaaaaaaaaaaaaaa";
    sprintf(buffer, "%s goes", s);
    printf("Success.\n");

    return 0;
}