// --printf-mutability option usecase example
// TODO: is not detected

// triggering case:
// 1. use format string that lies in writable memory

#include <stdio.h>
#include <string.h>

int main ()
{
    int variable = 12345;
    char s[5];
    strcpy(s, "%d\n");
    printf(s, variable);
    printf("Success.\n");

    return 0;
}