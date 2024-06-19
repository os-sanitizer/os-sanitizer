// --snprintf option usecase example

// triggering case:
// 1. snprintf to a buffer
// 2. use return value of snprintf to read/write from the buffer

#include <stdio.h>
#include <unistd.h>

int main ()
{
    char str_buf[16] = "0123456789abcdef";
    char *s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    // WTF! why does snprintf returns "characters that would have been written if n had been sufficiently large"
    int snprintf_result = snprintf(str_buf, 16, "%s", s);
    printf("snprintf return value: %d\n", snprintf_result);
    printf("Bytes actually written by snprintf: %d\n", 16);
    printf("Writing str_buf to STDOUT with snprintf return value.\n");
    ssize_t bytes_written = write(STDOUT_FILENO, str_buf, snprintf_result);
    printf("\n");
    printf("Bytes written by write %ld\n", bytes_written);
    printf("Success.\n");

    return 0;
}