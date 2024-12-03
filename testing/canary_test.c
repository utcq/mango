#include <stdio.h>

int main() {
    char buffer[50];

    printf("Write FMT: ");
    gets(buffer);
    printf("Formatted: ");
    printf(buffer);

    return 0;
}