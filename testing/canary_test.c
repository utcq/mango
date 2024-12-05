#include <stdio.h>

int main() {
    char buffer[50];

    printf("Write FMT: ");
    gets(buffer);
    printf("Formatted: ");
    printf(buffer);

    gets(buffer);
    printf("Unformatted: ");
    printf(buffer);

    return 0;
}