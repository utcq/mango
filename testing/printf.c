#include <stdio.h>

int main() {
    char buffer[32];
    gets(buffer);
    printf(buffer);
    return 0;
}