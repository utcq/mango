#include <stdio.h>

int main() {
    char buffer[10];
    printf("Enter a string: ");

    scanf("%s", buffer);
    printf("You entered: ");
    printf(buffer);
    printf("\n");

    return 0;
}
