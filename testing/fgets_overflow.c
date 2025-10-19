#include <stdio.h>

int main() {
    char buffer[16];
    
    fgets(buffer, 64, stdin);
    printf("Data: %s\n", buffer);
    return 0;
}
