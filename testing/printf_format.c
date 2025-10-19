#include <stdio.h>

int main() {
    char buffer[64];
    
    fgets(buffer, 64, stdin);
    printf(buffer);
    return 0;
}
