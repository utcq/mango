#include <stdio.h>
#include <unistd.h>

int main() {
    char buffer[32];
    
    read(0, buffer, 64);
    printf("Data: %s\n", buffer);
    return 0;
}
