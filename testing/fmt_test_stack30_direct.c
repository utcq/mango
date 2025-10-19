#include <stdio.h>
#include <stdlib.h>

int main() {
    char buf[40];
    fgets(buf, 300, stdin);
    printf(buf);
    printf(buf);
    return 0;
}
