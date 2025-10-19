#include <stdio.h>
#include <stdlib.h>

void vuln() {
    char buf[40];
    fgets(buf, 300, stdin);
    printf(buf);
    printf(buf);
}

int main() {
    vuln();
    return 0;
}
