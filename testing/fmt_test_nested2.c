#include <stdio.h>
#include <stdlib.h>

void vuln2() {
    char buf[40];
    fgets(buf, 300, stdin);
    printf(buf);
    printf(buf);
}

void vuln1() {
    vuln2();
}

int main() {
    vuln1();
    return 0;
}
