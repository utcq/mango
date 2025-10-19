#include <stdio.h>
#include <stdlib.h>

void vuln3() {
    char buf[40];
    fgets(buf, 300, stdin);
    printf(buf);
    printf(buf);
}

void vuln1() {
    vuln3();
}

void vuln2() {
    vuln3();
}

int main() {
    if (getchar() == 'a') {
        vuln1();
    } else {
        vuln2();
    }
    return 0;
}
