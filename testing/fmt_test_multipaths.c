#include <stdio.h>
#include <stdlib.h>

void vuln() {
    char buf[40];
    fgets(buf, 300, stdin);
    printf(buf);
    printf(buf);
}

void bridge2() {
    vuln();
}

void bridge1() {
    if (getchar() == 'a') {
        vuln();
    } else {
        bridge2();
    }
}

int main() {
    int choice = getchar();
    if (choice == '1') {
        vuln();
    } else if (choice == '2') {
        bridge1();
    } else {
        bridge1();
    }
    return 0;
}
