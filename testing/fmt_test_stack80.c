#include <stdio.h>
#include <stdlib.h>

void vuln() {
    char buf[120];
    fgets(buf, 300, stdin);
    printf(buf);
    printf(buf);
}

int main() {
    vuln();
    return 0;
}
