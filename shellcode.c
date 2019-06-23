#include <stdio.h>
#include <string.h>

char code[] =
"";

int main() {
    printf("length: %lu\n", strlen(code));
    ((int(*)()) code)();
}
