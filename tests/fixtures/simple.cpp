#include <cstring>

void foo(char *dst, char *src, int len) {
    if (len > 0)
        memcpy(dst, src, len);
}