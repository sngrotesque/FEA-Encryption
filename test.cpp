#include "fea.hpp"

#include <cstdio>

using namespace std;

int main(int argc, char **argv)
{
    const wByte *key = (wByte *)"0123456789abcdef0123456789abcdef";
    const wByte *iv  = (wByte *)"0123456789abcdef";
    fea fea_ctx(key, iv);

    char data[4096] = {"hello, world.\n"};

    wByte *buffer = (wByte *)data;
    size_t length = strlen(data);

    fea_ctx.encrypt(buffer, length, xcryptMode::CFB);

    for(size_t x = 0; x < length; ++x) {
        printf("%02x ", buffer[x]);
    }

    return 0;
}
