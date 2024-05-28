#include "fea.hpp"

#include "fea.cpp"
#include "fea_ecb.cpp"
#include "fea_cbc.cpp"
#include "fea_cfb.cpp"
#include "fea_ctr.cpp"

#include <iostream>
using namespace std;

static const uint8_t *key = (uint8_t *)"abcdef0123456789abcdef0123456789";
static const uint8_t *iv  = (uint8_t *)"abcdef0123456789";

void PRINT_HEX(const uint8_t *data, size_t len, size_t num, bool newline, bool tableChar)
{
    for(size_t x = 0; x < len; ++x) {
        if(tableChar && ((x) % num == 0)) printf("\t");

        printf("%02x", data[x]);

        if((x + 1) % num) printf(" ");
        else printf("\n");
    }
    if(newline) printf("\n");
}

int main()
{
    FEA fea(key, iv);
    char data[2048] = {"321"};

    uint8_t *buffer = (uint8_t *)data;
    size_t length = strlen(data);

    fea.encrypt(buffer, length, xcryptMode::CTR);

    // cout << "RoundKey:\n"; PRINT_HEX(fea.roundKey, sizeof(fea.roundKey), 32, 0, 1);
    cout << "Ciphertext:\n"; PRINT_HEX(buffer, length, 32, (length % 32), 1);

    return 0;
}
