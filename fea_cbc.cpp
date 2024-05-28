#include "fea.hpp"

void FEA::cbc_encrypt(uint8_t *p, size_t n)
{
    uint8_t roundIv[WMKC_FEA_BL];

    memcpy(roundIv, this->iv, WMKC_FEA_BL);
    for(uint32_t i = 0; i < n; i += WMKC_FEA_BL) {
        this->xorWithIV(p + i, roundIv);
        this->cipher(p + i, this->roundKey);
        memcpy(roundIv, p + i, WMKC_FEA_BL);
    }
}

void FEA::cbc_decrypt(uint8_t *c, size_t n)
{
    uint8_t roundIv[WMKC_FEA_BL];
    uint8_t roundBuffer[WMKC_FEA_BL];

    memcpy(roundIv, this->iv, WMKC_FEA_BL);
    for(uint32_t i = 0; i < n; i += WMKC_FEA_BL) {
        memcpy(roundBuffer, c + i, WMKC_FEA_BL);
        this->invCipher(c + i, this->roundKey);
        this->xorWithIV(c + i, roundIv);
        memcpy(roundIv, roundBuffer, WMKC_FEA_BL);
    }
}
