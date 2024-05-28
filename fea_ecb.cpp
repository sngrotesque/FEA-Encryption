#include "fea.hpp"

void FEA::ecb_encrypt(uint8_t *p)
{
    this->cipher(p, this->roundKey);
}

void FEA::ecb_decrypt(uint8_t *c)
{
    this->invCipher(c, this->roundKey);
}
