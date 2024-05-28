#include "fea.hpp"

static void nonce_add(uint8_t *counter)
{
    for(int32_t ctr_i = (WMKC_FEA_BL - 1); ctr_i >= 0; --ctr_i) {
        if(*(counter + ctr_i) == 0xff) {
            *(counter + ctr_i) = 0x00;
        } else {
            ++(*(counter + ctr_i));
            break;
        }
    }
}

void FEA::ctr_xcrypt(uint8_t *d, size_t n)
{
    size_t i, ks_i;
    uint8_t ks[WMKC_FEA_BL]{};
    uint8_t counter[WMKC_FEA_BL]{};

    memcpy(counter, this->nonce.nonce, this->nonce.size);

    for(i = 0, ks_i = WMKC_FEA_BL; i < n; ++i, ++ks_i) {
        if(ks_i == WMKC_FEA_BL) {
            memcpy(ks, counter, WMKC_FEA_BL);
            this->cipher(ks, this->roundKey);

            nonce_add(counter);

            ks_i = 0;
        }
        *(d + i) ^= *(ks + ks_i);
    }
}
