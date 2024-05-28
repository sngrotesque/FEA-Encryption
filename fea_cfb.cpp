#include "fea.hpp"

void FEA::cfb_encrypt(uint8_t *p, size_t n, uint32_t segmentSize)
{
    if(segmentSize & 7) {
        throw std::runtime_error("FEA::cfb_encrypt: "
            "The segment size is not a multiple of 8.");
    }

    size_t i, j;
    uint8_t round_iv[WMKC_FEA_BL];

    segmentSize >>= 3; // 将单位从位转到字节
    n = (n + segmentSize - 1) / segmentSize; // 得到总共有多少个数据段

    memcpy(round_iv, this->iv, WMKC_FEA_BL);
    for(i = 0; i < n; ++i) {
        this->cipher(round_iv, this->roundKey);
        for(j = 0; j < segmentSize; ++j) {
            *(p + (i * segmentSize + j)) ^= round_iv[j];
        }
        memcpy(round_iv, p + i * segmentSize, segmentSize);
    }
}

void FEA::cfb_decrypt(uint8_t *c, size_t n, uint32_t segmentSize)
{
    if(segmentSize & 7) {
        throw std::runtime_error("FEA::cfb_encrypt: "
            "The segment size is not a multiple of 8.");
    }

    size_t i, j;
    uint8_t round_iv[WMKC_FEA_BL];
    uint8_t tmp_buf[WMKC_FEA_BL];
    segmentSize >>= 3; // 将单位从位转到字节
    n = (n + segmentSize - 1) / segmentSize; // 得到总共有多少个数据段

    memcpy(round_iv, this->iv, WMKC_FEA_BL);
    for(i = 0; i < n; ++i) {
        memcpy(tmp_buf, c + i * segmentSize, segmentSize);
        this->cipher(round_iv, this->roundKey);
        for(j = 0; j < segmentSize; ++j) {
            *(c + (i * segmentSize + j)) ^= round_iv[j];
        }
        memcpy(round_iv, tmp_buf, segmentSize);
    }
}
