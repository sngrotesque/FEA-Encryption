#ifndef FEA_CIPHER
#define FEA_CIPHER

#ifdef _WIN32
#include <Windows.h>
#endif /* _WIN32 */
#include <memory.h>

#include <cstdint>
#include <stdexcept>

#define WMKC_FEA_NB 4
#define WMKC_FEA_NK 4
#define WMKC_FEA_NR 4

#define WMKC_FEA_BL 16 // WMKC FEA Block length

// 内存初始化处理
void memory_secure(void *p, size_t n);

enum class xcryptMode {ECB, CBC, CTR, CFB};

class Nonce_CTX {
    public:
        uint8_t nonce[WMKC_FEA_BL];
        uint32_t size;
        Nonce_CTX(uint8_t *nonce, const uint32_t size)
        : nonce(), size(size)
        {
            memcpy(this->nonce, nonce, size);
        }

        Nonce_CTX(std::string nonce)
        : nonce(), size(nonce.size())
        {
            memcpy(this->nonce, nonce.data(), size);
        }
};

/*
* 此算法，使用任意加密模式的情况下，即使提供了对应模式所需的数据，也不能缺失IV。
* 比如，使用CTR模式的情况下，即使提供了Nonce，但是也不能没有IV，因为RoundKey是经过keyExtension函数由Key和IV共同生成的。
* 如果缺失了IV或者传入的IV实际长度不是$(WMKC_FEA_BL)，那么加密结果将变得不可控。
* 
* 与AES算法不同，此算法，需要IV与Key共同作用生成加/解密所需的密钥，所以，即使是使用CTR模式，也请加上IV，并确保IV的
* 长度等于$(WMKC_FEA_BL)。
* 
* 当然，你在使用CTR模式的情况下，自然也可以不加入Nonce，同样可以正常加/解密，但是吧，密文的安全性，由你自己保证。
*/
#if defined(_WIN32) && defined(_MSC_VER)
class __declspec(dllexport) FEA
#else
class FEA
#endif
{
private:
    void subBytes(uint8_t *block);
    void shiftBits(uint8_t *block);

    void invSubBytes(uint8_t *block);
    void invShiftBits(uint8_t *block);

    void shiftRows(uint8_t *block);
    void invShiftRows(uint8_t *block);

    void xorWithIV(uint8_t *block, uint8_t *iv);

    void cipher(uint8_t *p, uint8_t *roundKey);
    void invCipher(uint8_t *c, uint8_t *roundKey);

    void keyExtension(const uint8_t *key, const uint8_t *iv);

    void ecb_encrypt(uint8_t *p);
    void ecb_decrypt(uint8_t *c);

    void cbc_encrypt(uint8_t *p, size_t n);
    void cbc_decrypt(uint8_t *c, size_t n);

    void ctr_xcrypt(uint8_t *d, size_t n);

    void cfb_encrypt(uint8_t *p, size_t n, uint32_t segmentSize);
    void cfb_decrypt(uint8_t *c, size_t n, uint32_t segmentSize);

public:
    uint8_t key[WMKC_FEA_BL << 1];
    uint8_t iv[WMKC_FEA_BL];
    uint8_t roundKey[sizeof(key) * WMKC_FEA_NR];

    Nonce_CTX nonce;
    uint32_t segmentSize;

    FEA(const uint8_t *key, const uint8_t *iv, Nonce_CTX nonce = {nullptr, 0},
        const uint32_t segmentSize = 128);
    ~FEA();
    void encrypt(uint8_t *content, size_t size, xcryptMode mode);
    void decrypt(uint8_t *content, size_t size, xcryptMode mode);
};

#endif /* FEA_CIPHER */
