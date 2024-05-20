#ifndef FEA
#define FEA

#ifdef _WIN32
#include <Windows.h>
#endif /* _WIN32 */
#include <memory.h>

#include <cstdint>
#include <stdexcept>

typedef uint8_t wByte;

#define WMKC_FEA_NB 4
#define WMKC_FEA_NK 4
#define WMKC_FEA_NR 4

#define WMKC_FEA_BL 16 // WMKC FEA Block length

// 内存初始化处理
void memory_secure(void *p, size_t n);

enum class xcryptMode {ECB, CBC, CTR, CFB};

class fea {
private:
    void subBytes(wByte *block);
    void shiftBits(wByte *block);

    void invSubBytes(wByte *block);
    void invShiftBits(wByte *block);

    void shiftRows(wByte *block);
    void invShiftRows(wByte *block);

    void xorWithIV(wByte *block, wByte *iv);
    void keyExtension(wByte *key, wByte *iv);

    void cipher(wByte *p, wByte *roundKey);
    void invCipher(wByte *c, wByte *roundKey);

    void ecb_encrypt(wByte *p);
    void ecb_decrypt(wByte *c);

    void cbc_encrypt(wByte *p, size_t n);
    void cbc_decrypt(wByte *c, size_t n);

    void ctr_xcrypt(wByte *d, size_t n);

    void cfb_encrypt(wByte *p, size_t n, uint32_t segmentSize);
    void cfb_decrypt(wByte *c, size_t n, uint32_t segmentSize);

public:
    wByte key[WMKC_FEA_BL << 1];
    wByte iv[WMKC_FEA_BL];
    wByte nonce[WMKC_FEA_BL >> 1];
    wByte roundKey[sizeof(key) * WMKC_FEA_NR]; // len(key) * WMKC_FEA_NR
    uint32_t segmentSize;

    //////////////////////////////////////////////////////////////////

    fea(const wByte *key, const wByte *iv, const uint32_t segmentSize = 128);
    ~fea();
    void encrypt(wByte *content, size_t size, xcryptMode mode);
    void decrypt(wByte *content, size_t size, xcryptMode mode);
};

#endif /* FEA */
