#include "libk.h"

static int kc_call(struct kcrypto_req* req) {
    return (int)syscall2(SYS_CRYPTO, (uint32_t)(unsigned long)req);
}

int kc_sha256(const void* data, size_t len, unsigned char out[32]) {
    struct kcrypto_req req;
    req.op = KC_SHA256;
    req.in1 = (uint32_t)(unsigned long)data; req.in1_len = (uint32_t)len;
    req.in2 = 0; req.in2_len = 0;
    req.in3 = 0; req.in3_len = 0;
    req.in4 = 0; req.in4_len = 0;
    req.out = (uint32_t)(unsigned long)out; req.out_cap = 32;
    req.result = 0;
    return kc_call(&req);
}

int kc_hmac_sha256(const void* key, size_t klen, const void* msg, size_t mlen,
                   unsigned char out[32]) {
    struct kcrypto_req req;
    req.op = KC_HMAC_SHA256;
    req.in1 = (uint32_t)(unsigned long)key; req.in1_len = (uint32_t)klen;
    req.in2 = (uint32_t)(unsigned long)msg; req.in2_len = (uint32_t)mlen;
    req.in3 = 0; req.in3_len = 0;
    req.in4 = 0; req.in4_len = 0;
    req.out = (uint32_t)(unsigned long)out; req.out_cap = 32;
    req.result = 0;
    return kc_call(&req);
}

int kc_x25519(const unsigned char scalar[32], const unsigned char point[32],
              unsigned char out[32]) {
    struct kcrypto_req req;
    req.op = KC_X25519;
    req.in1 = (uint32_t)(unsigned long)scalar; req.in1_len = 32;
    req.in2 = (uint32_t)(unsigned long)point; req.in2_len = 32;
    req.in3 = 0; req.in3_len = 0;
    req.in4 = 0; req.in4_len = 0;
    req.out = (uint32_t)(unsigned long)out; req.out_cap = 32;
    req.result = 0;
    return kc_call(&req);
}

int kc_random(void* out, size_t n) {
    struct kcrypto_req req;
    req.op = KC_RANDOM;
    req.in1 = 0; req.in1_len = 0;
    req.in2 = 0; req.in2_len = 0;
    req.in3 = 0; req.in3_len = 0;
    req.in4 = 0; req.in4_len = 0;
    req.out = (uint32_t)(unsigned long)out; req.out_cap = (uint32_t)n;
    req.result = 0;
    return kc_call(&req);
}

int kc_ed25519_keygen(const unsigned char seed[32], unsigned char pk[32]) {
    struct kcrypto_req req;
    req.op = KC_ED25519_KEYGEN;
    req.in1 = (uint32_t)(unsigned long)seed; req.in1_len = 32;
    req.in2 = 0; req.in2_len = 0;
    req.in3 = 0; req.in3_len = 0;
    req.in4 = 0; req.in4_len = 0;
    req.out = (uint32_t)(unsigned long)pk; req.out_cap = 32;
    req.result = 0;
    return kc_call(&req);
}

int kc_ed25519_sign(unsigned char sig[64], const void* msg, size_t len,
                    const unsigned char sk[64]) {
    struct kcrypto_req req;
    req.op = KC_ED25519_SIGN;
    req.in1 = (uint32_t)(unsigned long)sk; req.in1_len = 64;
    req.in2 = (uint32_t)(unsigned long)msg; req.in2_len = (uint32_t)len;
    req.in3 = 0; req.in3_len = 0;
    req.in4 = 0; req.in4_len = 0;
    req.out = (uint32_t)(unsigned long)sig; req.out_cap = 64;
    req.result = 0;
    return kc_call(&req);
}

int kc_chacha20(void* out, const void* in, size_t len,
                const unsigned char key[32], const unsigned char nonce[12],
                uint32_t counter) {
    struct kcrypto_req req;
    req.op = KC_CHACHA20;
    req.in1 = (uint32_t)(unsigned long)key; req.in1_len = 32;
    req.in2 = (uint32_t)(unsigned long)nonce; req.in2_len = 12;
    req.in3 = (uint32_t)(unsigned long)in; req.in3_len = (uint32_t)len;
    req.in4 = 0; req.in4_len = counter;
    req.out = (uint32_t)(unsigned long)out; req.out_cap = (uint32_t)len;
    req.result = 0;
    return kc_call(&req);
}

int kc_poly1305(unsigned char tag[16], const void* msg, size_t len,
                const unsigned char key[32]) {
    struct kcrypto_req req;
    req.op = KC_POLY1305;
    req.in1 = (uint32_t)(unsigned long)key; req.in1_len = 32;
    req.in2 = (uint32_t)(unsigned long)msg; req.in2_len = (uint32_t)len;
    req.in3 = 0; req.in3_len = 0;
    req.in4 = 0; req.in4_len = 0;
    req.out = (uint32_t)(unsigned long)tag; req.out_cap = 16;
    req.result = 0;
    return kc_call(&req);
}

int kc_aead_encrypt(const unsigned char key[32], const unsigned char nonce[12],
                    const void* aad, size_t aad_len,
                    const void* plain, size_t plain_len, unsigned char* out) {
    struct kcrypto_req req;
    req.op = KC_AEAD_ENC;
    req.in1 = (uint32_t)(unsigned long)key; req.in1_len = 32;
    req.in2 = (uint32_t)(unsigned long)nonce; req.in2_len = 12;
    req.in3 = (uint32_t)(unsigned long)aad; req.in3_len = (uint32_t)aad_len;
    req.in4 = (uint32_t)(unsigned long)plain; req.in4_len = (uint32_t)plain_len;
    req.out = (uint32_t)(unsigned long)out; req.out_cap = (uint32_t)(plain_len + 16);
    req.result = 0;
    return kc_call(&req);
}

int kc_aead_decrypt(const unsigned char key[32], const unsigned char nonce[12],
                    const void* aad, size_t aad_len,
                    const void* cipher, size_t cipher_len, unsigned char* out) {
    struct kcrypto_req req;
    req.op = KC_AEAD_DEC;
    req.in1 = (uint32_t)(unsigned long)key; req.in1_len = 32;
    req.in2 = (uint32_t)(unsigned long)nonce; req.in2_len = 12;
    req.in3 = (uint32_t)(unsigned long)aad; req.in3_len = (uint32_t)aad_len;
    req.in4 = (uint32_t)(unsigned long)cipher; req.in4_len = (uint32_t)cipher_len;
    req.out = (uint32_t)(unsigned long)out; req.out_cap = (uint32_t)cipher_len;
    req.result = 0;
    return kc_call(&req);
}
