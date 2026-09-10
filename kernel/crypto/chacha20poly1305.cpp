// ChaCha20-Poly1305 AEAD (RFC 8439). Freestanding.
#include "chacha20poly1305.h"
#include <string.h>

#define ROTL32(v, c) (uint32_t)(((v) << (c)) | ((v) >> (32 - (c))))

static void chacha20_quarter(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = in[i];
    for (int i = 0; i < 10; i++) {
        chacha20_quarter(&x[0],&x[4],&x[8], &x[12]);
        chacha20_quarter(&x[1],&x[5],&x[9], &x[13]);
        chacha20_quarter(&x[2],&x[6],&x[10],&x[14]);
        chacha20_quarter(&x[3],&x[7],&x[11],&x[15]);
        chacha20_quarter(&x[0],&x[5],&x[10],&x[15]);
        chacha20_quarter(&x[1],&x[6],&x[11],&x[12]);
        chacha20_quarter(&x[2],&x[7],&x[8], &x[13]);
        chacha20_quarter(&x[3],&x[4],&x[9], &x[14]);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

static uint32_t load32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store32(uint8_t* p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

static void chacha20_init_state(uint32_t st[16], const uint8_t key[32],
                                const uint8_t nonce[12], uint32_t counter) {
    st[0]=0x61707865; st[1]=0x3320646e; st[2]=0x79622d32; st[3]=0x6b206574;
    for (int i = 0; i < 8; i++) st[4+i] = load32(key + i*4);
    st[12] = counter;
    st[13] = load32(nonce + 0);
    st[14] = load32(nonce + 4);
    st[15] = load32(nonce + 8);
}

void chacha20_xor(uint8_t* out, const uint8_t* in, size_t len,
                  const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint8_t ks[64];
    size_t done = 0;
    while (done < len) {
        uint32_t st[16], blk[16];
        chacha20_init_state(st, key, nonce, counter++);
        chacha20_block(blk, st);
        for (int i = 0; i < 16; i++) store32(ks + i*4, blk[i]);
        size_t chunk = len - done; if (chunk > 64) chunk = 64;
        for (size_t i = 0; i < chunk; i++) out[done+i] = (uint8_t)(in[done+i] ^ ks[i]);
        done += chunk;
    }
}

/* ---- Poly1305 (donna-32, 5x26-bit limbs) ---- */

struct poly1305_state {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
};

static void poly1305_blocks(struct poly1305_state* st, const uint8_t* m,
                            size_t bytes, uint32_t hibit) {
    const uint32_t r0=st->r[0], r1=st->r[1], r2=st->r[2], r3=st->r[3], r4=st->r[4];
    uint32_t h0=st->h[0], h1=st->h[1], h2=st->h[2], h3=st->h[3], h4=st->h[4];
    const uint32_t s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    while (bytes >= 16) {
        uint32_t t0=load32(m+0), t1=load32(m+4), t2=load32(m+8), t3=load32(m+12);
        uint64_t d0,d1,d2,d3,d4; uint32_t c;
        h0 += t0 & 0x3ffffff;
        h1 += ((t0>>26)|(t1<<6)) & 0x3ffffff;
        h2 += ((t1>>20)|(t2<<12)) & 0x3ffffff;
        h3 += ((t2>>14)|(t3<<18)) & 0x3ffffff;
        h4 += (t3>>8) | hibit;
        d0=(uint64_t)h0*r0+(uint64_t)h1*s4+(uint64_t)h2*s3+(uint64_t)h3*s2+(uint64_t)h4*s1;
        d1=(uint64_t)h0*r1+(uint64_t)h1*r0+(uint64_t)h2*s4+(uint64_t)h3*s3+(uint64_t)h4*s2;
        d2=(uint64_t)h0*r2+(uint64_t)h1*r1+(uint64_t)h2*r0+(uint64_t)h3*s4+(uint64_t)h4*s3;
        d3=(uint64_t)h0*r3+(uint64_t)h1*r2+(uint64_t)h2*r1+(uint64_t)h3*r0+(uint64_t)h4*s4;
        d4=(uint64_t)h0*r4+(uint64_t)h1*r3+(uint64_t)h2*r2+(uint64_t)h3*r1+(uint64_t)h4*r0;
        c=(uint32_t)(d0>>26); h0=(uint32_t)d0&0x3ffffff;
        d1+=c; c=(uint32_t)(d1>>26); h1=(uint32_t)d1&0x3ffffff;
        d2+=c; c=(uint32_t)(d2>>26); h2=(uint32_t)d2&0x3ffffff;
        d3+=c; c=(uint32_t)(d3>>26); h3=(uint32_t)d3&0x3ffffff;
        d4+=c; c=(uint32_t)(d4>>26); h4=(uint32_t)d4&0x3ffffff;
        h0+=c*5; c=h0>>26; h0&=0x3ffffff; h1+=c;
        m += 16; bytes -= 16;
    }
    st->h[0]=h0; st->h[1]=h1; st->h[2]=h2; st->h[3]=h3; st->h[4]=h4;
}

static void poly1305_init(struct poly1305_state* st, const uint8_t key[32]) {
    uint32_t t0=load32(key+0), t1=load32(key+4), t2=load32(key+8), t3=load32(key+12);
    st->r[0] = t0 & 0x3ffffff;
    st->r[1] = ((t0>>26)|(t1<<6)) & 0x3ffff03;
    st->r[2] = ((t1>>20)|(t2<<12)) & 0x3ffc0ff;
    st->r[3] = ((t2>>14)|(t3<<18)) & 0x3f03fff;
    st->r[4] = (t3>>8) & 0x00fffff;
    st->h[0]=st->h[1]=st->h[2]=st->h[3]=st->h[4]=0;
    st->pad[0]=load32(key+16); st->pad[1]=load32(key+20);
    st->pad[2]=load32(key+24); st->pad[3]=load32(key+28);
}

static void poly1305_finish(struct poly1305_state* st, uint8_t tag[16]) {
    uint32_t h0=st->h[0],h1=st->h[1],h2=st->h[2],h3=st->h[3],h4=st->h[4];
    uint32_t c;
    c=h1>>26; h1&=0x3ffffff;
    h2+=c; c=h2>>26; h2&=0x3ffffff;
    h3+=c; c=h3>>26; h3&=0x3ffffff;
    h4+=c; c=h4>>26; h4&=0x3ffffff;
    h0+=c*5; c=h0>>26; h0&=0x3ffffff; h1+=c;

    /* compute h + -p and select if h >= p */
    uint32_t g0,g1,g2,g3,g4,mask;
    g0=h0+5; c=g0>>26; g0&=0x3ffffff;
    g1=h1+c; c=g1>>26; g1&=0x3ffffff;
    g2=h2+c; c=g2>>26; g2&=0x3ffffff;
    g3=h3+c; c=g3>>26; g3&=0x3ffffff;
    g4=h4+c-(1u<<26);
    mask=(g4>>31)-1;
    g0&=mask; g1&=mask; g2&=mask; g3&=mask; g4&=mask;
    mask=~mask;
    h0=(h0&mask)|g0; h1=(h1&mask)|g1; h2=(h2&mask)|g2; h3=(h3&mask)|g3; h4=(h4&mask)|g4;

    /* h = h % 2^128 (repack 26-bit limbs into 32-bit words) */
    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    /* mac = (h + pad) % 2^128 */
    uint64_t f;
    f = (uint64_t)h0 + st->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store32(tag+0, h0); store32(tag+4, h1); store32(tag+8, h2); store32(tag+12, h3);
}

void poly1305(uint8_t tag[16], const uint8_t* msg, size_t len, const uint8_t key[32]) {
    struct poly1305_state st;
    poly1305_init(&st, key);
    size_t i = 0;
    while (i + 16 <= len) { poly1305_blocks(&st, msg + i, 16, 1u << 24); i += 16; }
    if (i < len) {
        uint8_t buf[16];
        size_t n = len - i;
        memset(buf, 0, sizeof(buf));
        memcpy(buf, msg + i, n);
        buf[n] = 1;
        poly1305_blocks(&st, buf, 16, 0);
    }
    poly1305_finish(&st, tag);
}

/* ---- AEAD ---- */

/* Feed `data` (len bytes) to Poly1305 for the AEAD MAC. mac_data is padded to a
   multiple of 16 with zeros (pad16), so every block is a full 16-byte block and
   gets the 2^128 bit (hibit = 1<<24). */
static void poly1305_aead_feed(struct poly1305_state* st, const uint8_t* data, size_t len) {
    size_t i = 0;
    while (i + 16 <= len) { poly1305_blocks(st, data + i, 16, 1u << 24); i += 16; }
    if (i < len) {
        uint8_t buf[16];
        memset(buf, 0, sizeof(buf));
        memcpy(buf, data + i, len - i);
        poly1305_blocks(st, buf, 16, 1u << 24);
    }
}

static void aead_mac(uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* cipher, size_t len) {
    uint32_t st[16], blk[16];
    /* Poly1305 one-time key = ChaCha20 block 0 with the SAME nonce. */
    chacha20_init_state(st, key, nonce, 0);
    chacha20_block(blk, st);
    uint8_t otk[64];
    for (int i = 0; i < 16; i++) store32(otk + i*4, blk[i]);

    struct poly1305_state s;
    poly1305_init(&s, otk);
    poly1305_aead_feed(&s, aad, aad_len);
    poly1305_aead_feed(&s, cipher, len);
    /* Length block: le64(aad_len) || le64(cipher_len) in ONE 16-byte block. */
    {
        uint8_t lens[16];
        uint64_t al = (uint64_t)aad_len, cl = (uint64_t)len;
        for (int i = 0; i < 8; i++) lens[i] = (uint8_t)(al >> (8*i));
        for (int i = 0; i < 8; i++) lens[8+i] = (uint8_t)(cl >> (8*i));
        poly1305_blocks(&s, lens, 16, 1u << 24);
    }
    poly1305_finish(&s, tag);
}

void chacha20poly1305_encrypt(uint8_t* out,
                              const uint8_t* plain, size_t len,
                              const uint8_t* aad, size_t aad_len,
                              const uint8_t nonce[12],
                              const uint8_t key[32]) {
    chacha20_xor(out, plain, len, key, nonce, 1);
    aead_mac(out + len, key, nonce, aad, aad_len, out, len);
}

int chacha20poly1305_decrypt(uint8_t* out,
                             const uint8_t* cipher, size_t len,
                             const uint8_t* aad, size_t aad_len,
                             const uint8_t nonce[12],
                             const uint8_t key[32]) {
    uint8_t tag[16];
    aead_mac(tag, key, nonce, aad, aad_len, cipher, len);
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)(tag[i] ^ cipher[len + i]);
    if (diff != 0) return 0;
    chacha20_xor(out, cipher, len, key, nonce, 1);
    return 1;
}
