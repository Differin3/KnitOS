// Ed25519 signatures (RFC 8032) + SHA-512.
// Derived from TweetNaCl (public domain), using the same 16-limb field
// representation as the existing x25519.cpp.
#include "ed25519.h"
#include <string.h>

typedef long long i64;
typedef i64 gf[16];

/* ---------------- SHA-512 ---------------- */

struct sha512_ctx {
    uint64_t state[8];
    uint64_t bitlen;
    uint8_t data[128];
    size_t datalen;
};

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void sha512_transform(struct sha512_ctx* c, const uint8_t* block) {
    uint64_t w[80], a, b, cc, d, e, f, g, h, t1, t2;
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint64_t)block[i * 8] << 56) | ((uint64_t)block[i * 8 + 1] << 48) |
               ((uint64_t)block[i * 8 + 2] << 40) | ((uint64_t)block[i * 8 + 3] << 32) |
               ((uint64_t)block[i * 8 + 4] << 24) | ((uint64_t)block[i * 8 + 5] << 16) |
               ((uint64_t)block[i * 8 + 6] << 8) | (uint64_t)block[i * 8 + 7];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROTR64(w[i - 15], 1) ^ ROTR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROTR64(w[i - 2], 19) ^ ROTR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K512[i] + w[i];
        uint64_t S0 = ROTR64(a, 28) ^ ROTR64(a, 34) ^ ROTR64(a, 39);
        uint64_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void sha512_init(struct sha512_ctx* c) {
    c->state[0] = 0x6a09e667f3bcc908ULL; c->state[1] = 0xbb67ae8584caa73bULL;
    c->state[2] = 0x3c6ef372fe94f82bULL; c->state[3] = 0xa54ff53a5f1d36f1ULL;
    c->state[4] = 0x510e527fade682d1ULL; c->state[5] = 0x9b05688c2b3e6c1fULL;
    c->state[6] = 0x1f83d9abfb41bd6bULL; c->state[7] = 0x5be0cd19137e2179ULL;
    c->bitlen = 0;
    c->datalen = 0;
}

static void sha512_update(struct sha512_ctx* c, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    c->bitlen += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 128 - c->datalen;
        if (take > len) take = len;
        memcpy(c->data + c->datalen, p, take);
        c->datalen += take;
        p += take;
        len -= take;
        if (c->datalen == 128) {
            sha512_transform(c, c->data);
            c->datalen = 0;
        }
    }
}

static void sha512_final(struct sha512_ctx* c, uint8_t out[64]) {
    uint64_t bitlen = c->bitlen;
    uint8_t pad = 0x80;
    sha512_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->datalen != 112) sha512_update(c, &zero, 1);
    uint8_t lenbuf[16];
    for (int i = 0; i < 8; i++) lenbuf[i] = 0;
    for (int i = 0; i < 8; i++) lenbuf[15 - i] = (uint8_t)(bitlen >> (8 * i));
    /* sha512_update() would add to bitlen; write the length block directly. */
    memcpy(c->data + c->datalen, lenbuf, 16);
    sha512_transform(c, c->data);
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (uint8_t)(c->state[i] >> (56 - 8 * j));
    }
}

static void sha512(const void* data, size_t len, uint8_t out[64]) {
    struct sha512_ctx c;
    sha512_init(&c);
    sha512_update(&c, data, len);
    sha512_final(&c, out);
}

/* ---------------- field arithmetic (as in x25519.cpp) ---------------- */

static const gf gf0 = {0};
static const gf gf1 = {1};
static const gf _121665 = {0xDB41, 1};
static const gf D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
                     0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
static const gf D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                      0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
static const gf X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                     0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
static const gf Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                     0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
static const gf I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
                     0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static void car25519(gf o) {
    int i;
    i64 c;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}
static void sel25519(gf p, gf q, int b) {
    i64 t, i, c = ~(b - 1);
    for (i = 0; i < 16; i++) { t = c & (p[i] ^ q[i]); p[i] ^= t; q[i] ^= t; }
}
static void pack25519(uint8_t* o, const gf n) {
    int i, j, b;
    gf m, t;
    for (i = 0; i < 16; i++) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) { o[2 * i] = (uint8_t)(t[i] & 0xff); o[2 * i + 1] = (uint8_t)(t[i] >> 8); }
}
static void unpack25519(gf o, const uint8_t* n) {
    int i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}
static void A(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void Z(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }
static void M(gf o, const gf a, const gf b) {
    i64 i, j, t[31];
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++) for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o); car25519(o);
}
static void S(gf o, const gf a) { M(o, a, a); }
static void inv25519(gf o, const gf i) {
    gf c;
    int a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) { S(c, c); if (a != 2 && a != 4) M(c, c, i); }
    for (a = 0; a < 16; a++) o[a] = c[a];
}
static void pow2523(gf o, const gf i) {
    gf c;
    int a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 250; a >= 0; a--) { S(c, c); if (a != 1) M(c, c, i); }
    for (a = 0; a < 16; a++) o[a] = c[a];
}

/* ---------------- Edwards group ---------------- */

static void set25519(gf r, const gf a) { for (int i = 0; i < 16; i++) r[i] = a[i]; }

static void add(gf p[4], gf q[4]) {
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]); Z(t, q[1], q[0]); M(a, a, t);
    A(b, p[0], p[1]); A(t, q[0], q[1]); M(b, b, t);
    M(c, p[3], q[3]); M(c, c, D2);
    M(d, p[2], q[2]); A(d, d, d);
    Z(e, b, a); Z(f, d, c); A(g, d, c); A(h, b, a);
    M(p[0], e, f); M(p[1], h, g); M(p[2], g, f); M(p[3], e, h);
}
static void cswap(gf p[4], gf q[4], uint8_t b) {
    for (int i = 0; i < 4; i++) sel25519(p[i], q[i], b);
}
static int par25519(const gf a) { uint8_t d[32]; pack25519(d, a); return d[0] & 1; }
static void pack(uint8_t* r, gf p[4]) {
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= (uint8_t)(par25519(tx) << 7);
}
static void scalarmult(gf p[4], gf q[4], const uint8_t* s) {
    int i;
    set25519(p[0], gf0); set25519(p[1], gf1); set25519(p[2], gf1); set25519(p[3], gf0);
    for (i = 255; i >= 0; --i) {
        uint8_t b = (uint8_t)((s[i / 8] >> (i & 7)) & 1);
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}
static void scalarbase(gf p[4], const uint8_t* s) {
    gf q[4];
    set25519(q[0], X); set25519(q[1], Y); set25519(q[2], gf1); M(q[3], X, Y);
    scalarmult(p, q, s);
}

static const uint64_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
};

static void modL(uint8_t* r, i64 x[64]) {
    i64 carry, i, j;
    for (i = 63; i >= 32; --i) {
        carry = 0;
        for (j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * (i64)L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * (i64)L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; j++) x[j] -= carry * (i64)L[j];
    for (i = 0; i < 32; i++) { x[i + 1] += x[i] >> 8; r[i] = (uint8_t)(x[i] & 255); }
}

static void reduce(uint8_t* r) {
    i64 x[64];
    int i;
    for (i = 0; i < 64; i++) x[i] = (uint64_t)r[i];
    for (i = 0; i < 64; i++) r[i] = 0;
    modL(r, x);
}

static int vn(const uint8_t* x, const uint8_t* y, int n) {
    unsigned int i;
    unsigned char d = 0;
    for (i = 0; i < (unsigned)n; i++) d |= x[i] ^ y[i];
    return (1 & ((d - 1) >> 8)) - 1;
}
static int neq25519(const gf a, const gf b) {
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    return vn(c, d, 32);
}

static int unpackneg(gf r[4], const uint8_t p[32]) {
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);

    M(r[3], r[0], r[1]);
    return 0;
}

/* ---------------- public API ---------------- */

void ed25519_keypair_from_seed(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]) {
    uint8_t d[64];
    gf p[4];
    for (int i = 0; i < 32; i++) sk[i] = seed[i];
    sha512(sk, 32, d);
    d[0] &= 248; d[31] &= 127; d[31] |= 64;
    scalarbase(p, d);
    pack(pk, p);
    for (int i = 0; i < 32; i++) sk[i + 32] = pk[i];
}

void ed25519_public_key(uint8_t pk[32], const uint8_t sk[64]) {
    for (int i = 0; i < 32; i++) pk[i] = sk[32 + i];
}

void ed25519_sign(uint8_t* sig, const void* msg, size_t len, const uint8_t sk[64]) {
    uint8_t d[64], h[64], r[64];
    i64 i, j, x[64];
    gf p[4];
    const uint8_t* m = (const uint8_t*)msg;

    sha512(sk, 32, d);
    d[0] &= 248; d[31] &= 127; d[31] |= 64;

    static uint8_t sm[4096];
    if (len > sizeof(sm) - 64) return;
    for (i = 0; i < (i64)len; i++) sm[64 + i] = m[i];
    for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i];

    sha512(sm + 32, len + 32, r);
    reduce(r);
    scalarbase(p, r);
    pack(sm, p);
    for (i = 0; i < 32; i++) sig[i] = sm[i];

    for (i = 0; i < 32; i++) sm[i + 32] = sk[32 + i];
    sha512(sm, len + 64, h);
    reduce(h);

    for (i = 0; i < 64; i++) x[i] = 0;
    for (i = 0; i < 32; i++) x[i] = (uint64_t)r[i];
    for (i = 0; i < 32; i++)
        for (j = 0; j < 32; j++) x[i + j] += h[i] * (uint64_t)d[j];
    modL(sig + 32, x);
}

int ed25519_verify(const uint8_t* sig, const void* msg, size_t len, const uint8_t pk[32]) {
    i64 i;
    uint8_t t[32], h[64];
    gf p[4], q[4];
    const uint8_t* m = (const uint8_t*)msg;

    if (unpackneg(q, pk)) return 0;

    static uint8_t buf[4096];
    if (len + 64 > sizeof(buf)) return 0;
    for (i = 0; i < 32; i++) buf[i] = sig[i];        /* R */
    for (i = 0; i < 32; i++) buf[32 + i] = pk[i];    /* public key */
    for (i = 0; i < (i64)len; i++) buf[64 + i] = m[i];
    sha512(buf, len + 64, h);
    reduce(h);
    scalarmult(p, q, h);

    scalarbase(q, sig + 32);
    add(p, q);
    pack(t, p);

    if (vn(sig, t, 32)) return 0;
    return 1;
}
