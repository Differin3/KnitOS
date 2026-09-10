// Known-answer tests for the crypto primitives (run from the `cryptotest` shell command).
#include "sha256.h"
#include "chacha20poly1305.h"
#include "x25519.h"
#include "ed25519.h"
#include "drivers/video/terminal.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t hex2bin(const char* hex, uint8_t* out, size_t cap) {
    size_t n = 0;
    while (hex[0] && hex[1] && n < cap) {
        int hi = hexval(hex[0]), lo = hexval(hex[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}
static void print_hex(const uint8_t* b, size_t n) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        char s[3] = { hx[b[i] >> 4], hx[b[i] & 0xF], 0 };
        terminal_writestring(s);
    }
}
static int eq_hex(const uint8_t* got, size_t n, const char* want_hex) {
    uint8_t want[64];
    size_t wn = hex2bin(want_hex, want, sizeof(want));
    if (wn != n) return 0;
    for (size_t i = 0; i < n; i++) if (got[i] != want[i]) return 0;
    return 1;
}
static void report(const char* name, int ok, const uint8_t* got, size_t n) {
    terminal_writestring("\n  ");
    terminal_writestring(name);
    terminal_writestring(": ");
    terminal_writestring(ok ? "PASS" : "FAIL");
    if (!ok) { terminal_writestring("  got="); print_hex(got, n); }
}

int crypto_selftest_run(void) {
    int fails = 0;
    uint8_t out[64];

    /* SHA-256("abc") */
    sha256("abc", 3, out);
    int ok1 = eq_hex(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    report("SHA-256(abc)", ok1, out, 32); fails += !ok1;

    /* SHA-256("") */
    sha256("", 0, out);
    int ok2 = eq_hex(out, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    report("SHA-256(\"\")", ok2, out, 32); fails += !ok2;

    /* HMAC-SHA256(key="key", msg="The quick brown fox jumps over the lazy dog") */
    const char* msg = "The quick brown fox jumps over the lazy dog";
    hmac_sha256("key", 3, msg, strlen(msg), out);
    int ok3 = eq_hex(out, 32, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    report("HMAC-SHA256", ok3, out, 32); fails += !ok3;

    /* Poly1305 standalone (RFC 8439 §2.5.2) */
    {
        uint8_t key[32], tag[16];
        hex2bin("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", key, 32);
        const char* m = "Cryptographic Forum Research Group";
        poly1305(tag, (const uint8_t*)m, strlen(m), key);
        int ok = eq_hex(tag, 16, "a8061dc1305136c6c22b8baf0c0127a9");
        report("Poly1305 RFC8439", ok, tag, 16); fails += !ok;
    }

    /* ChaCha20-Poly1305 AEAD (RFC 8439 §2.8.2) */
    {
        uint8_t key[32], nonce[12], aad[12];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
        hex2bin("070000004041424344454647", nonce, 12);
        hex2bin("50515253c0c1c2c3c4c5c6c7", aad, 12);
        const char* pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        size_t plen = strlen(pt);
        uint8_t ct[128 + 16];
        chacha20poly1305_encrypt(ct, (const uint8_t*)pt, plen, aad, 12, nonce, key);
        int ct_ok = (ct[0] == 0xd3 && ct[1] == 0x1a && ct[2] == 0x8d && ct[3] == 0x34 &&
                     ct[4] == 0x64 && ct[5] == 0x8e && ct[6] == 0x60 && ct[7] == 0xdb);
        report("ChaCha20-Poly1305 ct", ct_ok, ct, 16);
        fails += !ct_ok;
        int tag_ok = eq_hex(ct + plen, 16, "1ae10b594f09e26a7e902ecbd0600691");
        report("ChaCha20-Poly1305 tag", tag_ok, ct + plen, 16);
        fails += !tag_ok;
        uint8_t dec[128];
        int rt = chacha20poly1305_decrypt(dec, ct, plen, aad, 12, nonce, key);
        int dec_ok = rt && memcmp(dec, pt, plen) == 0;
        report("ChaCha20-Poly1305 rt", dec_ok, dec, 16);
        fails += !dec_ok;
    }

    /* X25519 (RFC 7748 §5.2) */
    {
        uint8_t scalar[32], point[32], res[32];
        hex2bin("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar, 32);
        hex2bin("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", point, 32);
        x25519(res, scalar, point);
        int ok = eq_hex(res, 32, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        report("X25519 RFC7748", ok, res, 32); fails += !ok;
    }

    /* X25519 shared-secret agreement (both sides equal) */
    {
        uint8_t apriv[32], apub[32], bpriv[32], bpub[32], s1[32], s2[32];
        for (int i = 0; i < 32; i++) { apriv[i] = (uint8_t)(i + 1); bpriv[i] = (uint8_t)(0x40 + i); }
        x25519_public_key(apub, apriv);
        x25519_public_key(bpub, bpriv);
        x25519(s1, apriv, bpub);
        x25519(s2, bpriv, apub);
        int ok = memcmp(s1, s2, 32) == 0;
        report("X25519 ECDH shared", ok, s1, 32); fails += !ok;
    }

    /* Ed25519 (RFC 8032 §7.1 TEST 1, empty message) */
    {
        uint8_t seed[32], pk[32], sk[64], sig[64];
        hex2bin("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
        ed25519_keypair_from_seed(pk, sk, seed);
        int okpk = eq_hex(pk, 32, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        report("Ed25519 pubkey RFC8032", okpk, pk, 32); fails += !okpk;

        ed25519_sign(sig, "", 0, sk);
        int oksig = eq_hex(sig, 64,
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        report("Ed25519 sign RFC8032", oksig, sig, 64); fails += !oksig;

        int okv = ed25519_verify(sig, "", 0, pk);
        report("Ed25519 verify", okv, sig, 64); fails += !okv;
    }

    /* Ed25519 (RFC 8032 §7.1 TEST 2, one-byte message 0x72) */
    {
        uint8_t seed[32], pk[32], sk[64], sig[64];
        hex2bin("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", seed, 32);
        ed25519_keypair_from_seed(pk, sk, seed);
        int okpk = eq_hex(pk, 32, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        report("Ed25519 pubkey RFC8032-2", okpk, pk, 32); fails += !okpk;
        uint8_t m = 0x72;
        ed25519_sign(sig, &m, 1, sk);
        int oksig = eq_hex(sig, 64,
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        report("Ed25519 sign RFC8032-2", oksig, sig, 64); fails += !oksig;
        int okv = ed25519_verify(sig, &m, 1, pk);
        report("Ed25519 verify-2", okv, sig, 64); fails += !okv;
        m = 0x73; /* corrupted message must fail */
        int okbad = !ed25519_verify(sig, &m, 1, pk);
        report("Ed25519 reject bad", okbad, sig, 64); fails += !okbad;
    }

    return fails;
}
