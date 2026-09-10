#include "rng.h"
#include "sha256.h"
#include "chacha20poly1305.h"
#include "drivers/timer/pit.h"

/* ChaCha20-keystream CSPRNG. Секрет (key) и nonce берутся из энтропии
   загрузки и пересоздаются (rekey) по мере генерации. */

static uint8_t  g_key[32];
static uint8_t  g_nonce[12];
static uint32_t g_counter;
static uint64_t g_mix;
static int      g_ready = 0;

static uint64_t rdtsc(void) {
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static void rng_reseed_locked(void) {
    uint64_t seed[4];
    seed[0] = rdtsc();
    seed[1] = (uint64_t)timer_ms();
    seed[2] = (uint64_t)timer_jiffies();
    seed[3] = g_mix;
    uint8_t digest[32];
    sha256(seed, sizeof(seed), digest);
    for (int i = 0; i < 32; i++) g_key[i] = digest[i];
    for (int i = 0; i < 12; i++) g_nonce[i] = digest[31 - i];
    g_counter = 0;
}

void rng_init(void) {
    if (g_ready) return;
    g_mix = 0x9E3779B97F4A7C15ULL;
    rng_reseed_locked();
    g_ready = 1;
}

void rng_bytes(void* out, size_t n) {
    rng_init();
    uint8_t* p = (uint8_t*)out;
    static const uint8_t zeros[64] = {0};
    while (n > 0) {
        uint8_t block[64];
        chacha20_xor(block, zeros, sizeof(block), g_key, g_nonce, g_counter++);
        size_t c = n < sizeof(block) ? n : sizeof(block);
        for (size_t i = 0; i < c; i++) p[i] = block[i];
        p += c;
        n -= c;
        g_mix += 0x9E3779B97F4A7C15ULL;
        /* Пересоздаём ключ каждые 64 блока, чтобы не выдать keystream. */
        if ((g_counter & 0x3F) == 0) rng_reseed_locked();
    }
}

uint32_t rng_u32(void) {
    uint32_t v;
    rng_bytes(&v, sizeof(v));
    return v;
}
