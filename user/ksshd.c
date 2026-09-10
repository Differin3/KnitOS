// M5: user-space secure shell server (custom "kssh" protocol).
//
// Handshake (server side):
//   C -> S : 32-byte X25519 client public key
//   S -> C : 32-byte X25519 server public key || 12-byte salt
//   shared  = X25519(server_priv, client_pub)
//   key     = SHA256("kssh1" || shared || client_pub || server_pub)
//
// Transport: each direction is a sequence of frames
//   [u32 plaintext_len][ciphertext(plaintext_len) || tag(16)]
//   nonce = 12-byte little-endian per-direction frame counter (0,1,2,...)
//   AEAD = ChaCha20-Poly1305, AAD empty.
//
// The server runs a PTY-backed shell and relays it over the secure channel.
#include "lib/libk.h"

#define KSSH_PORT 2222

static unsigned char g_key[32];
static const unsigned char X25519_BASE[32] = {9};

static void make_nonce(unsigned char nonce[12], uint64_t counter) {
    for (int i = 0; i < 8; i++) nonce[i] = (unsigned char)(counter >> (8 * i));
    nonce[8] = nonce[9] = nonce[10] = nonce[11] = 0;
}

static int send_all(int fd, const void* buf, int n) {
    const unsigned char* p = (const unsigned char*)buf;
    int sent = 0;
    while (sent < n) {
        long r = sys_send(fd, p + sent, (unsigned long)(n - sent));
        if (r <= 0) return -1;
        sent += (int)r;
    }
    return 0;
}

static int recv_all(int fd, void* buf, int n) {
    unsigned char* p = (unsigned char*)buf;
    int got = 0;
    while (got < n) {
        long r = sys_recv(fd, p + got, (unsigned long)(n - got), 60000);
        if (r <= 0) return -1;
        got += (int)r;
    }
    return got;
}

static int send_frame(int fd, uint64_t* counter, const void* data, int len) {
    unsigned char nonce[12];
    make_nonce(nonce, (*counter)++);
    static unsigned char ct[4096 + 16];
    int n = kc_aead_encrypt(g_key, nonce, 0, 0, data, (size_t)len, ct);
    if (n < 0) return -1;
    unsigned char hdr[4];
    hdr[0] = (unsigned char)(len);
    hdr[1] = (unsigned char)(len >> 8);
    hdr[2] = (unsigned char)(len >> 16);
    hdr[3] = (unsigned char)(len >> 24);
    if (send_all(fd, hdr, 4) < 0) return -1;
    if (send_all(fd, ct, n) < 0) return -1;
    return 0;
}

static int recv_frame(int fd, uint64_t* counter, void* out, int cap) {
    unsigned char hdr[4];
    if (recv_all(fd, hdr, 4) < 0) return -1;
    int len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16) | (hdr[3] << 24);
    if (len < 0 || len > cap || len > 4096) return -1;
    static unsigned char ct[4096 + 16];
    if (recv_all(fd, ct, len + 16) < 0) return -1;
    unsigned char nonce[12];
    make_nonce(nonce, (*counter)++);
    return kc_aead_decrypt(g_key, nonce, 0, 0, ct, (size_t)(len + 16), (unsigned char*)out);
}

static int handshake(int c) {
    unsigned char cpub[32], spriv[32], spub[32], salt[12], shared[32];
    if (recv_all(c, cpub, 32) != 32) return -1;
    kc_random(spriv, 32);
    spriv[0] &= 248;
    spriv[31] &= 127;
    spriv[31] |= 64;
    kc_x25519(spriv, X25519_BASE, spub);
    kc_random(salt, 12);
    if (send_all(c, spub, 32) < 0) return -1;
    if (send_all(c, salt, 12) < 0) return -1;
    kc_x25519(spriv, cpub, shared);

    unsigned char buf[5 + 32 + 32 + 32];
    memcpy(buf, "kssh1", 5);
    memcpy(buf + 5, shared, 32);
    memcpy(buf + 37, cpub, 32);
    memcpy(buf + 69, spub, 32);
    if (kc_sha256(buf, sizeof(buf), g_key) < 0) return -1;
    return 0;
}

static void serve(int c) {
    if (handshake(c) < 0) {
        printf("ksshd: handshake failed\n");
        sys_sock_close(c);
        return;
    }
    printf("ksshd: session established\n");

    int pfd[2];
    if (sys_pty_open(pfd) < 0) { sys_sock_close(c); return; }
    int master = pfd[0];
    int slave = pfd[1];

    long sh = sys_fork();
    if (sh == 0) {
        sys_dup2(slave, 0);
        sys_dup2(slave, 1);
        sys_dup2(slave, 2);
        if (slave > 2) sys_close(slave);
        if (master > 2) sys_close(master);
        char* av[2];
        av[0] = (char*)"/tmp/sh.elf";
        av[1] = 0;
        sys_execve("/tmp/sh.elf", av, 0);
        sys_exit(127);
    }
    if (slave > 2) sys_close(slave);

    long relay = sys_fork();
    if (relay == 0) {
        /* master -> socket (зашифровано) */
        uint64_t sc = 0;
        for (;;) {
            char buf[1024];
            long n = sys_read(master, buf, sizeof(buf));
            if (n <= 0) break;
            if (send_frame(c, &sc, buf, (int)n) < 0) break;
        }
        sys_exit(0);
    }

    /* socket -> master (расшифровка) */
    uint64_t cs = 0;
    for (;;) {
        static char buf[4096];
        int n = recv_frame(c, &cs, buf, sizeof(buf));
        if (n < 0) break;
        if (n == 0) continue;
        if (sys_write(master, buf, (unsigned long)n) < 0) break;
    }

    sys_sock_close(c);
    sys_kill((int)relay, 0);
    sys_kill((int)sh, 0);
    int st;
    sys_waitpid((int)relay, &st);
    sys_waitpid((int)sh, &st);
    sys_close(master);
    printf("ksshd: session closed\n");
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    int lfd = (int)sys_socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { printf("ksshd: socket failed\n"); return 1; }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = KSSH_PORT;
    addr.sin_addr = 0;
    if (sys_bind(lfd, &addr) < 0) { printf("ksshd: bind failed\n"); return 1; }
    if (sys_listen(lfd, 4) < 0) { printf("ksshd: listen failed\n"); return 1; }
    printf("ksshd: listening on port %d\n", KSSH_PORT);
    for (;;) {
        int c = (int)sys_accept(lfd, 10000);
        if (c < 0) continue;
        serve(c);
    }
    return 0;
}
