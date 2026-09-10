// M6: SSHv2 server (RFC 4253 transport, 4252 userauth, 4254 connection).
//
// Algorithms: kex=curve25519-sha256, hostkey=ssh-ed25519,
//             cipher=chacha20-poly1305@openssh.com, compression=none.
//
// Auth: "none" is accepted for any user. Runs a PTY-backed shell.
#include "lib/libk.h"

#define SSH_PORT 2222
#define SSHV     "SSH-2.0-KnitOS_1.0"

#define MSG_DISCONNECT      1
#define MSG_IGNORE          2
#define MSG_UNIMPLEMENTED   3
#define MSG_DEBUG           4
#define MSG_SERVICE_REQUEST 5
#define MSG_SERVICE_ACCEPT  6
#define MSG_KEXINIT         20
#define MSG_NEWKEYS         21
#define MSG_KEX_ECDH_INIT   30
#define MSG_KEX_ECDH_REPLY  31
#define MSG_USERAUTH_REQUEST 50
#define MSG_USERAUTH_FAILURE 51
#define MSG_USERAUTH_SUCCESS 52
#define MSG_GLOBAL_REQUEST  80
#define MSG_REQUEST_FAILURE 82
#define MSG_CHANNEL_OPEN    90
#define MSG_CHANNEL_OPEN_CONFIRMATION 91
#define MSG_CHANNEL_OPEN_FAILURE 92
#define MSG_CHANNEL_WINDOW_ADJUST 93
#define MSG_CHANNEL_DATA    94
#define MSG_CHANNEL_EOF     96
#define MSG_CHANNEL_CLOSE   97
#define MSG_CHANNEL_REQUEST 98
#define MSG_CHANNEL_SUCCESS 99
#define MSG_CHANNEL_FAILURE 100

/* ---------------- byte buffer ---------------- */
struct buf { uint8_t* p; uint32_t len; uint32_t cap; };
static void bw_u8(struct buf* b, uint8_t v) { if (b->len < b->cap) b->p[b->len++] = v; }
static void bw_u32(struct buf* b, uint32_t v) {
    bw_u8(b, (uint8_t)(v >> 24)); bw_u8(b, (uint8_t)(v >> 16));
    bw_u8(b, (uint8_t)(v >> 8));  bw_u8(b, (uint8_t)v);
}
static void bw_raw(struct buf* b, const void* d, uint32_t n) {
    if (b->len + n > b->cap) n = b->cap - b->len;
    memcpy(b->p + b->len, d, n); b->len += n;
}
static void bw_str(struct buf* b, const void* d, uint32_t n) { bw_u32(b, n); bw_raw(b, d, n); }
static void bw_mpint(struct buf* b, const uint8_t* d, uint32_t n) {
    uint32_t i = 0;
    while (i < n && d[i] == 0) i++;
    uint32_t m = n - i;
    if (m == 0) { bw_u32(b, 0); return; }
    int pad = (d[i] & 0x80) ? 1 : 0;
    bw_u32(b, m + (uint32_t)pad);
    if (pad) bw_u8(b, 0);
    bw_raw(b, d + i, m);
}

struct br { const uint8_t* p; uint32_t len; uint32_t pos; };
static uint8_t br_u8(struct br* r) { return r->pos < r->len ? r->p[r->pos++] : 0; }
static uint32_t br_u32(struct br* r) { uint32_t v = 0; for (int i = 0; i < 4; i++) v = (v << 8) | br_u8(r); return v; }
static const uint8_t* br_raw(struct br* r, uint32_t n) {
    if (r->pos + n > r->len) { r->pos = r->len; return r->p + r->len; }
    const uint8_t* d = r->p + r->pos; r->pos += n; return d;
}
static void br_skip_str(struct br* r) { uint32_t n = br_u32(r); br_raw(r, n); }

/* ---------------- SHA-256 accumulator ---------------- */
struct shactx { uint8_t buf[2048]; uint32_t len; };
static void sha_init(struct shactx* s) { s->len = 0; }
static void sha_add(struct shactx* s, const void* d, uint32_t n) {
    if (s->len + n > sizeof(s->buf)) n = sizeof(s->buf) - s->len;
    memcpy(s->buf + s->len, d, n); s->len += n;
}
static void sha_add_mpint(struct shactx* s, const uint8_t* d, uint32_t n) {
    uint8_t tmp[300]; struct buf b; b.p = tmp; b.len = 0; b.cap = sizeof(tmp);
    bw_mpint(&b, d, n);
    sha_add(s, tmp, b.len);
}
static void sha_add_str(struct shactx* s, const uint8_t* d, uint32_t n) {
    uint8_t hdr[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n };
    sha_add(s, hdr, 4);
    sha_add(s, d, n);
}
static void sha_final(struct shactx* s, uint8_t out[32]) { kc_sha256(s->buf, s->len, out); }

/* ---------------- socket I/O ---------------- */
static int send_all(int fd, const void* buf, int n) {
    const uint8_t* p = (const uint8_t*)buf;
    int sent = 0;
    while (sent < n) {
        long r = sys_send(fd, p + sent, (unsigned long)(n - sent));
        if (r <= 0) return -1;
        sent += (int)r;
    }
    return 0;
}
static int recv_all(int fd, void* buf, int n) {
    uint8_t* p = (uint8_t*)buf;
    int got = 0;
    while (got < n) {
        long r = sys_recv(fd, p + got, (unsigned long)(n - got), 60000);
        if (r <= 0) return -1;
        got += (int)r;
    }
    return got;
}

/* ---------------- connection state ---------------- */
static int g_fd;
static uint32_t g_seq_in, g_seq_out;
static int g_encrypted;
static uint8_t g_key_c2s[64], g_key_s2c[64];
static uint32_t g_chan; /* client channel id */
static uint32_t g_maxpkt = 32768;
static uint8_t g_pending[2048];
static uint32_t g_pending_len;
static int g_has_pending;
static char g_user[64];
static uint16_t g_shell_uid;

/* chacha20-poly1305@openssh.com */
/* OpenSSH chacha uses a 64-bit counter + 64-bit nonce; mapped onto the
   RFC 8439 layout this means the 96-bit nonce is 00000000 || seq_be64. */
static void ossh_nonce(uint8_t nonce[12], uint32_t seq) {
    for (int i = 0; i < 12; i++) nonce[i] = 0;
    nonce[8]  = (uint8_t)(seq >> 24);
    nonce[9]  = (uint8_t)(seq >> 16);
    nonce[10] = (uint8_t)(seq >> 8);
    nonce[11] = (uint8_t)(seq);
}

static void ossh_encrypt(uint8_t* out, const uint8_t* payload, uint32_t plen,
                         const uint8_t* key, uint32_t seq) {
    const uint8_t* k_len = key + 32;  /* header key: packet length */
    const uint8_t* k_pl = key;        /* main key: payload AEAD */
    uint8_t zero[64] = {0};
    uint8_t nonce[12];
    ossh_nonce(nonce, seq);
    uint8_t lenb[4] = { (uint8_t)(plen >> 24), (uint8_t)(plen >> 16),
                        (uint8_t)(plen >> 8), (uint8_t)plen };
    uint8_t enc_len[4];
    kc_chacha20(enc_len, lenb, 4, k_len, nonce, 0);
    uint8_t polykey[64];
    kc_chacha20(polykey, zero, 64, k_pl, nonce, 0);
    uint8_t enc_pl[2048];
    kc_chacha20(enc_pl, payload, plen, k_pl, nonce, 1);
    static uint8_t macbuf[2052];
    memcpy(macbuf, enc_len, 4);
    memcpy(macbuf + 4, enc_pl, plen);
    uint8_t tag[16];
    kc_poly1305(tag, macbuf, 4 + plen, polykey);
    memcpy(out, enc_len, 4);
    memcpy(out + 4, enc_pl, plen);
    memcpy(out + 4 + plen, tag, 16);
}

static int ossh_decrypt(uint8_t* out, const uint8_t* enclen, const uint8_t* in,
                        uint32_t plen, const uint8_t* key, uint32_t seq) {
    const uint8_t* k_pl = key;
    uint8_t zero[64] = {0};
    uint8_t nonce[12];
    ossh_nonce(nonce, seq);
    uint8_t polykey[64];
    kc_chacha20(polykey, zero, 64, k_pl, nonce, 0);
    static uint8_t macbuf[2052];
    memcpy(macbuf, enclen, 4);
    memcpy(macbuf + 4, in, plen);
    uint8_t tag[16];
    kc_poly1305(tag, macbuf, 4 + plen, polykey);
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= tag[i] ^ in[plen + i];
    if (diff != 0) return -1;
    kc_chacha20(out, in, plen, k_pl, nonce, 1);
    return 0;
}

static int ssh_send(const uint8_t* payload, uint32_t plen) {
    uint8_t pkt[2100];
    uint32_t pad;
    if (!g_encrypted) {
        /* cleartext: (4 + packet_length) % 8 == 0 */
        pad = 8 - ((plen + 5) % 8);
    } else {
        /* chacha20-poly1305: the encrypted part is packet_length bytes,
           so OpenSSH requires packet_length % 8 == 0. */
        pad = 8 - ((plen + 1) % 8);
    }
    if (pad < 4) pad += 8;
    uint32_t packet_len = 1 + plen + pad;
    static uint8_t body[2048];
    body[0] = (uint8_t)pad;
    memcpy(body + 1, payload, plen);
    uint8_t rnd[256];
    kc_random(rnd, pad);
    memcpy(body + 1 + plen, rnd, pad);
    if (!g_encrypted) {
        uint8_t hdr[4] = { (uint8_t)(packet_len >> 24), (uint8_t)(packet_len >> 16),
                           (uint8_t)(packet_len >> 8), (uint8_t)packet_len };
        memcpy(pkt, hdr, 4);
        memcpy(pkt + 4, body, packet_len);
        if (send_all(g_fd, pkt, 4 + (int)packet_len) < 0) return -1;
    } else {
        ossh_encrypt(pkt, body, packet_len, g_key_s2c, g_seq_out);
        if (send_all(g_fd, pkt, 4 + (int)packet_len + 16) < 0) return -1;
    }
    g_seq_out++;
    return 0;
}

static int ssh_recv(uint8_t* out, uint32_t* outlen) {
    uint8_t lenbuf[4];
    if (recv_all(g_fd, lenbuf, 4) < 0) return -1;
    uint32_t packet_len;
    if (!g_encrypted) {
        packet_len = ((uint32_t)lenbuf[0] << 24) | ((uint32_t)lenbuf[1] << 16) |
                     ((uint32_t)lenbuf[2] << 8) | lenbuf[3];
    } else {
        uint8_t dec[4], nonce[12];
        ossh_nonce(nonce, g_seq_in);
        kc_chacha20(dec, lenbuf, 4, g_key_c2s + 32, nonce, 0);
        packet_len = ((uint32_t)dec[0] << 24) | ((uint32_t)dec[1] << 16) |
                     ((uint32_t)dec[2] << 8) | dec[3];
    }
    if (packet_len < 5 || packet_len > 2000) return -1;
    static uint8_t body[2048];
    if (recv_all(g_fd, body, (int)(packet_len + (g_encrypted ? 16 : 0))) < 0) return -1;
    uint8_t plain[2048];
    if (!g_encrypted) memcpy(plain, body, packet_len);
    else if (ossh_decrypt(plain, lenbuf, body, packet_len, g_key_c2s, g_seq_in) < 0) return -1;
    g_seq_in++;
    uint8_t pad = plain[0];
    if ((uint32_t)pad + 1 > packet_len) return -1;
    uint32_t paylen = packet_len - 1 - pad;
    memcpy(out, plain + 1, paylen);
    *outlen = paylen;
    return 0;
}

/* ---------------- KEX ---------------- */
static uint8_t g_host_pk[32], g_host_sk[64];
static uint8_t g_sid[32];
static uint8_t g_k[32];
static uint8_t g_ic[2048], g_is[2048];
static uint32_t g_ic_len, g_is_len;
static char g_vc[64], g_vs[64];

static void build_kexinit(uint8_t* out, uint32_t* outlen) {
    static const char kex[] = "curve25519-sha256";
    static const char hk[] = "ssh-ed25519";
    static const char enc[] = "chacha20-poly1305@openssh.com";
    static const char mac[] = "hmac-sha2-256";
    static const char comp[] = "none";
    struct buf b; b.p = out; b.len = 0; b.cap = 1024;
    bw_u8(&b, MSG_KEXINIT);
    uint8_t cookie[16]; kc_random(cookie, 16);
    bw_raw(&b, cookie, 16);
    bw_str(&b, kex, (uint32_t)strlen(kex));
    bw_str(&b, hk, (uint32_t)strlen(hk));
    bw_str(&b, enc, (uint32_t)strlen(enc)); bw_str(&b, enc, (uint32_t)strlen(enc));
    bw_str(&b, mac, (uint32_t)strlen(mac)); bw_str(&b, mac, (uint32_t)strlen(mac));
    bw_str(&b, comp, (uint32_t)strlen(comp)); bw_str(&b, comp, (uint32_t)strlen(comp));
    bw_str(&b, "", 0);   bw_str(&b, "", 0);
    bw_u8(&b, 0); bw_u32(&b, 0);
    *outlen = b.len;
    printf("sshd: kexinit len=%d\n", (int)*outlen);
}

static void derive_key(uint8_t out[64], const uint8_t* H, char letter) {
    uint8_t k1[32];
    struct shactx s; sha_init(&s);
    sha_add_mpint(&s, g_k, 32);
    sha_add(&s, H, 32);
    sha_add(&s, &letter, 1);
    sha_add(&s, g_sid, 32);
    sha_final(&s, k1);
    struct shactx s2; sha_init(&s2);
    sha_add_mpint(&s2, g_k, 32);
    sha_add(&s2, H, 32);
    sha_add(&s2, k1, 32);
    sha_final(&s2, out + 32);
    memcpy(out, k1, 32);
}

static int do_kex(void) {
    static uint8_t pkt[2048];
    uint32_t plen;
    if (ssh_recv(pkt, &plen) < 0 || pkt[0] != MSG_KEXINIT) return -1;
    memcpy(g_ic, pkt, plen); g_ic_len = plen;

    uint8_t myk[1024]; uint32_t myklen;
    build_kexinit(myk, &myklen);
    memcpy(g_is, myk, myklen); g_is_len = myklen;
    if (ssh_send(myk, myklen) < 0) return -1;

    if (ssh_recv(pkt, &plen) < 0) return -1;
    struct br r; r.p = pkt; r.len = plen; r.pos = 0;
    if (br_u8(&r) != MSG_KEX_ECDH_INIT) return -1;
    uint32_t qclen = br_u32(&r);
    const uint8_t* qc = br_raw(&r, qclen);
    if (qclen != 32) return -1;

    uint8_t spriv[32], spub[32], base[32] = {9};
    kc_random(spriv, 32);
    spriv[0] &= 248; spriv[31] &= 127; spriv[31] |= 64;
    kc_x25519(spriv, base, spub);
    kc_x25519(spriv, qc, g_k);

    uint8_t ksb[128]; struct buf kb; kb.p = ksb; kb.len = 0; kb.cap = sizeof(ksb);
    const char alg[] = "ssh-ed25519";
    bw_str(&kb, alg, 11);
    bw_str(&kb, g_host_pk, 32);

    struct shactx s; sha_init(&s);
    sha_add_str(&s, g_vc, (uint32_t)strlen(g_vc));
    sha_add_str(&s, g_vs, (uint32_t)strlen(g_vs));
    sha_add_str(&s, g_ic, g_ic_len);
    sha_add_str(&s, g_is, g_is_len);
    sha_add_str(&s, ksb, kb.len);
    sha_add_str(&s, qc, 32);
    sha_add_str(&s, spub, 32);
    sha_add_mpint(&s, g_k, 32);
    uint8_t H[32];
    sha_final(&s, H);
    memcpy(g_sid, H, 32);

    uint8_t sig[64];
    kc_ed25519_sign(sig, H, 32, g_host_sk);
    uint8_t sigblob[128]; struct buf sb; sb.p = sigblob; sb.len = 0; sb.cap = sizeof(sigblob);
    bw_str(&sb, alg, 11);
    bw_str(&sb, sig, 64);

    uint8_t rep[256]; struct buf rb; rb.p = rep; rb.len = 0; rb.cap = sizeof(rep);
    bw_u8(&rb, MSG_KEX_ECDH_REPLY);
    bw_str(&rb, ksb, kb.len);
    bw_str(&rb, spub, 32);
    bw_str(&rb, sigblob, sb.len);
    if (ssh_send(rep, rb.len) < 0) return -1;

    uint8_t nk[1] = { MSG_NEWKEYS };
    if (ssh_send(nk, 1) < 0) return -1;
    if (ssh_recv(pkt, &plen) < 0 || pkt[0] != MSG_NEWKEYS) return -1;

    derive_key(g_key_c2s, H, 'C');
    derive_key(g_key_s2c, H, 'D');
    g_encrypted = 1;
    printf("sshd: KEX done (curve25519-sha256, ssh-ed25519)\n");
    return 0;
}

/* ---------------- userauth ---------------- */
static int service_accept(const char* name) {
    uint8_t p[128]; struct buf b; b.p = p; b.len = 0; b.cap = sizeof(p);
    bw_u8(&b, MSG_SERVICE_ACCEPT);
    bw_str(&b, name, (uint32_t)strlen(name));
    return ssh_send(p, b.len);
}

/* FNV-1a(salt||password), as used by the kernel's /etc/shadow. */
static uint32_t fnv1a_pw(const char* salt, const char* pass) {
    uint32_t h = 2166136261u;
    for (int i = 0; salt[i]; i++) { h ^= (uint8_t)salt[i]; h *= 16777619u; }
    for (int i = 0; pass[i]; i++) { h ^= (uint8_t)pass[i]; h *= 16777619u; }
    return h;
}

/* Verify a password against the "name|salt|hash" line in /etc/shadow. */
static int verify_password(const char* user, const char* pass) {
    int fd = (int)sys_open("/etc/shadow", O_RDONLY, 0);
    if (fd < 0) return 0;
    static char buf[4096];
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    size_t ulen = strlen(user);
    char* p = buf;
    while (*p) {
        char* eol = p;
        while (*eol && *eol != '\n') eol++;
        char* b1 = p;
        while (b1 < eol && *b1 != '|') b1++;
        if (b1 < eol && (size_t)(b1 - p) == ulen && memcmp(p, user, ulen) == 0) {
            char* b2 = b1 + 1;
            while (b2 < eol && *b2 != '|') b2++;
            if (b2 < eol) {
                char salt[40]; size_t sl = (size_t)(b2 - (b1 + 1));
                if (sl > sizeof(salt) - 1) sl = sizeof(salt) - 1;
                memcpy(salt, b1 + 1, sl); salt[sl] = 0;
                char want[16]; size_t hl = (size_t)(eol - (b2 + 1));
                if (hl > sizeof(want) - 1) hl = sizeof(want) - 1;
                memcpy(want, b2 + 1, hl); want[hl] = 0;
                uint32_t h = fnv1a_pw(salt, pass);
                static const char hx[] = "0123456789abcdef";
                char got[16];
                for (int i = 7; i >= 0; i--) { got[i] = hx[h & 0xF]; h >>= 4; }
                got[8] = 0;
                return strcmp(got, want) == 0;
            }
        }
        p = (*eol) ? eol + 1 : eol;
    }
    return 0;
}

static int auth_failure(void) {
    uint8_t f[64]; struct buf b; b.p = f; b.len = 0; b.cap = sizeof(f);
    bw_u8(&b, MSG_USERAUTH_FAILURE);
    bw_str(&b, "password,publickey", 18);
    bw_u8(&b, 0);
    return ssh_send(f, b.len);
}

static int do_userauth(void) {
    static uint8_t pkt[2048];
    uint32_t plen;
    /* SERVICE_REQUEST ssh-userauth */
    int rr = ssh_recv(pkt, &plen);
    if (rr < 0 || pkt[0] != MSG_SERVICE_REQUEST) return -1;
    struct br r; r.p = pkt; r.len = plen; r.pos = 1;
    uint32_t n = br_u32(&r); const uint8_t* svc = br_raw(&r, n);
    if (n != 12 || memcmp(svc, "ssh-userauth", 12) != 0) return -1;
    if (service_accept("ssh-userauth") < 0) return -1;

    /* USERAUTH_REQUEST loop: accept "password" against /etc/shadow. */
    for (;;) {
        rr = ssh_recv(pkt, &plen);
        if (rr < 0 || pkt[0] != MSG_USERAUTH_REQUEST) return -1;
        struct br ur; ur.p = pkt; ur.len = plen; ur.pos = 1;
        uint32_t un = br_u32(&ur);
        const uint8_t* user = br_raw(&ur, un);
        uint32_t ul = un < sizeof(g_user) - 1 ? un : (uint32_t)sizeof(g_user) - 1;
        memcpy(g_user, user, ul);
        g_user[ul] = 0;
        g_shell_uid = (ul == 4 && memcmp(g_user, "root", 4) == 0) ? 0 : 1000;
        uint32_t sn = br_u32(&ur); br_raw(&ur, sn); /* service */
        uint32_t mn = br_u32(&ur);
        const uint8_t* method = br_raw(&ur, mn);
        int ok = 0;
        if (mn == 8 && memcmp(method, "password", 8) == 0) {
            br_u8(&ur); /* FALSE: not a password change */
            uint32_t pn = br_u32(&ur);
            const uint8_t* pass = br_raw(&ur, pn);
            char pw[128];
            uint32_t pl = pn < sizeof(pw) - 1 ? pn : (uint32_t)sizeof(pw) - 1;
            memcpy(pw, pass, pl);
            pw[pl] = 0;
            ok = verify_password(g_user, pw);
            printf("sshd: password auth user=%s ok=%d\n", g_user, ok);
        }
        if (ok) {
            uint8_t succ[1] = { MSG_USERAUTH_SUCCESS };
            if (ssh_send(succ, 1) < 0) return -1;
            break;
        }
        if (auth_failure() < 0) return -1;
    }

    /* Optional SERVICE_REQUEST "ssh-connection"; otherwise the client
       proceeds straight to CHANNEL_OPEN, which we hand to do_connection. */
    rr = ssh_recv(pkt, &plen);
    if (rr < 0) return -1;
    if (pkt[0] == MSG_SERVICE_REQUEST) {
        r.p = pkt; r.len = plen; r.pos = 1;
        n = br_u32(&r); svc = br_raw(&r, n);
        if (n != 14 || memcmp(svc, "ssh-connection", 14) != 0) return -1;
        if (service_accept("ssh-connection") < 0) return -1;
    } else {
        if (plen > sizeof(g_pending)) return -1;
        memcpy(g_pending, pkt, plen);
        g_pending_len = plen;
        g_has_pending = 1;
    }
    printf("sshd: user authenticated\n");
    return 0;
}

/* ---------------- connection + PTY shell ---------------- */
static int start_shell(void) {
    int pfd[2];
    if (sys_pty_open(pfd) < 0) return -1;
    int master = pfd[0], slave = pfd[1];
    long sh = sys_fork();
    if (sh == 0) {
        sys_dup2(slave, 0);
        sys_dup2(slave, 1);
        sys_dup2(slave, 2);
        if (slave > 2) sys_close(slave);
        if (master > 2) sys_close(master);
        if (g_shell_uid != 0) sys_setuid(g_shell_uid);
        sys_chdir(g_shell_uid == 0 ? "/root" : "/");
        char* av[2];
        av[0] = (char*)"/tmp/sh.elf";
        av[1] = 0;
        sys_execve("/tmp/sh.elf", av, 0);
        sys_exit(127);
    }
    sys_close(slave);

    long relay = sys_fork();
    if (relay == 0) {
        /* master -> client (CHANNEL_DATA) */
        for (;;) {
            char data[1024];
            uint32_t lim = sizeof(data);
            if (g_maxpkt > 16 && g_maxpkt - 16 < lim) lim = g_maxpkt - 16;
            long r = sys_read(master, data, lim);
            if (r <= 0) break;
            uint8_t p[1100]; struct buf b; b.p = p; b.len = 0; b.cap = sizeof(p);
            bw_u8(&b, MSG_CHANNEL_DATA);
            bw_u32(&b, g_chan);
            bw_str(&b, data, (uint32_t)r);
            if (ssh_send(p, b.len) < 0) break;
        }
        uint8_t eof[5]; struct buf eb; eb.p = eof; eb.len = 0; eb.cap = sizeof(eof);
        bw_u8(&eb, MSG_CHANNEL_EOF); bw_u32(&eb, g_chan);
        ssh_send(eof, eb.len);
        sys_exit(0);
    }

    /* client -> master */
    static uint8_t pkt[2048];
    uint32_t plen;
    for (;;) {
        if (ssh_recv(pkt, &plen) < 0) break;
        uint8_t t = pkt[0];
        struct br r; r.p = pkt; r.len = plen; r.pos = 1;
        if (t == MSG_CHANNEL_DATA) {
            br_u32(&r); /* recipient */
            uint32_t dn = br_u32(&r);
            const uint8_t* d = br_raw(&r, dn);
            if (dn) sys_write(master, d, dn);
        } else if (t == MSG_CHANNEL_CLOSE || t == MSG_CHANNEL_EOF) {
            break;
        } else if (t == MSG_CHANNEL_WINDOW_ADJUST) {
            /* ignore */
        } else if (t == MSG_GLOBAL_REQUEST) {
            /* ignore: only the relay child may send s2c packets (shared seq) */
        } else if (t == MSG_DISCONNECT) {
            break;
        }
    }
    sys_kill((int)relay, 0);
    sys_kill((int)sh, 0);
    int st;
    sys_waitpid((int)relay, &st);
    sys_waitpid((int)sh, &st);
    sys_close(master);
    return 0;
}

static int start_exec(const char* cmd) {
    int pfd[2];
    if (sys_pty_open(pfd) < 0) return -1;
    int master = pfd[0], slave = pfd[1];
    long sh = sys_fork();
    if (sh == 0) {
        sys_dup2(slave, 0);
        sys_dup2(slave, 1);
        sys_dup2(slave, 2);
        if (slave > 2) sys_close(slave);
        if (master > 2) sys_close(master);
        if (g_shell_uid != 0) sys_setuid(g_shell_uid);
        sys_chdir(g_shell_uid == 0 ? "/root" : "/");
        char* av[2];
        av[0] = (char*)"/tmp/sh.elf";
        av[1] = 0;
        sys_execve("/tmp/sh.elf", av, 0);
        sys_exit(127);
    }
    sys_close(slave);
    sys_write(master, cmd, (unsigned long)strlen(cmd));
    sys_write(master, "\nexit\n", 6);

    uint64_t sc = 0;
    for (;;) {
        char data[1024];
        uint32_t lim = sizeof(data);
        if (g_maxpkt > 16 && g_maxpkt - 16 < lim) lim = g_maxpkt - 16;
        long r = sys_read(master, data, lim);
        if (r <= 0) break;
        uint8_t p[1100]; struct buf b; b.p = p; b.len = 0; b.cap = sizeof(p);
        bw_u8(&b, MSG_CHANNEL_DATA);
        bw_u32(&b, g_chan);
        bw_str(&b, data, (uint32_t)r);
        if (ssh_send(p, b.len) < 0) break;
    }
    {
        uint8_t es[64]; struct buf eb; eb.p = es; eb.len = 0; eb.cap = sizeof(es);
        bw_u8(&eb, MSG_CHANNEL_REQUEST);
        bw_u32(&eb, g_chan);
        bw_str(&eb, "exit-status", 11);
        bw_u8(&eb, 0);
        bw_u32(&eb, 0);
        ssh_send(es, eb.len);
    }
    uint8_t e[5]; struct buf eb; eb.p = e; eb.len = 0; eb.cap = sizeof(e);
    bw_u8(&eb, MSG_CHANNEL_EOF); bw_u32(&eb, g_chan); ssh_send(e, eb.len);
    struct buf cb; cb.p = e; cb.len = 0; cb.cap = sizeof(e);
    bw_u8(&cb, MSG_CHANNEL_CLOSE); bw_u32(&cb, g_chan); ssh_send(e, cb.len);
    sys_kill((int)sh, 0);
    int st;
    sys_waitpid((int)sh, &st);
    sys_close(master);
    return 0;
}

static int do_connection(void) {
    static uint8_t pkt[2048];
    uint32_t plen;
    if (g_has_pending) {
        memcpy(pkt, g_pending, g_pending_len);
        plen = g_pending_len;
        g_has_pending = 0;
    } else if (ssh_recv(pkt, &plen) < 0) {
        return -1;
    }
    if (pkt[0] != MSG_CHANNEL_OPEN) return -1;
    struct br r; r.p = pkt; r.len = plen; r.pos = 1;
    uint32_t tn = br_u32(&r); br_raw(&r, tn); /* channel type */
    g_chan = br_u32(&r);
    uint32_t win = br_u32(&r);
    uint32_t maxpkt = br_u32(&r);
    (void)win;
    if (maxpkt >= 64 && maxpkt < g_maxpkt) g_maxpkt = maxpkt;

    uint8_t p[64]; struct buf b; b.p = p; b.len = 0; b.cap = sizeof(p);
    bw_u8(&b, MSG_CHANNEL_OPEN_CONFIRMATION);
    bw_u32(&b, g_chan);   /* recipient */
    bw_u32(&b, 0);        /* sender channel */
    bw_u32(&b, 1 << 20);  /* initial window */
    bw_u32(&b, 32768);    /* max packet */
    if (ssh_send(p, b.len) < 0) return -1;

    int got_shell = 0;
    int mode = 1; /* 1 = interactive shell, 2 = exec */
    static char exec_cmd[512];
    while (!got_shell) {
        if (ssh_recv(pkt, &plen) < 0) return -1;
        uint8_t t = pkt[0];
        r.p = pkt; r.len = plen; r.pos = 1;
        if (t == MSG_CHANNEL_REQUEST) {
            br_u32(&r); /* recipient */
            uint32_t rn = br_u32(&r);
            const uint8_t* req = br_raw(&r, rn);
            uint8_t want_reply = br_u8(&r);
            int okreq = 0;
            if (rn == 7 && memcmp(req, "pty-req", 7) == 0) {
                okreq = 1;
            } else if (rn == 5 && memcmp(req, "shell", 5) == 0) {
                okreq = 1; mode = 1; got_shell = 1;
            } else if (rn == 4 && memcmp(req, "exec", 4) == 0) {
                uint32_t cn = br_u32(&r);
                const uint8_t* cmd = br_raw(&r, cn);
                uint32_t cl = cn < sizeof(exec_cmd) - 1 ? cn : (uint32_t)sizeof(exec_cmd) - 1;
                memcpy(exec_cmd, cmd, cl);
                exec_cmd[cl] = 0;
                okreq = 1; mode = 2; got_shell = 1;
            } else if (rn == 3 && memcmp(req, "env", 3) == 0) {
                okreq = 1;
            }
            if (want_reply) {
                uint8_t s[5]; struct buf sb; sb.p = s; sb.len = 0; sb.cap = sizeof(s);
                bw_u8(&sb, okreq ? MSG_CHANNEL_SUCCESS : MSG_CHANNEL_FAILURE);
                bw_u32(&sb, g_chan);
                ssh_send(s, sb.len);
            }
        } else if (t == MSG_CHANNEL_CLOSE) {
            return -1;
        }
    }
    if (mode == 2) return start_exec(exec_cmd);
    return start_shell();
}

/* ---------------- session ---------------- */
static int read_version(int fd, char* out, int cap) {
    int n = 0;
    while (n < cap - 1) {
        char c;
        if (recv_all(fd, &c, 1) < 0) return -1;
        if (c == '\n') break;
        if (c != '\r') out[n++] = c;
    }
    out[n] = 0;
    return n;
}

static void serve(int c) {
    g_fd = c;
    g_seq_in = g_seq_out = 0;
    g_encrypted = 0;
    g_chan = 0;

    /* version exchange */
    if (send_all(c, SSHV "\r\n", (int)strlen(SSHV) + 2) < 0) return;
    if (read_version(c, g_vc, sizeof(g_vc)) < 0) return;
    if (strncmp(g_vc, "SSH-", 4) != 0) return;
    strcpy(g_vs, SSHV);
    printf("sshd: client %s\n", g_vc);

    if (do_kex() < 0) { printf("sshd: kex failed\n"); return; }
    if (do_userauth() < 0) { printf("sshd: auth failed\n"); return; }
    if (do_connection() < 0) { printf("sshd: connection failed\n"); return; }
    printf("sshd: session closed\n");
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    /* stable demo host key derived from a fixed seed */
    uint8_t seed[32];
    kc_sha256("KnitOS-sshd-hostkey-v1", 21, seed);
    kc_ed25519_keygen(seed, g_host_pk);
    memcpy(g_host_sk, seed, 32);
    memcpy(g_host_sk + 32, g_host_pk, 32);

    int lfd = (int)sys_socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { printf("sshd: socket failed\n"); return 1; }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = SSH_PORT;
    addr.sin_addr = 0;
    if (sys_bind(lfd, &addr) < 0) { printf("sshd: bind failed\n"); return 1; }
    if (sys_listen(lfd, 4) < 0) { printf("sshd: listen failed\n"); return 1; }
    printf("sshd: listening on port %d\n", SSH_PORT);
    for (;;) {
        int c = (int)sys_accept(lfd, 10000);
        if (c < 0) continue;
        serve(c);
        sys_sock_close(c);
    }
    return 0;
}
