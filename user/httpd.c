// M3: minimal user-space HTTP server (validates socket ABI + libk in user mode).
#include "lib/libk.h"

static const char* page =
    "<!doctype html><html><head><title>KnitOS</title></head>"
    "<body><h1>KnitOS httpd</h1>"
    "<p>Hello from user space!</p></body></html>\n";

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    int port = 8080;
    int fd = (int)sys_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = (unsigned short)port;
    addr.sin_addr = 0;
    if (sys_bind(fd, &addr) < 0) return 1;
    if (sys_listen(fd, 4) < 0) return 1;

    for (;;) {
        int c = (int)sys_accept(fd, 10000);
        if (c < 0) continue;
        char req[1024];
        int n = (int)sys_recv(c, req, sizeof(req) - 1, 3000);
        if (n > 0) {
            req[n] = 0;
            int blen = (int)strlen(page);
            char resp[512];
            int rl = snprintf(resp, sizeof(resp),
                "HTTP/1.0 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %d\r\n"
                "Connection: close\r\n"
                "\r\n%s",
                blen, page);
            sys_send(c, resp, (unsigned long)rl);
        }
        sys_sock_close(c);
    }
    return 0;
}
