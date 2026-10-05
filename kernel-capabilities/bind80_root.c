/*
 * bind80_root.c - Bind to port 80 the "traditional" way: run as root.
 *
 * Ports below 1024 are privileged. The kernel only lets a process bind them
 * if it has CAP_NET_BIND_SERVICE. Root has that capability, but it also has
 * every other capability (CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, ...), so a bug
 * in this program hands the attacker the entire machine.
 *
 * Run:  sudo ./bind80_root      (works)
 *       ./bind80_root           (fails with EACCES)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define PORT 80

static void print_identity(const char *when) {
    printf("[%s] uid=%d euid=%d\n", when, getuid(), geteuid());
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, "Cap", 3) == 0)
            printf("[%s] %s", when, line);
    fclose(f);
}

int main(void) {
    print_identity("start");

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("bind(%d) failed: %s\n", PORT, strerror(errno));
        return 1;
    }
    printf("bind(%d) succeeded\n", PORT);

    /* Note: we are STILL root here, with every capability, while parsing
     * untrusted network input. */
    print_identity("after bind");

    listen(srv, 5);
    printf("Listening on port %d...\n", PORT);

    for (;;) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;
        const char *resp = "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nhi\n";
        write(c, resp, strlen(resp));
        close(c);
    }
}
