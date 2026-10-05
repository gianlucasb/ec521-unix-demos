/*
 * bind80_caps.c - Bind to port 80 as an unprivileged user using capabilities.
 *
 * Instead of running as root, the binary is granted exactly one capability
 * via a file capability:
 *
 *     sudo setcap cap_net_bind_service=+ep ./bind80_caps
 *
 * The process runs as a normal user (uid != 0) but the kernel lets it bind
 * port 80 because CAP_NET_BIND_SERVICE is in its effective set. After
 * binding, we drop the capability entirely, so the code that handles network
 * input has no special privileges at all.
 *
 * Run:  ./bind80_caps    (fails with EACCES until setcap has been run)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/capability.h>

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

/* Clear the effective, permitted and inheritable sets (no libcap needed). */
static int drop_all_caps(void) {
    struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof(data));
    return syscall(SYS_capset, &hdr, data);
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
        printf("Hint: sudo setcap cap_net_bind_service=+ep ./bind80_caps\n");
        return 1;
    }
    printf("bind(%d) succeeded\n", PORT);

    if (drop_all_caps() < 0) { perror("capset"); return 1; }
    print_identity("after drop");

    listen(srv, 5);
    printf("Listening on port %d (no capabilities left)...\n", PORT);

    for (;;) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;
        const char *resp = "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nhi\n";
        write(c, resp, strlen(resp));
        close(c);
    }
}
