/*
 * fixed_ping_library.c - Fixed with Library Function
 *
 * MITIGATION #3: Use a library instead of executing external commands
 * This uses raw sockets to send ICMP echo requests directly,
 * completely avoiding any shell or external process.
 *
 * NOTE: Requires root privileges or CAP_NET_RAW capability to run.
 * Compile: gcc -o fixed_ping_library fixed_ping_library.c
 * Run:     sudo ./fixed_ping_library
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define MAX_INPUT 256
#define PING_COUNT 3
#define TIMEOUT_SEC 2

/*
 * Calculate ICMP checksum
 */
unsigned short checksum(void *data, int len) {
    unsigned short *buf = data;
    unsigned int sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

/*
 * Resolve hostname to IP address
 */
int resolve_host(const char *hostname, struct sockaddr_in *addr) {
    struct addrinfo hints, *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;

    int ret = getaddrinfo(hostname, NULL, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "Could not resolve host: %s\n", gai_strerror(ret));
        return -1;
    }

    memcpy(addr, result->ai_addr, sizeof(*addr));
    freeaddrinfo(result);
    return 0;
}

/*
 * Send a single ICMP echo request and wait for reply
 */
int ping_host(int sockfd, struct sockaddr_in *addr, int seq) {
    char packet[64];
    struct icmp *icmp_hdr = (struct icmp *)packet;
    struct timeval start, end;

    // Build ICMP echo request
    memset(packet, 0, sizeof(packet));
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = htons(getpid() & 0xFFFF);
    icmp_hdr->icmp_seq = htons(seq);
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = checksum(packet, sizeof(packet));

    gettimeofday(&start, NULL);

    // Send packet
    if (sendto(sockfd, packet, sizeof(packet), 0,
               (struct sockaddr *)addr, sizeof(*addr)) < 0) {
        perror("sendto");
        return -1;
    }

    // Wait for reply
    char recv_buf[128];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    ssize_t bytes = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr *)&from, &fromlen);

    gettimeofday(&end, NULL);

    if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Request timeout for seq %d\n", seq);
        } else {
            perror("recvfrom");
        }
        return -1;
    }

    // Calculate round-trip time
    double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                 (end.tv_usec - start.tv_usec) / 1000.0;

    printf("Reply from %s: seq=%d time=%.2f ms\n",
           inet_ntoa(from.sin_addr), seq, rtt);

    return 0;
}

int main(int argc, char *argv[]) {
    char target[MAX_INPUT];
    struct sockaddr_in addr;

    printf("=== Network Diagnostic Tool (Library/Raw Socket) ===\n");
    printf("Enter hostname or IP to ping: ");

    if (fgets(target, sizeof(target), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }

    target[strcspn(target, "\n")] = '\0';

    if (strlen(target) == 0) {
        fprintf(stderr, "Error: No target specified\n");
        return 1;
    }

    // FIX: No shell involved at all!
    // User input is passed directly to networking functions.
    // Shell metacharacters like ; | & have no special meaning here.

    printf("Pinging %s...\n\n", target);

    // Resolve hostname
    if (resolve_host(target, &addr) < 0) {
        return 1;
    }

    // Create raw socket for ICMP
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket (are you root?)");
        return 1;
    }

    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Send pings
    int success = 0;
    for (int i = 1; i <= PING_COUNT; i++) {
        if (ping_host(sockfd, &addr, i) == 0) {
            success++;
        }
        if (i < PING_COUNT) {
            sleep(1);
        }
    }

    close(sockfd);

    printf("\n--- %s ping statistics ---\n", target);
    printf("%d packets transmitted, %d received\n", PING_COUNT, success);

    return (success > 0) ? 0 : 1;
}
