/*
 * vuln_ping.c - Vulnerable Ping Utility
 *
 * EDUCATIONAL DEMO: Command Injection Vulnerability
 * This program intentionally contains a security flaw for teaching purposes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 256
#define CMD_SIZE 512

int main(int argc, char *argv[]) {
    char command[CMD_SIZE];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hostname or IP>\n", argv[0]);
        return 1;
    }

    printf("=== Network Diagnostic Tool ===\n");

    // VULNERABLE: User input is directly concatenated into command
    snprintf(command, sizeof(command), "ping -c 3 %s", argv[1]);

    printf("Executing: %s\n\n", command);

    // VULNERABLE: system() executes the command through a shell
    // This allows shell metacharacters like ; | & ` $() to be interpreted
    int result = system(command);

    return result;
}
