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
    char target[MAX_INPUT];
    char command[CMD_SIZE];

    printf("=== Network Diagnostic Tool ===\n");
    printf("Enter hostname or IP to ping: ");

    // Read user input
    if (fgets(target, sizeof(target), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }

    // Remove trailing newline
    target[strcspn(target, "\n")] = '\0';

    if (strlen(target) == 0) {
        fprintf(stderr, "Error: No target specified\n");
        return 1;
    }

    // VULNERABLE: User input is directly concatenated into command
    snprintf(command, sizeof(command), "ping -c 3 %s", target);

    printf("Executing: %s\n\n", command);

    // VULNERABLE: system() executes the command through a shell
    // This allows shell metacharacters like ; | & ` $() to be interpreted
    int result = system(command);

    return result;
}
