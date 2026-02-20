/*
 * fixed_ping_validation.c - Fixed with Input Validation
 *
 * MITIGATION #1: Allowlist input validation
 * Only permit characters that are valid in hostnames/IPs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_INPUT 256
#define CMD_SIZE 512

/*
 * Validates that input contains only safe characters for a hostname/IP.
 * Allowed: alphanumeric, dots, hyphens, colons (for IPv6)
 * Returns: 1 if valid, 0 if invalid
 */
int is_valid_target(const char *input) {
    if (input == NULL || strlen(input) == 0) {
        return 0;
    }

    // Check maximum reasonable hostname length (RFC 1035: 253 chars)
    if (strlen(input) > 253) {
        return 0;
    }

    for (size_t i = 0; input[i] != '\0'; i++) {
        char c = input[i];

        // Allowlist: alphanumeric, dot, hyphen, colon (IPv6)
        if (!isalnum((unsigned char)c) && c != '.' && c != '-' && c != ':') {
            return 0;
        }
    }

    // Additional check: shouldn't start or end with hyphen or dot
    size_t len = strlen(input);
    if (input[0] == '-' || input[0] == '.' ||
        input[len-1] == '-' || input[len-1] == '.') {
        return 0;
    }

    return 1;
}

int main(int argc, char *argv[]) {
    char target[MAX_INPUT];
    char command[CMD_SIZE];

    printf("=== Network Diagnostic Tool (Input Validation) ===\n");
    printf("Enter hostname or IP to ping: ");

    if (fgets(target, sizeof(target), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }

    target[strcspn(target, "\n")] = '\0';

    // FIX: Validate input before use
    if (!is_valid_target(target)) {
        fprintf(stderr, "Error: Invalid characters in target.\n");
        fprintf(stderr, "Only alphanumeric, dots, hyphens, and colons allowed.\n");
        return 1;
    }

    snprintf(command, sizeof(command), "ping -c 3 %s", target);
    printf("Executing: %s\n\n", command);

    int result = system(command);
    return result;
}
