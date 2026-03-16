/*
 * fixed_ping_validation.c - "Fixed" with Input Validation (Blocklist)
 *
 * MITIGATION #1: Blocklist input validation
 * Block known dangerous shell metacharacters.
 *
 * NOTE: This approach is INTENTIONALLY FLAWED for teaching purposes.
 * Blocklists are inherently incomplete - there's always a bypass.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_INPUT 256
#define CMD_SIZE 512

/* Known dangerous shell metacharacters */
static const char *BLOCKED_CHARS = ";&|`$(){}[]!><#";

/*
 * Checks input against a blocklist of dangerous shell characters.
 * Returns: 1 if input appears safe, 0 if dangerous characters found
 */
int is_valid_target(const char *input) {
    if (input == NULL || strlen(input) == 0) {
        return 0;
    }

    if (strlen(input) > 253) {
        return 0;
    }

    // Block known dangerous characters
    for (size_t i = 0; input[i] != '\0'; i++) {
        if (strchr(BLOCKED_CHARS, input[i]) != NULL) {
            printf("[-] Blocked dangerous character: '%c'\n", input[i]);
            return 0;
        }
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
        fprintf(stderr, "Error: Dangerous characters detected in target.\n");
        return 1;
    }

    snprintf(command, sizeof(command), "ping -c 3 %s", target);
    printf("Executing: %s\n\n", command);

    int result = system(command);
    return result;
}
