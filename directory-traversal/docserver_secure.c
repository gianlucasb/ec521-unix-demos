/*
 * Document Server - SECURE VERSION
 * EC521 Demo
 *
 * This demonstrates the CORRECT fix for directory traversal using
 * realpath() to resolve canonical paths and verify containment.
 *
 * Why this works:
 *   1. realpath() resolves ALL symlinks and normalizes the path
 *   2. We compare the canonical paths, not string manipulation
 *   3. No matter how the attacker constructs the input, the resolved
 *      path must physically reside under the base directory
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define BASE_DIR "./public/"
#define MAX_PATH 256
#define BUFFER_SIZE 1024

/*
 * SECURE PATH VALIDATION
 *
 * Uses realpath() to resolve both the base directory and the requested
 * path to their canonical forms, then verifies the requested path
 * starts with the base path.
 *
 * Returns: 1 if path is safe, 0 if path escapes base directory
 */
int is_path_within_base(const char *base_dir, const char *requested_path) {
    char resolved_base[PATH_MAX];
    char resolved_request[PATH_MAX];
    size_t base_len;

    /* Resolve the base directory to canonical form */
    if (realpath(base_dir, resolved_base) == NULL) {
        perror("[-] Cannot resolve base directory");
        return 0;
    }

    /* Resolve the requested path to canonical form */
    if (realpath(requested_path, resolved_request) == NULL) {
        /* File doesn't exist or path is invalid */
        return 0;
    }

    /* Get length of base path */
    base_len = strlen(resolved_base);

    /* Check if resolved request starts with resolved base */
    if (strncmp(resolved_request, resolved_base, base_len) != 0) {
        return 0;
    }

    /*
     * Ensure we matched the full directory name, not just a prefix.
     * For example, base="/var/www" should not match "/var/www-backup/file"
     * The character after the base must be '/' or '\0' (exact match)
     */
    if (resolved_request[base_len] != '/' && resolved_request[base_len] != '\0') {
        return 0;
    }

    return 1;
}

int main(int argc, char *argv[]) {
    char filepath[MAX_PATH];
    char resolved_path[PATH_MAX];
    char buffer[BUFFER_SIZE];
    FILE *file;
    size_t bytes_read;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        fprintf(stderr, "Serves files from the public directory.\n");
        return 1;
    }

    printf("[*] Requested file: %s\n", argv[1]);

    /* Build the path (same as vulnerable version) */
    snprintf(filepath, sizeof(filepath), "%s%s", BASE_DIR, argv[1]);

    printf("[*] Constructed path: %s\n", filepath);

    /* SECURE CHECK: Validate the path stays within BASE_DIR */
    if (!is_path_within_base(BASE_DIR, filepath)) {
        fprintf(stderr, "[-] ACCESS DENIED: Path escapes base directory!\n");
        fprintf(stderr, "[-] This could be a directory traversal attack.\n");
        return 1;
    }

    /* Show the canonical resolved path for educational purposes */
    if (realpath(filepath, resolved_path) != NULL) {
        printf("[+] Canonical path:   %s\n", resolved_path);
    }

    printf("[+] Path validated - within allowed directory\n");
    printf("[*] Reading file...\n\n");

    file = fopen(filepath, "r");
    if (file == NULL) {
        perror("[-] Error opening file");
        return 1;
    }

    /* Read and display file contents */
    printf("--- File Contents ---\n");
    while ((bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
    }
    printf("\n--- End of File ---\n");

    fclose(file);
    return 0;
}
