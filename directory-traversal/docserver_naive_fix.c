/*
 * Document Server - NAIVE FIX (Still Vulnerable!)
 * EC521 Demo
 *
 * This demonstrates a common but INSUFFICIENT fix for directory traversal.
 * The sanitization can be bypassed using SYMLINKS.
 *
 * Bypass example:
 *   1. Create symlink: ln -s /etc public/configs
 *   2. Request: ./docserver_naive configs/passwd
 *   3. The string check passes (no "..") but symlink escapes!
 *
 * The fundamental flaw: String-based validation cannot detect
 * symlinks that point outside the allowed directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE_DIR "./public/"
#define MAX_PATH 256
#define BUFFER_SIZE 1024

/*
 * FLAWED CHECK: Only looks at the STRING for ".." patterns.
 * Does NOT resolve symlinks or check where the file actually resides.
 * A symlink like public/escape -> /etc bypasses this completely.
 */
int is_path_safe_naive(const char *path) {
    /* Check for obvious traversal patterns */
    if (strstr(path, "..") != NULL) {
        return 0;  /* Contains ".." - reject */
    }

    /* Check for absolute paths trying to escape */
    if (path[0] == '/') {
        return 0;  /* Absolute path - reject */
    }

    /* FLAW: We think it's safe, but symlinks can still escape! */
    return 1;
}

int main(int argc, char *argv[]) {
    char filepath[MAX_PATH];
    char buffer[BUFFER_SIZE];
    FILE *file;
    size_t bytes_read;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        fprintf(stderr, "Serves files from the public directory.\n");
        return 1;
    }

    printf("[*] Requested file: %s\n", argv[1]);

    /* NAIVE CHECK: String-based validation */
    if (!is_path_safe_naive(argv[1])) {
        fprintf(stderr, "[-] Rejected: path contains suspicious patterns\n");
        return 1;
    }

    printf("[+] Naive check passed (no '..' found in string)\n");

    /* Build the final path */
    snprintf(filepath, sizeof(filepath), "%s%s", BASE_DIR, argv[1]);

    printf("[*] Resolved path:  %s\n", filepath);
    printf("[*] Reading file...\n");
    printf("[!] WARNING: Symlinks are NOT checked!\n\n");

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
