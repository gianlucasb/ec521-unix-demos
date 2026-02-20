/*
 * Vulnerable Document Server - EC521 Demo
 *
 * This program demonstrates a DIRECTORY TRAVERSAL vulnerability.
 * DO NOT use this code in production - it is intentionally insecure.
 *
 * The vulnerability: User input is directly concatenated to the base path
 * without validating that the resulting path stays within the public directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE_DIR "./public/"
#define MAX_PATH 256
#define BUFFER_SIZE 1024

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

    /* VULNERABLE: Direct concatenation of user input to base path.
     * No validation is performed to ensure the path stays within BASE_DIR.
     * An attacker can use "../" sequences to escape the directory.
     */
    snprintf(filepath, sizeof(filepath), "%s%s", BASE_DIR, argv[1]);

    printf("[*] Requested file: %s\n", argv[1]);
    printf("[*] Resolved path:  %s\n", filepath);
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
