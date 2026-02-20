/*
 * TOCTOU (Time of Check to Time of Use) Vulnerability Demo
 * =========================================================
 *
 * This program demonstrates a classic race condition vulnerability.
 * When run as a setuid-root program, it attempts to safely read a file
 * by first checking if the real user has permission. However, the
 * filesystem state can change between the check and the actual file open.
 *
 * VULNERABILITY WINDOW:
 *   1. access() checks permissions using REAL UID
 *   2. fopen() opens file using EFFECTIVE UID (root if setuid)
 *   3. Between these calls, an attacker can swap a symlink
 *
 * EXPLOITATION:
 *   Terminal 1 (victim runs):
 *     $ ln -s /tmp/readable.txt /tmp/target
 *     $ ./toctou /tmp/target
 *
 *   Terminal 2 (during the sleep window):
 *     $ rm /tmp/target && ln -s /etc/shadow /tmp/target
 *
 *   Result: Program reads /etc/shadow with root privileges!
 *
 * SECURE ALTERNATIVE:
 *   Instead of check-then-open, use open-then-check:
 *
 *     int fd = open(argv[1], O_RDONLY);
 *     struct stat st;
 *     fstat(fd, &st);
 *     // Check st.st_uid, st.st_mode to verify the real user should have access
 *
 *   This eliminates the race because we operate on the file descriptor,
 *   not the pathname. Once opened, the fd refers to a specific inode,
 *   and symlink swaps cannot affect it.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    /* Get and display the real and effective UIDs.
     * In a setuid program, these will differ:
     *   - real UID: the actual user running the program
     *   - effective UID: the owner of the binary (root if setuid-root)
     */
    int real = getuid();
    int euid = geteuid();
    printf("REAL UID: %d\n", real);
    printf("EFFECTIVE UID: %d\n", euid);

    /* VULNERABLE CHECK (Time of Check)
     * access() checks using the REAL UID, not effective UID.
     * This is intentional - it's meant to answer "can the actual user read this?"
     * But this creates a race condition with the subsequent fopen().
     */
    if (access(argv[1], R_OK)) {
        printf("You don't have permissions to read this file\n");
        return 1;
    }

    /* RACE WINDOW - artificially extended to 60 seconds for demo purposes.
     * In real vulnerable programs, this window may be milliseconds,
     * but attackers can still exploit it with repeated attempts.
     */
    sleep(60);

    /* VULNERABLE USE (Time of Use)
     * fopen() uses EFFECTIVE UID (root).
     * If the file path was swapped during the sleep, we now open
     * a different file than what we checked!
     */
    FILE *f;
    f = fopen(argv[1], "r");
    if (f == NULL) {
        perror("fopen");
        return 1;
    }

    char chunk[64];

    while (fgets(chunk, sizeof(chunk), f) != NULL) {
        fputs(chunk, stdout);
    }

    fclose(f);

    return 0;
}
