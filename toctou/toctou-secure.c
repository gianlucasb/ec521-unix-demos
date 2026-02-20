/*
 * TOCTOU-Secure: Fixed Version
 * ============================
 *
 * This program demonstrates the SECURE way to check file permissions
 * in a setuid program, eliminating the TOCTOU race condition.
 *
 * THE FIX:
 *   Instead of check-then-open (access() then fopen()), we use:
 *   1. open() the file first - this locks in the inode
 *   2. fstat() on the fd - checks the actual opened file
 *   3. Verify permissions based on file metadata
 *
 *   Once we have a file descriptor, symlink swaps cannot affect it
 *   because the fd refers to a specific inode, not a pathname.
 *
 * ADDITIONAL PROTECTIONS:
 *   - O_NOFOLLOW: Refuse to open symlinks (optional, stricter policy)
 *   - Check file ownership and mode bits against real UID/GID
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

/*
 * Check if the real user (not effective user) has read permission
 * for the file described by the stat structure.
 *
 * Returns 1 if access should be granted, 0 otherwise.
 */
int check_real_user_access(struct stat *st) {
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

    /* If the real user owns the file, check owner permissions */
    if (st->st_uid == real_uid) {
        return (st->st_mode & S_IRUSR) != 0;
    }

    /* If the real user's group owns the file, check group permissions */
    if (st->st_gid == real_gid) {
        return (st->st_mode & S_IRGRP) != 0;
    }

    /* Otherwise, check world permissions */
    return (st->st_mode & S_IROTH) != 0;
}

int main(int argc, char** argv) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    /* Display UIDs for demonstration purposes */
    uid_t real_uid = getuid();
    uid_t euid = geteuid();
    printf("REAL UID: %d\n", real_uid);
    printf("EFFECTIVE UID: %d\n", euid);

    /*
     * SECURE: Open first, check later.
     *
     * O_NOFOLLOW prevents opening symlinks, providing additional
     * protection against symlink attacks. Remove this flag if you
     * need to legitimately follow symlinks.
     */
    int fd = open(argv[1], O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) {
            fprintf(stderr, "Error: %s is a symbolic link (not allowed)\n", argv[1]);
        } else {
            perror("open");
        }
        return 1;
    }

    /*
     * SECURE: Use fstat() on the file descriptor.
     *
     * This checks the ACTUAL file we opened, not a pathname that
     * could have changed. The file descriptor is bound to an inode,
     * so even if an attacker swaps symlinks after this point,
     * we're still looking at the original file.
     */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    /* Reject non-regular files (e.g., devices, directories) */
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: %s is not a regular file\n", argv[1]);
        close(fd);
        return 1;
    }

    /*
     * SECURE: Check if the REAL user has permission.
     *
     * We manually check the file's ownership and permission bits
     * against the real UID/GID. This is the equivalent of what
     * access() does, but on the already-opened file.
     */
    if (!check_real_user_access(&st)) {
        printf("You don't have permissions to read this file\n");
        close(fd);
        return 1;
    }

    printf("Access granted - reading file...\n");

    /* Simulated delay - now safe because we're using the fd, not the path */
    sleep(60);

    /*
     * SECURE: Read from the file descriptor.
     *
     * Even if an attacker swaps the symlink during the sleep,
     * we're still reading from the original file we opened and checked.
     */
    char chunk[64];
    ssize_t bytes_read;

    while ((bytes_read = read(fd, chunk, sizeof(chunk) - 1)) > 0) {
        chunk[bytes_read] = '\0';
        fputs(chunk, stdout);
    }

    if (bytes_read < 0) {
        perror("read");
        close(fd);
        return 1;
    }

    close(fd);

    return 0;
}
