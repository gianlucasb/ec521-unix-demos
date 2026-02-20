/*
 * fixed_ping_execve.c - Fixed with execve()
 *
 * MITIGATION #2: Use execve() instead of system()
 * execve() does NOT invoke a shell, so metacharacters like ; | & are
 * passed as literal arguments to the program, not interpreted.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_INPUT 256

int main(int argc, char *argv[]) {
    char target[MAX_INPUT];

    printf("=== Network Diagnostic Tool (execve) ===\n");
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

    printf("Pinging: %s\n\n", target);

    // FIX: Use fork + execve instead of system()
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        return 1;
    }

    if (pid == 0) {
        // Child process

        // Arguments passed as separate array elements, NOT parsed by shell
        // Even if target contains "; rm -rf /", it's treated as a literal hostname
        char *args[] = {
            "/bin/ping",
            "-c", "3",
            target,     // User input is a single argument, not shell-parsed
            NULL
        };

        // Environment (can be empty or inherited)
        char *env[] = { NULL };

        // execve replaces this process with ping
        // NO SHELL INVOLVED - metacharacters are NOT interpreted
        execve("/bin/ping", args, env);

        // If execve returns, it failed
        perror("execve failed");
        exit(1);
    }

    // Parent process: wait for child
    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    return 1;
}
