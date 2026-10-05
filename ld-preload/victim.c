/*
 * victim.c - A program whose behavior depends on the current time.
 *
 * It calls libc's time() to decide whether a "trial" has expired.
 * The program is dynamically linked, so time() is resolved by the dynamic
 * linker at run time, and LD_PRELOAD can change which time() it gets.
 *
 * Compile:  gcc -o victim victim.c
 * Run:      ./victim
 */
#include <stdio.h>
#include <time.h>

/* Trial ends 2025-01-01 00:00:00 UTC */
#define TRIAL_END 1735689600

int main(void) {
    time_t now = time(NULL);
    printf("Current time: %s", ctime(&now));

    if (now > TRIAL_END)
        printf("Trial expired. Please purchase a license.\n");
    else
        printf("Trial active. Welcome!\n");
    return 0;
}
