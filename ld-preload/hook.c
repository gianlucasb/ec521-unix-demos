/*
 * hook.c - Shared library that replaces libc's time().
 *
 * When loaded with LD_PRELOAD, the dynamic linker searches this library
 * BEFORE libc, so the victim's call to time() lands here instead.
 * The victim binary is not modified in any way.
 *
 * Compile:  gcc -shared -fPIC -o hook.so hook.c
 * Run:      LD_PRELOAD=./hook.so ./victim
 */
#include <time.h>

/* Pretend it is always 2024-06-01 00:00:00 UTC */
time_t time(time_t *tloc) {
    time_t fake = 1717200000;
    if (tloc)
        *tloc = fake;
    return fake;
}
