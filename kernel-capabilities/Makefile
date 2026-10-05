CC = gcc
CFLAGS = -Wall -Wextra -g

all: bind80_root bind80_caps

bind80_root: bind80_root.c
	$(CC) $(CFLAGS) -o bind80_root bind80_root.c

bind80_caps: bind80_caps.c
	$(CC) $(CFLAGS) -o bind80_caps bind80_caps.c

clean:
	rm -f bind80_root bind80_caps

# ============================================================
# NOTE: Linux only. Docker containers default to
# net.ipv4.ip_unprivileged_port_start=0, which lets ANY user bind port 80
# and makes the "fails" demos succeed. In Docker, add:
#   --sysctl net.ipv4.ip_unprivileged_port_start=1024
# On a normal host, check: sysctl net.ipv4.ip_unprivileged_port_start
# ============================================================

# --- Approach 1: run as root -------------------------------------------

demo-root-fails:
	@echo "=== Root version as a normal user: no CAP_NET_BIND_SERVICE ==="
	-./bind80_root

demo-root:
	@echo "=== Root version with sudo: works, but we hold ALL capabilities ==="
	sudo ./bind80_root

# --- Approach 2: capabilities ------------------------------------------

demo-caps-fails:
	@echo "=== Caps version before setcap: fails like any normal user ==="
	-./bind80_caps

setcap: bind80_caps
	@echo "=== Granting ONLY cap_net_bind_service to the binary ==="
	sudo setcap cap_net_bind_service=+ep ./bind80_caps
	getcap ./bind80_caps

demo-caps: setcap
	@echo "=== Caps version as a normal user: binds 80, then drops the cap ==="
	./bind80_caps

# Remove the file capability again
unsetcap:
	sudo setcap -r ./bind80_caps

# Inspect a running server from another terminal (e.g. after `make demo-caps`)
show-caps:
	@for p in bind80_root bind80_caps; do \
	  pid=$$(pgrep -n $$p) && echo "== $$p (pid $$pid) ==" && grep -E 'Uid|Cap' /proc/$$pid/status; \
	done; true

.PHONY: all clean demo-root-fails demo-root demo-caps-fails setcap demo-caps unsetcap show-caps
