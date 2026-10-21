#!/usr/bin/env bash
#
# Cerberus Phase 4 integration test.
#
# Verifies:
#   - process-scoped rules (comm + target)
#   - UID-scoped rules
#   - runtime addproc / rmuid commands
#   - sandbox (allowlist-only) mode
#   - monitor mode reporting for sandbox denials
#   - list output and clean shutdown
#
# Must run as root (BPF LSM).
#
# Usage:
#   sudo tests/test_phase4.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AGENT=./build/cerberus_agent
FIFO=/tmp/cerberus_p4_fifo
LOG=/tmp/cerberus_p4.log
WORK=/tmp/cerberus_p4_dir

pass=0
fail=0

check() {
    local desc="$1" expected="$2" actual="$3"

    if [ "$expected" = "$actual" ]; then
        echo "PASS: $desc"
        pass=$((pass + 1))
    else
        echo "FAIL: $desc (expected '$expected', got '$actual')"
        fail=$((fail + 1))
    fi
}

contains() {
    local desc="$1" needle="$2" file="$3"

    if grep -q "$needle" "$file" 2>/dev/null; then
        echo "PASS: $desc"
        pass=$((pass + 1))
    else
        echo "FAIL: $desc (missing '$needle')"
        fail=$((fail + 1))
    fi
}

cleanup() {
    exec 9>&- 2>/dev/null || true

    if [ -n "${AGENT_PID:-}" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill -INT "$AGENT_PID" 2>/dev/null
        wait "$AGENT_PID" 2>/dev/null
    fi

    rm -rf "$WORK" "$FIFO" "$LOG"
}

trap cleanup EXIT


if [ "$(id -u)" -ne 0 ]; then
    echo "This test must run as root: sudo $0"
    exit 1
fi

if [ ! -x "$AGENT" ]; then
    echo "Agent not built. Run 'make' first."
    exit 1
fi


#
# Test fixtures.
#
rm -rf "$WORK" "$FIFO" "$LOG"
mkdir -p "$WORK"

echo "proc secret" > "$WORK/procsecret.txt"
echo "uid secret" > "$WORK/uidsecret.txt"
echo "other content" > "$WORK/other.txt"
echo "allowed content" > "$WORK/allowed.txt"
echo "head secret" > "$WORK/prochead.txt"

#
# Statically linked probe: a sandboxed process
# cannot rely on the dynamic loader, because the
# loader's own file opens would also be denied.
#
cat > "$WORK/probe.c" <<'PROBE'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 2)
        return 3;

    int fd = open(argv[1], O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "denied: %s\n", strerror(errno));
        return 2;
    }

    char buf[128];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n < 0)
        return 4;

    buf[n] = 0;
    printf("%s", buf);

    return 0;
}
PROBE

gcc -static -O2 "$WORK/probe.c" -o "$WORK/probe" || {
    echo "Failed to compile the static test probe"
    exit 1
}

CONF="$WORK/phase4.conf"

cat > "$CONF" <<EOF
# Cerberus Phase 4 test policy
mode enforce
proc cat procsecret.txt
uid 0 uidsecret.txt
EOF


#
# Start the agent with the test config.
#
mkfifo "$FIFO"

"$AGENT" "$CONF" < "$FIFO" > "$LOG" 2>&1 &
AGENT_PID=$!

# Keep the FIFO open so the agent does not see EOF.
exec 9>"$FIFO"

sleep 1


#
# Process-scoped rule: only "cat" is denied.
#
out=$(cat "$WORK/procsecret.txt" 2>&1)
check "process rule blocks matching process" \
    "cat: $WORK/procsecret.txt: Operation not permitted" "$out"

out=$(grep . "$WORK/procsecret.txt" 2>&1)
check "process rule leaves other processes alone" \
    "proc secret" "$out"


#
# UID-scoped rule: every process running as root is denied.
#
out=$(cat "$WORK/uidsecret.txt" 2>&1)
check "uid rule blocks matching uid" \
    "cat: $WORK/uidsecret.txt: Operation not permitted" "$out"

out=$(head -1 "$WORK/uidsecret.txt" 2>&1)
check "uid rule applies regardless of process name" \
    "head: cannot open '$WORK/uidsecret.txt' for reading: Operation not permitted" "$out"


#
# Unrelated file must still be accessible.
#
out=$(cat "$WORK/other.txt" 2>&1)
check "unlisted file remains accessible" "other content" "$out"


#
# Runtime process rule via the CLI.
#
printf 'addproc head prochead.txt\n' >&9
sleep 0.3

head -1 "$WORK/prochead.txt" > /dev/null 2>&1
check "runtime process rule blocks" "1" "$?"


#
# Removing the uid rule restores access.
#
printf 'rmuid 0 uidsecret.txt\n' >&9
sleep 0.3

out=$(cat "$WORK/uidsecret.txt" 2>&1)
check "removed uid rule restores access" "uid secret" "$out"


#
# Sandbox mode: no allowlist entries means deny everything.
#
printf 'sandbox probe\n' >&9
sleep 0.3

"$WORK/probe" "$WORK/other.txt" > /dev/null 2>&1
check "sandbox denies unlisted access" "2" "$?"


#
# Add an allowlist entry and retry.
#
printf 'allow probe %s\n' "$WORK/allowed.txt" >&9
sleep 0.3

out=$("$WORK/probe" "$WORK/allowed.txt" 2>&1)
check "sandbox allows allowlisted access" "allowed content" "$out"

"$WORK/probe" "$WORK/other.txt" > /dev/null 2>&1
check "sandbox still denies other files" "2" "$?"


#
# Monitor mode: sandbox denial is reported, not enforced.
#
printf 'list\n' >&9
sleep 0.2

printf 'mode monitor\n' >&9
sleep 0.3

out=$("$WORK/probe" "$WORK/other.txt" 2>&1)
check "sandbox denial only reports in monitor mode" "other content" "$out"

printf 'mode enforce\n' >&9
sleep 0.3


#
# Disable the sandbox; access works again.
#
printf 'unsandbox probe\n' >&9
sleep 0.3

out=$("$WORK/probe" "$WORK/other.txt" 2>&1)
check "unsandbox restores access" "other content" "$out"


#
# Events reached user space in both modes.
#
contains "blocked alert reached user space" \
    "BLOCKED INTRUSION" "$LOG"

contains "monitor alert reached user space" \
    "MONITOR ALERT" "$LOG"

contains "sandbox default-deny event reported" \
    "sandbox default-deny" "$LOG"

contains "list shows sandboxed process" \
    "SANDBOX] probe" "$LOG"

contains "list shows process rule" \
    "proc cat" "$LOG"

contains "list shows uid rule" \
    "uid 0" "$LOG"


#
# Clean shutdown on SIGINT.
#
kill -INT "$AGENT_PID"
wait "$AGENT_PID" 2>/dev/null
AGENT_PID=""

contains "SIGINT performs clean shutdown" \
    "Cerberus stopped" "$LOG"


echo
echo "================================"
echo "PASS: $pass  FAIL: $fail"
echo "================================"

[ "$fail" -eq 0 ]
