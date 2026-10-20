#!/usr/bin/env bash
#
# Cerberus Phase 3.5 integration test.
#
# Verifies:
#   - config file loading (name + path rules, mode directive)
#   - ENFORCE mode denies with EPERM
#   - MONITOR mode reports without denying
#   - runtime CLI rule creation
#   - ring buffer alerts for both modes
#   - clean shutdown on SIGINT
#
# Must run as root (BPF LSM).
#
# Usage:
#   sudo tests/test_phase35.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AGENT=./build/cerberus_agent
FIFO=/tmp/cerberus_test_fifo
LOG=/tmp/cerberus_test.log
WORK=/tmp/cerberus_test_dir

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

echo "top secret" > "$WORK/secret.txt"
echo "autoloaded secret" > "$WORK/autoloaded.txt"
echo "cli secret" > "$WORK/fromcli.txt"

CONF="$WORK/cerberus.conf"

cat > "$CONF" <<EOF
# Cerberus test policy
mode enforce
name autoloaded.txt
path $WORK/secret.txt
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
# ENFORCE mode: config rules must deny access.
#
out=$(cat "$WORK/secret.txt" 2>&1)
check "path rule blocks in enforce mode" \
    "cat: $WORK/secret.txt: Operation not permitted" "$out"

out=$(cat "$WORK/autoloaded.txt" 2>&1)
check "config name rule blocks in enforce mode" \
    "cat: $WORK/autoloaded.txt: Operation not permitted" "$out"

out=$(cat "$WORK/fromcli.txt" 2>&1)
check "unlisted file is not blocked" "cli secret" "$out"


#
# MONITOR mode: the same access must succeed but be reported.
#
printf 'mode monitor\n' >&9
sleep 0.3

out=$(cat "$WORK/secret.txt" 2>&1)
check "path rule only reports in monitor mode" "top secret" "$out"


#
# Runtime CLI rule creation while in ENFORCE mode.
#
printf 'add fromcli.txt\n' >&9
sleep 0.3

printf 'mode enforce\n' >&9
sleep 0.3

out=$(cat "$WORK/fromcli.txt" 2>&1)
check "CLI name rule blocks in enforce mode" \
    "cat: $WORK/fromcli.txt: Operation not permitted" "$out"


#
# Remove the CLI rule; access must work again.
#
printf 'remove fromcli.txt\n' >&9
sleep 0.3

out=$(cat "$WORK/fromcli.txt" 2>&1)
check "removed rule no longer blocks" "cli secret" "$out"


#
# Ring buffer must have reported both blocked and monitor events.
#
contains "blocked alert reached user space" \
    "BLOCKED INTRUSION" "$LOG"

contains "monitor alert reached user space" \
    "MONITOR ALERT" "$LOG"


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
