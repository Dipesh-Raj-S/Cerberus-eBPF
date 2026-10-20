#!/usr/bin/env bash
#
# Cerberus interactive CLI test.
#
# Verifies:
#   - the "cerberus> " prompt appears immediately at startup
#   - a pasted batch of commands is fully processed
#   - enforcement works from batched CLI commands
#   - the prompt is redrawn after commands and alerts
#   - "quit" exits cleanly and releases the LSM hook
#
# Must run as root (BPF LSM).
#
# Usage:
#   sudo tests/test_cli.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AGENT=./build/cerberus_agent
FIFO=/tmp/cerberus_cli_fifo
LOG=/tmp/cerberus_cli.log
WORK=/tmp/cerberus_cli_dir

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

check_ge() {
    local desc="$1" min="$2" actual="$3"

    if [ "$actual" -ge "$min" ]; then
        echo "PASS: $desc"
        pass=$((pass + 1))
    else
        echo "FAIL: $desc (expected at least $min, got $actual)"
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

count_prompts() {
    grep -o 'cerberus> ' "$LOG" 2>/dev/null | wc -l | tr -d ' '
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

echo "cli secret" > "$WORK/secret.txt"

mkfifo "$FIFO"

"$AGENT" < "$FIFO" > "$LOG" 2>&1 &
AGENT_PID=$!

# Keep the FIFO open so the agent does not see EOF.
exec 9>"$FIFO"

sleep 1


#
# The prompt must be visible before any command is typed.
#
check_ge "prompt shown immediately at startup" 1 "$(count_prompts)"


#
# Paste two commands in a single write. Both must be
# processed even though only one read() delivers them.
#
printf 'addpath %s\nmode enforce\n' "$WORK/secret.txt" >&9
sleep 0.7

out=$(cat "$WORK/secret.txt" 2>&1)
check "batched CLI commands apply enforcement" \
    "cat: $WORK/secret.txt: Operation not permitted" "$out"

check_ge "prompt redrawn after each command" 3 "$(count_prompts)"


#
# Paste status and quit together; quit must still be
# reached after status is handled.
#
printf 'status\nquit\n' >&9

for _ in $(seq 1 40); do
    kill -0 "$AGENT_PID" 2>/dev/null || break
    sleep 0.25
done

if kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "FAIL: agent did not exit on batched quit"
    fail=$((fail + 1))
else
    echo "PASS: batched quit exits cleanly"
    pass=$((pass + 1))
fi

wait "$AGENT_PID" 2>/dev/null
AGENT_PID=""

contains "status output from batch is complete" \
    "Mode: ENFORCE" "$LOG"

contains "blocked alert reached user space" \
    "BLOCKED INTRUSION" "$LOG"

contains "shutdown summary printed" \
    "Cerberus stopped" "$LOG"


#
# The LSM hook must be fully released after quit.
#
out=$(cat "$WORK/secret.txt" 2>&1)
check "access restored after quit" "cli secret" "$out"


echo
echo "================================"
echo "PASS: $pass  FAIL: $fail"
echo "================================"

[ "$fail" -eq 0 ]
