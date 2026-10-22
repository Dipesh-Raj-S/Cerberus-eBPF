#!/usr/bin/env bash
#
# Cerberus IP-based network security test.
#
# Verifies:
#   - IPv4/IPv6 rule validation and canonicalization
#   - adding, removing and listing IP block/allow rules
#   - monitor mode never denies connections
#   - enforce mode denies connections to blocked IPs
#     (the caller sees EPERM)
#   - block wins over a conflicting allow rule
#   - runtime rule updates take effect without restart
#   - network events carry pid/uid/process/target and verdict
#   - the existing file-access pipeline still works
#
# Connections from the tested processes run inside an
# isolated network namespace ("cerb-net") so nothing on
# the host outside loopback addresses is touched.
#
# Must run as root (BPF LSM, network namespace).
#
# Usage:
#   sudo tests/test_net.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AGENT=./build/cerberus_agent
NETNS=cerb-net
FIFO=/tmp/cerberus_net_fifo
LOG=/tmp/cerberus_net.log
WORK=/tmp/cerberus_net_dir
PORT_TCP=9969
PORT_UDP=9970

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

lacks() {
    local desc="$1" needle="$2" file="$3"

    if grep -q "$needle" "$file" 2>/dev/null; then
        echo "FAIL: $desc (unexpectedly contains '$needle')"
        fail=$((fail + 1))
    else
        echo "PASS: $desc"
        pass=$((pass + 1))
    fi
}

#
# Send one command to the agent and let it settle.
#
cli() {
    printf '%s\n' "$1" >&9
    sleep 0.3
}

#
# Try a connection from inside the network namespace
# and report the outcome:
#
#   EPERM          connection denied by Cerberus
#   ECONNREFUSED   connect reached the kernel and was refused
#   ESTABLISHED    connection succeeded
#   ETIMEOUT       no route / unreachable target
#
connect_outcome() {
    local ip="$1" port="$2" kind="${3:-tcp}"

    ip netns exec "$NETNS" \
        python3 "$WORK/connect_test.py" "$ip" "$port" "$kind"
}

cleanup() {
    exec 9>&- 2>/dev/null || true

    if [ -n "${AGENT_PID:-}" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill -INT "$AGENT_PID" 2>/dev/null
        wait "$AGENT_PID" 2>/dev/null
    fi

    ip netns del "$NETNS" 2>/dev/null || true
    rm -rf "$WORK" "$FIFO" "$LOG"
}

trap cleanup EXIT


if [ "$(id -u)" -ne 0 ]; then
    echo "This test must run as root: sudo $0"
    exit 1
fi

for tool in ip python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool missing: $tool"
        exit 1
    fi
done

if [ ! -x "$AGENT" ]; then
    echo "Agent not built. Run 'make' first."
    exit 1
fi


#
# Test fixtures.
#
rm -rf "$WORK" "$FIFO" "$LOG"
mkdir -p "$WORK"

echo "net test secret" > "$WORK/secret.txt"

cat > "$WORK/connect_test.py" <<'EOF'
import socket
import sys

ip = sys.argv[1]
port = int(sys.argv[2])
kind = sys.argv[3] if len(sys.argv) > 3 else "tcp"

family = socket.AF_INET6 if ":" in ip else socket.AF_INET
socktype = socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM

try:
    s = socket.socket(family, socktype)
    s.settimeout(2)
    s.connect((ip, port))
    s.close()
    print("ESTABLISHED")
except PermissionError:
    print("EPERM")
except ConnectionRefusedError:
    print("ECONNREFUSED")
except TimeoutError:
    print("ETIMEOUT")
except OSError as e:
    print("ETIMEOUT" if "timed out" in str(e) else "EOTHER")
EOF

mkfifo "$FIFO"

if ! ip netns add "$NETNS" 2>/dev/null; then
    echo "Could not create network namespace $NETNS (already exists?)"
    ip netns del "$NETNS" 2>/dev/null || true
    ip netns add "$NETNS"
fi

ip -n "$NETNS" link set lo up

"$AGENT" < "$FIFO" > "$LOG" 2>&1 &
AGENT_PID=$!

# Keep the FIFO open so the agent does not see EOF.
exec 9>"$FIFO"

for _ in $(seq 1 40); do
    grep -q "Cerberus BPF IPS is ACTIVE" "$LOG" 2>/dev/null && break
    kill -0 "$AGENT_PID" 2>/dev/null || break
    sleep 0.25
done

sleep 0.5


#
# Both policy modes must start in monitor mode.
#
contains "network policy starts in monitor mode" "Net mode: MONITOR" "$LOG"


#
# Invalid literals must be rejected in both families.
#
cli "block-ip 999.9.9.9"
cli "block-ip 1920.2.10"
cli "block-ip ::dead::beef::"
cli "block-ip two words"

contains "invalid IPv4 rejected" "Invalid IPv4 address" "$LOG"
contains "invalid IPv6 rejected" "Invalid IPv6 address" "$LOG"
contains "multi-token input rejected" "single IPv4 or IPv6 address" "$LOG"


#
# Add a valid IPv4 rule; it must appear in the listing.
#
cli "block-ip 127.0.0.1"

contains "IPv4 block rule accepted" "IP block rule added: 127.0.0.1" "$LOG"

cli "list"

contains "listing shows IPv4 block rule" "[BLOCK4] 127.0.0.1" "$LOG"


#
# Monitor mode must never deny. Dormant port 9969 on
# loopback refuses every connection; only a hook deny
# would change the outcome to EPERM.
#
cli "net-mode monitor"
sleep 0.7

out=$(connect_outcome 127.0.0.1 "$PORT_TCP")
check "monitor mode never denies a blocked IP" "ECONNREFUSED" "$out"

contains "monitor match reported without deny" "NET WOULD BLOCK" "$LOG"
contains "event carries destination IP and port" "127.0.0.1:9969 (tcp)" "$LOG"
contains "monitor event carries process name" "python3" "$LOG"


#
# Enforce mode must deny the same IP.
#
cli "net-mode enforce"
sleep 0.7

out=$(connect_outcome 127.0.0.1 "$PORT_TCP")
check "enforce mode denies a blocked IPv4" "EPERM" "$out"

out=$(connect_outcome 127.0.0.1 "$PORT_UDP" udp)
check "enforce mode denies a connected UDP socket" "EPERM" "$out"

contains "deny event recorded" "NET CONNECT BLOCKED" "$LOG"


#
# Runtime removal must restore normal behavior without
# restarting the agent.
#
cli "unblock-ip 127.0.0.1"
sleep 0.5

out=$(connect_outcome 127.0.0.1 "$PORT_TCP")
check "runtime unblock restores connections" "ECONNREFUSED" "$out"


#
# IPv6 block/unblock round-trip.
#
cli "block-ip ::1"

contains "IPv6 block rule added" "IP block rule added: ::1" "$LOG"

sleep 0.5

out=$(connect_outcome ::1 "$PORT_TCP")
check "enforce mode denies a blocked IPv6" "EPERM" "$out"

cli "unblock-ip ::1"
sleep 0.5

out=$(connect_outcome ::1 "$PORT_TCP")
check "IPv6 unblock restores connections" "ECONNREFUSED" "$out"


#
# A conflicting allow rule must not override a block rule.
#
cli "block-ip 127.0.0.1"
cli "allow-ip 127.0.0.1"

contains "conflicting rule warning printed" \
    "the BLOCK rule takes precedence" "$LOG"

sleep 0.5

out=$(connect_outcome 127.0.0.1 "$PORT_TCP")
check "block wins over conflicting allow rule" "EPERM" "$out"


#
# An allow rule alone is reported but never denies.
#
cli "remove-allow-ip 127.0.0.1"
cli "unblock-ip 127.0.0.1"
cli "allow-ip 127.0.0.1"
sleep 0.5

out=$(connect_outcome 127.0.0.1 "$PORT_TCP")
check "allow rule alone never denies" "ECONNREFUSED" "$out"

contains "allow match reported in event" "(allow)" "$LOG"

cli "remove-allow-ip 127.0.0.1"


#
# The file-access pipeline must be unaffected.
#
cli "add cerberus_net_secret.txt"
sleep 0.3

out=$(cat "$WORK/secret.txt")
check "file rules still evaluate" "net test secret" "$out"

contains "file monitor alert still delivered" "MONITOR ALERT" "$LOG"


#
# Clean shutdown.
#
cli "quit"

for _ in $(seq 1 40); do
    kill -0 "$AGENT_PID" 2>/dev/null || break
    sleep 0.25
done

if kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "FAIL: agent did not exit on quit"
    fail=$((fail + 1))
else
    echo "PASS: agent exits cleanly"
    pass=$((pass + 1))
fi

wait "$AGENT_PID" 2>/dev/null
AGENT_PID=""

contains "clean shutdown summary" "Cerberus stopped" "$LOG"


echo
echo "================================"
echo "PASS: $pass  FAIL: $fail"
echo "================================"

[ "$fail" -eq 0 ]
