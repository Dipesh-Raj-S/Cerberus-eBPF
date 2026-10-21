#!/usr/bin/env bash
#
# Cerberus Phase 5 integration test.
#
# Verifies:
#   - network connection monitoring (LSM socket_connect)
#   - reverse-shell heuristic alerts (report-only)
#   - explicit IP rules, monitor and enforce behavior
#   - DNS-capture-driven domain rules, subdomain matching,
#     TTL expiry and refresh
#   - no collateral blocking on shared IPs
#   - allow rules
#   - default-deny (deny-all) with its exemptions
#   - port-53 exemption on/off
#   - kernel-side suspicious blocking (opt-in)
#   - event rate limiting
#   - config-file network directives
#   - file-access rules still work while network
#     protection is active
#
# Must run as root (BPF LSM + TC attach).
#
# Creates its own network namespace and veth pair, a
# dnsmasq instance and socat listeners inside that
# fixture; everything is torn down at exit. No system-wide
# DNS/firewall settings are touched.
#
# Usage:
#   sudo tests/test_phase5.sh

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AGENT=./build/cerberus_agent
FIFO=/tmp/cerberus_p5_fifo
LOG=/tmp/cerberus_p5.log
WORK=/tmp/cerberus_p5_work

NS=cerberus_p5
VETH_HOST=cp5h
VETH_NS=cp5n
NET_IP=10.200.0.1
NS_IP=10.200.0.2

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

# ---------------------------------------------------------------
# Connection probes from inside the test namespace.
#
# python3 prints the connect() errno: "0" on success,
# "1" for EPERM (Cerberus denied), "111" for connection
# refused, etc.
# ---------------------------------------------------------------
nsconnect() {
    ip netns exec "$NS" python3 -c '
import socket, sys

ip = sys.argv[1]
port = int(sys.argv[2])

s = socket.socket()
s.settimeout(3)

try:
    s.connect((ip, port))
    print("0")
except OSError as e:
    print(e.errno if e.errno else 1)
' "$1" "$2"
}

dump_diagnostics() {
    echo
    echo "--- agent log tail ($LOG) ---"

    tail -n 60 "$LOG" 2>/dev/null || echo "(no log)"

    echo "--- fixture listeners ---"

    ss -ltn 2>/dev/null \
        | grep -E ':(53|9990|9991|9992|9993|9994)\b' \
        || echo "(none found)"

    echo "--- fixture processes ---"

    pgrep -a -f "TCP-LISTEN" 2>/dev/null \
        || echo "(no socat listeners alive)"
    pgrep -a -f "cerberus_p5_work" 2>/dev/null \
        || echo "(dnsmasq not alive)"

    echo "--- end diagnostics ---"
}

cleanup() {
    exec 9>&- 2>/dev/null || true

    if [ -n "${AGENT_PID:-}" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        printf 'quit\n' >&9 2>/dev/null || true
        kill -INT "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi

    pkill -f "cerberus_p5_dnsmasq" 2>/dev/null || true
    pkill -f "cerberus_p5_socat" 2>/dev/null || true
    for p in "${SOCAT_PIDS[@]:-}"; do
        kill "$p" 2>/dev/null || true
    done
    [ -n "${DNSMASQ_PID:-}" ] && kill "$DNSMASQ_PID" 2>/dev/null || true

    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true

    #
    # Preserve the agent log when the run failed so the
    # failure is diagnosable afterwards; clean it up on
    # success.
    #
    if [ "${fail:-0}" -gt 0 ]; then
        dump_diagnostics
    else
        rm -rf "$WORK" "$FIFO" "$LOG"
    fi
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

for tool in ip dnsmasq dig socat python3; do
    if ! command -v "$tool" >/dev/null; then
        echo "Missing tool: $tool"
        exit 1
    fi
done

rm -rf "$WORK" "$FIFO" "$LOG"
mkdir -p "$WORK"


# ---------------------------------------------------------------
# Network fixture. The veth pair is created BEFORE the agent
# starts, because TC attachments happen at startup for every
# interface that is up at that moment.
# ---------------------------------------------------------------
ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip addr add "$NET_IP/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip link set "$VETH_NS" netns "$NS"
ip -n "$NS" addr add "$NS_IP/24" dev "$VETH_NS"
ip -n "$NS" link set "$VETH_NS" up
ip -n "$NS" link set lo up
ip -n "$NS" route add default via "$NET_IP" 2>/dev/null || true

echo "playground" > "$WORK/readme.txt"

#
# Reachable TCP listeners on the host end of the veth.
#
# socat needs TWO addresses: the listening socket and a
# per-connection target. PIPE is a sink that accepts and
# discards; without it socat exits with
# "exactly 2 addresses required" and every fixture connect
# fails with ECONNREFUSED.
#
start_socat() {
    socat "TCP-LISTEN:$2,bind=$1,reuseaddr,fork" PIPE \
        </dev/null >/dev/null 2>&1 &
    SOCAT_PIDS+=($!)

    #
    # A listener that silently failed to bind poisons every
    # later check with unrelated ECONNREFUSED; verify it up
    # from the host side and say so if it is not.
    #
    local i

    for i in $(seq 1 20); do
        if timeout 1 bash -c "exec 3<>/dev/tcp/$1/$2" \
            2>/dev/null; then
            return 0
        fi

        sleep 0.25
    done

    echo "WARN: listener $1:$2 did not come up"
}

SOCAT_PIDS=()

#
# Secondary addresses so that rule-target IPs connect
# successfully when they are supposed to be allowed.
#
ip addr add 10.200.0.56/32 dev "$VETH_HOST"
ip addr add 10.200.0.57/32 dev "$VETH_HOST"
ip addr add 10.200.0.99/32 dev "$VETH_HOST"

start_socat "$NET_IP" 9990
start_socat "$NET_IP" 9991
start_socat "$NET_IP" 9992
start_socat "$NET_IP" 9994
start_socat 10.200.0.56 9993
start_socat 10.200.0.56 9994
start_socat 10.200.0.57 9993

#
# dnsmasq serving static records with a short TTL. Bound to
# the veth only; no system DNS settings are touched.
#
DNSCONF="$WORK/dnsmasq.conf"
cat > "$DNSCONF" <<EOF
port=53
no-resolv
no-hosts
bind-interfaces
interface=$VETH_HOST
local-ttl=2
neg-ttl=2
log-queries=extra
host-record=a.blocked.test,10.200.0.57
host-record=mail.blocked.test,10.200.0.57
host-record=allowed.test,10.200.0.56
host-record=ok.test,10.200.0.56
EOF

dnsmasq --no-daemon --conf-file="$DNSCONF" \
    --pid-file="$WORK/dnsmasq.pid" \
    --log-facility="$WORK/dnsmasq.log" &
DNSMASQ_PID=$!

#
# Wait until the resolver actually answers from the veth
# address; DNS checks below fail confusingly without this.
#
for _ in $(seq 1 20); do
    if [ "$(dig +short +time=1 +tries=1 @"$NET_IP" \
        a.blocked.test A 2>/dev/null)" = "10.200.0.57" ]; then
        break
    fi

    sleep 0.25
done

sleep 1

nsdigs() {
    ip netns exec "$NS" dig +short +time=2 +tries=1 @"$NET_IP" "$1" A
}


# ---------------------------------------------------------------
# Start the agent, empty config: monitor mode everywhere.
# ---------------------------------------------------------------
mkfifo "$FIFO"

"$AGENT" /dev/null < "$FIFO" > "$LOG" 2>&1 &
AGENT_PID=$!
exec 9>"$FIFO"

sleep 2


# ---------------------------------------------------------------
# 1. Monitor mode
#
# nc is not in the watch list: plain monitor events.
# ---------------------------------------------------------------
out=$(nsconnect "$NET_IP" 9990)
sleep 1
contains "outgoing connection is monitored" "NET MONITOR" "$LOG"
contains "monitor event shows destination" "10.200.0.1:9990" "$LOG"
check "unblocked connect succeeds in monitor mode" "0" "$out"

out=$(nsconnect "$NET_IP" 9991)
sleep 1
check "second connect still reaches listener" "0" "$out"


# ---------------------------------------------------------------
# 2. Reverse-shell heuristic, report-only
#
# bash IS in the default watch list.
# ---------------------------------------------------------------
ip netns exec "$NS" bash -c "exec 3<>/dev/tcp/$NET_IP/9992" 2>/dev/null
sleep 1
contains "suspicious alert fires for shell process" "NET SUSPICIOUS" "$LOG"
contains "alert cites shell-process evidence" "shell-process" "$LOG"
contains "alert cites unmapped destination" "unmapped-destination" "$LOG"
out=$(nsconnect "$NET_IP" 9992)
check "heuristic stays report-only by default" "0" "$out"


# ---------------------------------------------------------------
# 3. Explicit IP rules, enforced
#
# ---------------------------------------------------------------
printf 'network-mode enforce\nblock-ip 10.200.0.1\n' >&9
sleep 1

out=$(nsconnect "$NET_IP" 9991)
check "block-ip denies connect with EPERM" "1" "$out"
sleep 1
contains "blocked event shows block-ip rule" "block-ip 10.200.0.1" "$LOG"

printf 'unblock-ip 10.200.0.1\n' >&9
sleep 1

out=$(nsconnect "$NET_IP" 9991)
check "unblock-ip restores connectivity" "0" "$out"


# ---------------------------------------------------------------
# 4. Domain rules from live DNS capture
#
# The dig creates the kernel association; the block rule is
# added afterwards and swept into the existing entry.
# ---------------------------------------------------------------
nsdigs a.blocked.test >/dev/null
nsdigs allowed.test >/dev/null
sleep 2

printf 'network-mode enforce\nblock-domain blocked.test\n' >&9
sleep 1

out=$(nsconnect 10.200.0.57 9993)
check "blocked domain denies its address" "1" "$out"
sleep 1
contains "blocked event names the domain rule" "block-domain blocked.test" "$LOG"
contains "blocked event shows DNS association" "via: a.blocked.test" "$LOG"

#
# Subdomain matching: mail.blocked.test shares the address
# and is covered by the parent-domain rule.
#
nsdigs mail.blocked.test >/dev/null
sleep 1

out=$(nsconnect 10.200.0.57 9993)
check "subdomain of blocked domain is denied" "1" "$out"

#
# No collateral damage: allowed.test maps to a different
# address that stays unmapped-rule-wise.
#
out=$(nsconnect 10.200.0.56 9994)
check "unrelated domain on its own address is allowed" "0" "$out"

#
# allow-domain cannot overcome a block rule (deny wins),
# but removing the block restores the allow rule's effect.
#
printf 'allow-domain blocked.test\n' >&9
sleep 1

out=$(nsconnect 10.200.0.57 9993)
check "deny beats allow on the same domain" "1" "$out"

printf 'unblock-domain blocked.test\n' >&9
sleep 1

out=$(nsconnect 10.200.0.57 9993)
check "allow-domain opens the address after unblock" "0" "$out"

printf 'remove-allow-domain blocked.test\n' >&9
sleep 1


# ---------------------------------------------------------------
# 5. TTL expiry and refresh
#
# dnsmasq answers with local-ttl=2; the association lapses
# and the address becomes unmapped (allowed in enforce).
# ---------------------------------------------------------------
printf 'block-domain blocked.test\n' >&9
sleep 1

nsdigs a.blocked.test >/dev/null
sleep 1

out=$(nsconnect 10.200.0.57 9993)
check "fresh association is enforced" "1" "$out"

sleep 6   # TTL(2s) + agent purge period(5s)

out=$(nsconnect 10.200.0.57 9993)
check "expired association lapses to unmapped" "0" "$out"

nsdigs a.blocked.test >/dev/null
sleep 1

out=$(nsconnect 10.200.0.57 9993)
check "re-resolved association enforces again" "1" "$out"

printf 'unblock-domain blocked.test\n' >&9
sleep 1


# ---------------------------------------------------------------
# 6. Default-deny (opt-in, two-step confirmation)
#
# ---------------------------------------------------------------
printf 'network-mode deny-all\n' >&9
sleep 0.5
contains "deny-all asks for confirmation" "deny-all confirm" "$LOG"

out=$(nsconnect "$NET_IP" 9994)
check "deny-all stays off without confirmation" "0" "$out"

printf 'network-mode deny-all confirm\n' >&9
sleep 1

out=$(nsconnect "$NET_IP" 9994)
check "deny-all denies unmapped destination" "1" "$out"
sleep 1
contains "default-deny event explains itself" "default-deny" "$LOG"

printf 'allow-ip 10.200.0.1\n' >&9
sleep 1

out=$(nsconnect "$NET_IP" 9994)
check "allow-ip pokes a hole in deny-all" "0" "$out"

nsdigs allowed.test >/dev/null
sleep 1

out=$(nsconnect 10.200.0.56 9994)
check "mapped allow-domain works in deny-all" "1" "$out"

printf 'allow-domain allowed.test\n' >&9
sleep 1

out=$(nsconnect 10.200.0.56 9994)
check "domain allow rule works in deny-all" "0" "$out"

printf 'remove-allow-domain allowed.test\n' >&9
sleep 1

#
# Loopback stays exempt: connecting to a closed loopback
# port gives ECONNREFUSED (111), never EPERM (1).
#
out=$(ip netns exec "$NS" python3 -c '
import socket
s = socket.socket()
s.settimeout(2)
try:
    s.connect(("127.0.0.1", 9))
    print("0")
except OSError as e:
    print(e.errno if e.errno else 1)
')
check "loopback exempt from deny-all" "111" "$out"

# ---------------------------------------------------------------
# 7. Port-53 exemption in deny-all
#
# denied loopback connect was ECONNREFUSED above; here the
# DNAT-free path to the resolver must be allowed.
# ---------------------------------------------------------------
out=$(nsconnect "$NET_IP" 53)
check "port-53 exemption keeps DNS reachable" "0" "$out"

printf 'net-dns-port off\n' >&9
sleep 1

out=$(nsconnect "$NET_IP" 53)
check "net-dns-port off closes the exemption" "1" "$out"

printf 'net-dns-port on\n' >&9

out=$(nsconnect "$NET_IP" 53)
check "port-53 exemption returns" "0" "$out"

printf 'allow-ip 10.200.0.1\nunallow-ip 10.200.0.1\nnetwork-mode enforce\n' >&9
sleep 1


# ---------------------------------------------------------------
# 8. Kernel-side suspicious blocking (opt-in)
#
# ---------------------------------------------------------------
printf 'add-shellwatch probe\nnetwork-mode enforce\nblock-suspicious on\n' >&9
sleep 1

#
# bash to an unmapped destination: watch-list hit + EPERM.
#
ip netns exec "$NS" bash -c "exec 3<>/dev/tcp/10.200.0.99/4444" 2>/dev/null
sleep 1
contains "kernel blocks suspicious shell connection" "SUSPICIOUS BLOCKED" "$LOG"
contains "suspicious block is explained" "net-block-suspicious" "$LOG"

printf 'block-suspicious off\n' >&9
sleep 1

out=$(nsconnect "$NET_IP" 9994)
check "block-suspicious off stops kernel denials" "0" "$out"

printf 'rm-shellwatch probe\n' >&9
sleep 0.5


# ---------------------------------------------------------------
# 9. Event rate limiting
#
# 200 rapid connects from one process exceed the 64/s
# threshold; after the burst the same process connects once
# more, and that event must report the suppressed count.
# Enforcement is unaffected (all connects still set up).
# ---------------------------------------------------------------
ip netns exec "$NS" python3 -c '
import socket, time

ip = "10.200.0.1"
port = 9990

ok = 0

for i in range(200):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((ip, port))
        s.close()
        ok += 1
    except OSError:
        pass

time.sleep(1.5)

s = socket.socket()
s.settimeout(1)
s.connect((ip, port))
s.close()

print("burst-ok", ok)
'
sleep 2
contains "rate limiting suppresses event flood" "suppressed by rate limit" "$LOG"


# ---------------------------------------------------------------
# 10. Config-file network directives
#
# A second agent run loads a file policy alongside network
# directives; both must act.
# ---------------------------------------------------------------
printf 'quit\n' >&9
sleep 2

CONF="$WORK/p5.conf"
cat > "$CONF" <<EOF
# file policy
mode enforce
name secret.txt

# network policy
net-mode enforce
block-ip 10.200.0.1
add-shellwatch sneaky
net-dns-port on
EOF

rm -f "$LOG" "$FIFO"
mkfifo "$FIFO"

"$AGENT" "$CONF" < "$FIFO" > "$LOG" 2>&1 &
AGENT_PID=$!
exec 9>"$FIFO"

sleep 2

out=$(nsconnect "$NET_IP" 9994)
check "config block-ip denies" "1" "$out"

out=$(cat "$WORK/readme.txt" 2>&1)
check "config file rule denies" \
    "cat: $WORK/readme.txt: Operation not permitted" "$out"

printf 'quit\n' >&9
sleep 2


echo
echo "---------------------------------------"
echo "Phase 5: pass=$pass fail=$fail"
echo "---------------------------------------"

[ "$fail" -eq 0 ]
