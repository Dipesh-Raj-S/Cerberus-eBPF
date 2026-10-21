/*
 * Cerberus BPF map definitions.
 *
 * All maps live in this single header, which is
 * included exactly once by the ips_core translation
 * unit. This keeps every hook program sharing the
 * same maps without map-in-map or pinning tricks.
 */
#ifndef CERBERUS_MAPS_BPF_H
#define CERBERUS_MAPS_BPF_H


/*
 * Global rule table.
 *
 * Key layouts (see cerberus/common.h):
 *
 *   NAME rule:
 *       "sensitive.txt"
 *
 *   PATH rule:
 *       "tmp" + '/' + "sensitive.txt"
 *
 * Value:
 *       struct rule_value { type }
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[256]);
    __type(value, struct rule_value);
} blocklist SEC(".maps");


/*
 * Scoped rule table.
 *
 * Process rule:  comm = "bash",  uid = CERBERUS_UID_ANY
 * UID rule:      comm = "",      uid = 1000
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct scoped_rule_key);
    __type(value, struct rule_value);
} scoped_rules SEC(".maps");


/*
 * Allowlist entries for sandboxed processes.
 *
 * Same key shape as scoped_rules, but the uid
 * field is always CERBERUS_UID_ANY.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct scoped_rule_key);
    __type(value, __u8);
} allowlist SEC(".maps");


/*
 * Processes running in allowlist (sandbox) mode.
 *
 * If a process is present here, every file open
 * it performs must match an allowlist entry.
 * An empty allowlist therefore denies all opens.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, __u8);
} sandboxed SEC(".maps");


/*
 * Global policy mode.
 *
 *   CERBERUS_MODE_MONITOR  -> report only
 *   CERBERUS_MODE_ENFORCE  -> report and deny with -EPERM
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} policy_mode SEC(".maps");


/*
 * ============================================================
 *  Network security maps (Phase 5)
 * ============================================================
 */

/*
 * Global network policy mode.
 *
 *   CERBERUS_NET_MODE_MONITOR   -> report only    (default)
 *   CERBERUS_NET_MODE_ENFORCE   -> deny rule matches
 *   CERBERUS_NET_MODE_DENY_ALL  -> default-deny,
 *                                  allow rules open holes
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} net_policy_mode SEC(".maps");

/*
 * Runtime network flag bits (CERBERUS_NETF_*).
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} net_flags SEC(".maps");

/*
 * Explicit IP rules. Checked first by the connect hook;
 * never expire.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct net_addr);
    __type(value, struct net_ip_rule);
} net_ip_rules SEC(".maps");

/*
 * DNS-derived per-address decisions.
 *
 * The agent fills this map when a DNS answer associates
 * an address with a domain (with the answer TTL as
 * expiry), and rewrites it whenever domain rules change.
 * The connect hook treats entries past their expiry as
 * absent.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct net_addr);
    __type(value, struct net_ip_decision);
} net_ip_decisions SEC(".maps");

/*
 * Per-PID connect-event rate limiting state. Connections
 * are always enforced; when the per-second threshold is
 * exceeded, only the ring-buffer emission is suppressed.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct net_rate);
} net_rate SEC(".maps");

/*
 * Recent process executions (keyed by PID), maintained by
 * the bprm_creds_for_exec hook and consulted by the
 * connect hook for reverse-shell correlation.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct exec_recent);
} exec_recent SEC(".maps");

/*
 * Process names (comm) whose unmapped connections may be
 * denied when BLOCK_SUSPICIOUS is enabled and the mode is
 * not MONITOR. Written by the agent.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, __u8);
} shell_block SEC(".maps");


/*
 * Events sent from kernel space to the Cerberus
 * user-space agent. Enlarged to absorb DNS packet
 * capture events.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} rb SEC(".maps");


#endif /* CERBERUS_MAPS_BPF_H */
