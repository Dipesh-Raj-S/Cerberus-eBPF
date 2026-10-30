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
 * Destination IP rules for outgoing connections,
 * IPv4 keys in network byte order.
 *
 * Value is a presence marker; block and allow rules
 * live in separate maps so lookups decide precedence.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} net_block4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u8[16]);
    __type(value, __u8);
} net_block6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} net_allow4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u8[16]);
    __type(value, __u8);
} net_allow6 SEC(".maps");


/*
 * Network policy mode, separate from policy_mode so
 * file-access and network policies can operate in
 * different modes.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} net_mode SEC(".maps");


/*
 * Events sent from kernel space to the Cerberus
 * user-space agent.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


#endif /* CERBERUS_MAPS_BPF_H */
