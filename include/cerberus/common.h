#ifndef CERBERUS_COMMON_H
#define CERBERUS_COMMON_H

/*
 * Global policy modes, stored in the policy_mode map.
 *
 *   CERBERUS_MODE_MONITOR
 *       Suspicious accesses are reported but never denied.
 *
 *   CERBERUS_MODE_ENFORCE
 *       Suspicious accesses are reported and denied with -EPERM.
 */
#define CERBERUS_MODE_MONITOR 0
#define CERBERUS_MODE_ENFORCE 1


/*
 * Rule types, stored in blocklist map values.
 *
 *   CERBERUS_RULE_NAME
 *       Key is a plain file name: "sensitive.txt".
 *
 *   CERBERUS_RULE_PATH
 *       Key is a fixed layout:
 *
 *           [0 .. 63]   parent directory name ("tmp")
 *           [64]        '/'
 *           [65 .. 255] file name ("sensitive.txt")
 *
 * File names can never contain '/', so the two
 * layouts can never collide inside the same map.
 */
#define CERBERUS_RULE_NAME 1
#define CERBERUS_RULE_PATH 2
#define CERBERUS_RULE_SANDBOX 3

#define CERBERUS_PATH_SLOT 64

/*
 * Wildcard UID for process-scoped rules.
 */
#define CERBERUS_UID_ANY 0xFFFFFFFFu


/*
 * Key for scoped deny rules and allowlist entries.
 *
 *   Process rule:  comm = "bash",  uid = CERBERUS_UID_ANY
 *   UID rule:      comm = "",      uid = 1000
 *   Allow entry:   comm = "bash",  uid = CERBERUS_UID_ANY
 *
 * "rule" holds a NAME or PATH rule key.
 */
struct scoped_rule_key {
    char comm[16];
    unsigned int uid;
    char rule[256];
};


/*
 * Event types sent through the ring buffer.
 *
 * Every ring-buffer record starts with the same 12-byte
 * prefix (pid, uid, denied, rule_type, evt_type, flags/reserved),
 * so a consumer can identify the record type at a fixed
 * offset regardless of which structure it belongs to.
 */
#define CERBERUS_EVT_FILE_OPEN 1
#define CERBERUS_EVT_NET_CONNECT 2
#define CERBERUS_EVT_DNS_RESPONSE 3


/*
 * Value stored in the blocklist hash map.
 */
struct rule_value {
    unsigned char type; /* CERBERUS_RULE_* */
};


/*
 * Event structure shared between:
 *
 *   - the eBPF kernel program
 *   - the user-space Cerberus agent
 *
 * Both sides must interpret this structure
 * in exactly the same way.
 */
struct event {
    unsigned int pid;
    unsigned int uid;
    unsigned char denied;    /* 1 = blocked, 0 = monitor-only */
    unsigned char rule_type; /* CERBERUS_RULE_* */
    unsigned char evt_type;  /* CERBERUS_EVT_* */
    unsigned char reserved;
    char comm[16];
    char rule[256];          /* matched rule key (slot layout for path rules) */
};


/*
 * ============================================================
 *  Network security (Phase 5)
 * ============================================================
 */

/*
 * Network policy modes, stored in the net_policy_mode map.
 * Fully independent of the file-access policy modes above.
 *
 *   CERBERUS_NET_MODE_MONITOR
 *       Outgoing connections are reported, never denied.
 *
 *   CERBERUS_NET_MODE_ENFORCE
 *       Connections matching a deny rule are denied
 *       (connect() fails with -EPERM); everything else
 *       is allowed and reported. Destinations without
 *       any domain information are allowed and logged.
 *
 *   CERBERUS_NET_MODE_DENY_ALL
 *       Opt-in default-deny: outgoing connections are
 *       denied unless an explicit allow rule permits
 *       them. Never enabled automatically.
 */
#define CERBERUS_NET_MODE_MONITOR 0
#define CERBERUS_NET_MODE_ENFORCE 1
#define CERBERUS_NET_MODE_DENY_ALL 2

/*
 * Runtime flag bits stored in the net_flags array map.
 *
 *   ALLOW_DNS_PORT
 *       In DENY_ALL mode, destination port 53 is exempt
 *       so that DNS resolution keeps working.
 *       Default: on. Documented DNS-tunneling trade-off.
 *
 *   BLOCK_SUSPICIOUS
 *       Authorizes the kernel to deny connections from
 *       watched shell processes to destinations without
 *       domain information (coarse reverse-shell
 *       heuristic). Default: off.
 */
#define CERBERUS_NETF_ALLOW_DNS_PORT 0x01
#define CERBERUS_NETF_BLOCK_SUSPICIOUS 0x02

/*
 * Rule types reported in network events.
 */
#define CERBERUS_NET_RULE_NONE 0
#define CERBERUS_NET_RULE_DOMAIN_BLOCK 1
#define CERBERUS_NET_RULE_DOMAIN_ALLOW 2
#define CERBERUS_NET_RULE_IP_BLOCK 3
#define CERBERUS_NET_RULE_IP_ALLOW 4
#define CERBERUS_NET_RULE_SUSPICIOUS 5

/*
 * Rule verdicts as recorded in the BPF maps.
 */
#define CERBERUS_NET_VERDICT_ALLOW 1
#define CERBERUS_NET_VERDICT_DENY 2
#define CERBERUS_NET_VERDICT_NONE 0   /* domain decision: nothing matched */

/*
 * Address family and protocol constants.
 *
 * Defined here so the BPF side does not depend on
 * any Linux userspace headers.
 */
#define CERBERUS_AF_INET 2
#define CERBERUS_AF_INET6 10
#define CERBERUS_PROTO_TCP 6
#define CERBERUS_PROTO_UDP 17

/*
 * Flags carried in network events (net_event.flags).
 */
#define CERBERUS_EF_WOULD_DENY 0x01   /* deny verdict, but monitor mode */
#define CERBERUS_EF_SHARED_HOST 0x02 /* IP also serves an allow-ruled domain */
#define CERBERUS_EF_UNMAPPED 0x04     /* no domain association known */
#define CERBERUS_EF_DNS_EXEMPT 0x08   /* allowed by the port-53 exemption */
#define CERBERUS_EF_SUSPICIOUS 0x10   /* coarse shell heuristic fired */
#define CERBERUS_EF_RECENT_EXEC 0x20  /* destination process exec'd < 5s ago */
#define CERBERUS_EF_LOOPBACK 0x40     /* loopback destination */
#define CERBERUS_EF_DEFAULT_DENY 0x80 /* deny-all mode, no allow rule */

/*
 * Maximum length of a stored domain name, including the
 * terminating NUL.
 */
#define CERBERUS_NET_DOMAIN_MAX 64

/*
 * Maximum bytes of a DNS message captured by the TC sniffer.
 */
#define CERBERUS_DNS_CAPTURE_MAX 320

/*
 * Key for per-address BPF maps (explicit IP rules and the
 * DNS-derived domain associations). Addresses are stored
 * in network byte order; IPv4 occupies addr[0..3].
 */
struct net_addr {
    unsigned int family;             /* CERBERUS_AF_* */
    unsigned char addr[16];
};

/*
 * Explicit IP rule, stored in the net_ip_rules hash map.
 * No expiry: explicit rules are always honored.
 */
struct net_ip_rule {
    unsigned char verdict;           /* CERBERUS_NET_VERDICT_* */
    unsigned char rule_type;         /* CERBERUS_NET_RULE_IP_* */
};

/*
 * DNS-derived per-address decision, stored in the
 * net_ip_decisions LRU map. Written by the agent whenever
 * a DNS answer associates an address with a domain, and
 * rewritten whenever the administrator changes a domain
 * rule.
 *
 *   domain     matching domain rule key ("" if none matched)
 *   assoc      the DNS-mapped domain the address was seen serving
 *   verdict    what a *domain rule* matched:
 *              NONE = no rule matched, ALLOW/DENY = matched
 */
struct net_ip_decision {
    char domain[CERBERUS_NET_DOMAIN_MAX];
    char assoc[CERBERUS_NET_DOMAIN_MAX];
    unsigned char verdict;   /* CERBERUS_NET_VERDICT_* */
    unsigned char rule_type; /* CERBERUS_NET_RULE_DOMAIN_* */
    unsigned char flags;
    unsigned char reserved;
    unsigned long long expires; /* CLOCK_MONOTONIC ns, 0 = never */
};

/*
 * Rate limiting state for connect-event emission
 * (net_rate LRU map, keyed by PID).
 */
struct net_rate {
    unsigned int last_sec;
    unsigned int count;
    unsigned int suppressed;
};

/*
 * Recent process-execution state (exec_recent LRU map,
 * keyed by PID). Filled by the bprm_creds_for_exec hook;
 * consulted by the connect hook for reverse-shell
 * correlation.
 */
struct exec_recent {
    unsigned long long ts_ns;
    char name[16];
};

/*
 * Network connection event. Same 12-byte prefix layout as
 * "struct event" (evt_type at byte offset 10) so one
 * dispatcher can identify both record types.
 */
struct net_event {
    unsigned int pid;
    unsigned int uid;
    unsigned char denied;    /* 1 = connect() will actually be denied */
    unsigned char rule_type; /* CERBERUS_NET_RULE_* of the decision */
    unsigned char evt_type;  /* CERBERUS_EVT_NET_CONNECT */
    unsigned char flags;     /* CERBERUS_EF_* */
    char comm[16];
    unsigned int family;         /* CERBERUS_AF_* */
    unsigned int port;           /* destination port, host byte order */
    unsigned int proto;          /* CERBERUS_PROTO_* where known, else 0 */
    unsigned int suppressed;     /* events suppressed by rate limiting */
    unsigned char dst[16];       /* destination address, network order */
    unsigned int reserved2;      /* explicit alignment padding */
    unsigned long long ts;       /* CLOCK_MONOTONIC ns at the hook */
    char rule[CERBERUS_NET_DOMAIN_MAX];      /* matched rule key */
    char assoc[CERBERUS_NET_DOMAIN_MAX];     /* mapped domain (via DNS) */
};

/*
 * DNS answer event emitted by the TC sniffer. The payload
 * is the raw DNS message (header + question + answers),
 * truncated to CERBERUS_DNS_CAPTURE_MAX bytes at a 32-byte
 * chunk boundary. Only DNS responses (QR bit set) are
 * emitted; the agent parses A/AAAA records and maintains
 * the domain-to-address association.
 */
struct dns_event {
    unsigned int pid;
    unsigned int uid;
    unsigned char denied;    /* always 0 */
    unsigned char rule_type; /* always 0 */
    unsigned char evt_type;  /* CERBERUS_EVT_DNS_RESPONSE */
    unsigned char reserved;
    char comm[16];
    unsigned int family;     /* CERBERUS_AF_* of the DNS packet */
    unsigned int payload_len; /* captured message bytes */
    unsigned char payload[CERBERUS_DNS_CAPTURE_MAX];
};

#endif
