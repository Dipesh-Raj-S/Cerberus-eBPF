/*
 * Cerberus outgoing-connection control hook.
 *
 * Attached to LSM socket_connect, this program sees every
 * connect() attempt before it completes and decides
 * whether it is allowed, reported only, or denied
 * (-EPERM).
 *
 * What this hook can observe:
 *   - the already-resolved destination address (never the
 *     hostname the application asked for),
 *   - destination port and address family,
 *   - process identity (pid, uid, comm).
 *
 * What it cannot observe:
 *   - DNS traffic itself (captured separately by the TC
 *     sniffer in dns_capture.bpf.h),
 *   - the application's intended hostname when no DNS
 *     association is known (direct-IP connections).
 *
 * Honest-enforcement note: a denied event always means
 * connect() really returns -EPERM. In monitor mode a
 * matching deny rule sets EF_WOULD_DENY instead of
 * denied=1.
 */
#ifndef CERBERUS_HOOK_SOCKET_CONNECT_BPF_H
#define CERBERUS_HOOK_SOCKET_CONNECT_BPF_H


/*
 * The kernel-side copy buffer for connect() addresses is
 * at least sizeof(struct sockaddr_storage) (128 bytes), so
 * reading the first 64 bytes is always safe.
 */
#define CERBERUS_SOCK_READ_MAX 64

/*
 * Recent-exec window used for reverse-shell correlation.
 */
#define CERBERUS_RECENT_EXEC_NS 5000000000ULL


/*
 * Is this destination loopback?
 */
static __always_inline int net_is_loopback(
    __u32 family,
    const unsigned char *dst)
{
    int i;

    if (family == CERBERUS_AF_INET)
        return dst[0] == 127;

    if (family == CERBERUS_AF_INET6)
    {
        for (i = 0; i < 15; i++)
        {
            if (dst[i])
                return 0;
        }

        return dst[15] == 1;
    }

    return 0;
}


/*
 * Link-local and multicast destinations are allowed
 * without an event: they are local network plumbing,
 * not outgoing security-relevant traffic.
 */
static __always_inline int net_is_local_scope(
    __u32 family,
    const unsigned char *dst)
{
    if (family == CERBERUS_AF_INET)
    {
        if (dst[0] == 169 && dst[1] == 254)
            return 1; /* IPv4 link-local */

        if (dst[0] >= 224 && dst[0] <= 239)
            return 1; /* IPv4 multicast */
    }

    if (family == CERBERUS_AF_INET6)
    {
        if (dst[0] == 0xfe && dst[1] == 0x80)
            return 1; /* IPv6 link-local */

        if (dst[0] == 0xff)
            return 1; /* IPv6 multicast */
    }

    return 0;
}


/*
 * Classification result for one destination.
 *
 *   explicit_ip  = 1 when net_ip_rules matched (absolute
 *                  verdict, never expires)
 *   verdict      = what a RULE matched, per-address:
 *                    DENY   deny rule matched
 *                    ALLOW  allow rule matched
 *                    NONE   mapped but no domain rule
 *                           matched (or nothing found)
 *   rule_type    = CERBERUS_NET_RULE_* of the match
 *   rule         matched domain rule key ("" for IP rules)
 *   assoc        DNS-mapped domain for the address
 */
struct net_lookup_result {
    char rule[CERBERUS_NET_DOMAIN_MAX];
    char assoc[CERBERUS_NET_DOMAIN_MAX];
    unsigned char rule_type;
    unsigned char flags;
    unsigned char verdict;
    unsigned char explicit_ip;
    unsigned char mapped;      /* 1 = a DNS association exists */
};


/*
 * Rule lookup. Mode-based defaults stay in the caller so
 * monitor/enforce/deny-all semantics live in one place.
 */
static __always_inline void net_lookup(
    const struct net_addr *key,
    struct net_lookup_result *res)
{
    struct net_ip_rule *ipr;
    struct net_ip_decision *dec;
    __u64 now = net_now_ns();

    res->rule_type = CERBERUS_NET_RULE_NONE;
    res->flags = 0;
    res->verdict = CERBERUS_NET_VERDICT_NONE;
    res->explicit_ip = 0;
    res->mapped = 0;

    __builtin_memset(res->rule, 0, sizeof(res->rule));
    __builtin_memset(res->assoc, 0, sizeof(res->assoc));

    /*
     * Explicit IP rules first; they never expire.
     */
    ipr = bpf_map_lookup_elem(&net_ip_rules, key);

    if (ipr)
    {
        res->explicit_ip = 1;
        res->verdict = ipr->verdict;
        res->rule_type = ipr->rule_type;

        return;
    }

    /*
     * DNS-derived decisions second. Entries past their
     * expiry are treated as absent, exactly like missing
     * ones.
     */
    dec = bpf_map_lookup_elem(&net_ip_decisions, key);

    if (dec &&
        (dec->expires == 0 || dec->expires > now))
    {
        res->mapped = 1;
        res->verdict = dec->verdict;
        res->rule_type = dec->rule_type;
        res->flags = dec->flags;

        __builtin_memcpy(
            res->rule,
            dec->domain,
            sizeof(res->rule)
        );

        __builtin_memcpy(
            res->assoc,
            dec->assoc,
            sizeof(res->assoc)
        );
    }
}


SEC("lsm/socket_connect")
int BPF_PROG(restrict_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct net_event *e;
    struct net_lookup_result res = {};
    struct net_addr key = {};

    char sbuf[CERBERUS_SOCK_READ_MAX] = {};
    char comm[16] = {};

    unsigned char dst[16] = {};

    __u32 zero = 0;
    __u32 port = 0;
    __u32 proto = 0;
    __u32 suppressed = 0;
    __u32 pid;

    __u8 *modep;
    __u8 *flagp;

    unsigned char mode;
    unsigned char flags_cfg;

    __u16 fam;

    int denied;
    int emit;
    int suspicious = 0;

    unsigned char ef = 0;

    if (addrlen < 8)
        return 0;

    /*
     * Copy the kernel-side sockaddr. Failure is a transient
     * read error: fail open, honestly.
     */
    if (bpf_probe_read_kernel(sbuf, sizeof(sbuf), address))
        return 0;

    __builtin_memcpy(&fam, sbuf, sizeof(fam));

    if (fam == CERBERUS_AF_INET)
    {
        __u16 pbe = 0;

        key.family = fam;

        __builtin_memcpy(key.addr, sbuf + 4, 4);
        __builtin_memcpy(dst, sbuf + 4, 4);
        __builtin_memcpy(&pbe, sbuf + 2, sizeof(pbe));

        port = bpf_ntohs(pbe);
    }
    else if (fam == CERBERUS_AF_INET6)
    {
        __u16 pbe = 0;

        if (addrlen < 24)
            return 0;

        key.family = fam;

        __builtin_memcpy(key.addr, sbuf + 8, 16);
        __builtin_memcpy(dst, sbuf + 8, 16);
        __builtin_memcpy(&pbe, sbuf + 2, sizeof(pbe));

        port = bpf_ntohs(pbe);
    }
    else
    {
        /*
         * Unix, netlink and other non-IP families are not
         * part of network protection.
         */
        return 0;
    }

    /*
     * Loopback, link-local and multicast traffic is
     * allowed without an event: it is local plumbing.
     */
    if (net_is_loopback(key.family, dst) ||
        net_is_local_scope(key.family, dst))
        return 0;

    pid =
        bpf_get_current_pid_tgid() >> 32;

    /*
     * Protocol where known.
     */
    {
        struct sock *sk = BPF_CORE_READ(sock, sk);

        if (sk)
            proto = (unsigned int)BPF_CORE_READ(sk, sk_protocol);
    }

    /*
     * Mode and runtime flags.
     */
    modep = bpf_map_lookup_elem(&net_policy_mode, &zero);

    mode = modep
        ? *modep
        : CERBERUS_NET_MODE_MONITOR;

    flagp = bpf_map_lookup_elem(&net_flags, &zero);

    flags_cfg = flagp ? *flagp : 0;

    /*
     * Rule lookup.
     */
    net_lookup(&key, &res);

    denied = 0;

    if (res.explicit_ip || res.mapped)
    {
        /*
         * A rule or a live DNS decision decides.
         *
         * Explicit IP verdicts are absolute; a domain
         * "NONE" verdict only blocks the connection in
         * DENY_ALL mode, where anything without an allow
         * rule is denied.
         */
        if (mode == CERBERUS_NET_MODE_MONITOR)
        {
            if (res.verdict == CERBERUS_NET_VERDICT_DENY)
                ef |= CERBERUS_EF_WOULD_DENY;
        }
        else if (mode == CERBERUS_NET_MODE_ENFORCE)
        {
            if (res.verdict == CERBERUS_NET_VERDICT_DENY)
                denied = 1;
        }
        else /* DENY_ALL */
        {
            if (res.verdict == CERBERUS_NET_VERDICT_ALLOW)
            {
                /* explicitly allowed */
            }
            else
            {
                denied = 1;

                if (res.verdict == CERBERUS_NET_VERDICT_NONE)
                    ef |= CERBERUS_EF_DEFAULT_DENY;
            }
        }
    }
    else
    {
        /*
         * No explicit rule, no live decision: the
         * destination domain is unknown.
         */
        ef |= CERBERUS_EF_UNMAPPED;

        /*
         * Port-53 exemption in DENY_ALL mode keeps DNS
         * resolution working. Documented trade-off: port
         * 53 is also a classic exfiltration channel.
         */
        if (
            mode == CERBERUS_NET_MODE_DENY_ALL &&
            (flags_cfg & CERBERUS_NETF_ALLOW_DNS_PORT) &&
            port == 53)
        {
            ef |= CERBERUS_EF_DNS_EXEMPT;
        }
        else
        {
            /*
             * Coarse reverse-shell blocking: only when the
             * administrator enabled it, never in monitor
             * mode.
             */
            if (
                (flags_cfg & CERBERUS_NETF_BLOCK_SUSPICIOUS) &&
                mode != CERBERUS_NET_MODE_MONITOR &&
                port != 53)
            {
                bpf_get_current_comm(
                    comm,
                    sizeof(comm)
                );

                if (bpf_map_lookup_elem(&shell_block, comm))
                {
                    /*
                     * Blocking is authorized here: this path
                     * only runs outside monitor mode with
                     * BLOCK_SUSPICIOUS enabled.
                     */
                    suspicious = 1;
                    denied = 1;

                    res.rule_type = CERBERUS_NET_RULE_SUSPICIOUS;

                    ef |= CERBERUS_EF_SUSPICIOUS;
                }
            }

            if (!suspicious && mode == CERBERUS_NET_MODE_DENY_ALL)
            {
                denied = 1;
            }
        }
    }

    /*
     * Recent-exec marker for reverse-shell heuristics.
     */
    {
        struct exec_recent *er = bpf_map_lookup_elem(
            &exec_recent,
            &pid
        );

        if (er &&
            (net_now_ns() - er->ts_ns) < CERBERUS_RECENT_EXEC_NS)
            ef |= CERBERUS_EF_RECENT_EXEC;
    }

    if (res.flags & CERBERUS_EF_SHARED_HOST)
        ef |= CERBERUS_EF_SHARED_HOST;

    /*
     * Rate-limited event emission. Suppressed events still
     * receive their verdict; only the reporting is dropped.
     */
    emit = net_rate_allow(pid, &suppressed);

    if (!emit)
        return denied ? -EPERM : 0;

    e = net_event_alloc();

    if (!e)
        return denied ? -EPERM : 0;

    e->family = key.family;
    e->port = port;
    e->proto = proto;

    __builtin_memcpy(
        e->dst,
        key.addr,
        sizeof(e->dst)
    );

    e->denied = denied ? 1 : 0;

    e->rule_type = res.rule_type;

    e->flags = ef;

    e->suppressed = suppressed;

    e->ts = net_now_ns();

    net_copy_domain(e->rule, res.rule);

    net_copy_domain(e->assoc, res.assoc);

    bpf_ringbuf_submit(e, 0);

    /*
     * LSM verdict: denied means connect() really fails.
     */
    return denied ? -EPERM : 0;
}


#endif /* CERBERUS_HOOK_SOCKET_CONNECT_BPF_H */
