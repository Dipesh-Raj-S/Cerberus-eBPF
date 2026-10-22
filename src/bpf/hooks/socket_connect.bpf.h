/*
 * Cerberus IP-based network hook.
 *
 * Attached to the Linux Security Module socket_connect
 * hook, this program inspects every outgoing connection
 * attempt (TCP connect() and connected UDP), matches the
 * destination IP against the IPv4/IPv6 block and allow
 * maps, reports the attempt through the ring buffer and
 * denies the connection in enforce mode.
 *
 * Policy precedence is deterministic:
 *
 *   1. block rule  -> deny (in enforce mode)
 *   2. allow rule  -> allow
 *   3. no rule     -> allow
 *
 * A block match therefore never becomes an allow, and no
 * default-deny applies to unlisted addresses.
 */
#ifndef CERBERUS_HOOK_SOCKET_CONNECT_BPF_H
#define CERBERUS_HOOK_SOCKET_CONNECT_BPF_H


SEC("lsm/socket_connect")
int BPF_PROG(restrict_socket_connect,
             struct sock *sk,
             struct sockaddr *address,
             int addrlen)
{
    struct sockaddr sa = {};

    unsigned char addr[16] = {};
    unsigned short port = 0;
    unsigned char protocol = 0;
    int family;
    int enforced;
    int matched_block = 0;
    int matched_allow = 0;

    __u32 zero = 0;
    __u8 *mode;

    /*
     * The LSM hook receives the kernel copy of the
     * destination address made by the connect path.
     */
    bpf_probe_read_kernel(
        &sa,
        sizeof(sa),
        address
    );

    family = sa.sa_family;

    /*
     * Grab the network policy mode once; monitor mode
     * never denies anything.
     */
    mode = bpf_map_lookup_elem(
        &net_mode,
        &zero
    );

    enforced = (
        mode &&
        *mode == CERBERUS_MODE_ENFORCE
    );

    if (family == CERBERUS_AF_INET)
    {
        struct sockaddr_in sin = {};

        if (addrlen < (int)sizeof(sin))
            return 0;

        bpf_probe_read_kernel(
            &sin,
            sizeof(sin),
            address
        );

        __builtin_memcpy(
            addr,
            &sin.sin_addr,
            sizeof(sin.sin_addr)
        );

        port = sin.sin_port;

        protocol =
            BPF_CORE_READ(sk, sk_protocol);

        /*
         * Block rule wins over an allow rule for the
         * same address, so allow is only consulted
         * when the block lookup missed.
         */
        __u32 key4 = 0;

        __builtin_memcpy(
            &key4,
            addr,
            sizeof(key4)
        );

        if (bpf_map_lookup_elem(&net_block4, &key4))
        {
            matched_block = 1;
        }
        else if (bpf_map_lookup_elem(&net_allow4, &key4))
        {
            matched_allow = 1;
        }
    }
    else if (family == CERBERUS_AF_INET6)
    {
        struct sockaddr_in6 sin6 = {};

        if (addrlen < (int)sizeof(sin6))
            return 0;

        bpf_probe_read_kernel(
            &sin6,
            sizeof(sin6),
            address
        );

        __builtin_memcpy(
            addr,
            &sin6.sin6_addr,
            sizeof(sin6.sin6_addr)
        );

        port = sin6.sin6_port;

        protocol =
            BPF_CORE_READ(sk, sk_protocol);

        if (bpf_map_lookup_elem(&net_block6, addr))
        {
            matched_block = 1;
        }
        else if (bpf_map_lookup_elem(&net_allow6, addr))
        {
            matched_allow = 1;
        }
    }
    else
    {
        /*
         * AF_UNSPEC (UDP disconnect and similar calls) and
         * non-IP families are outside the scope of the
         * IP policy; allow without reporting.
         */
        return 0;
    }


    /*
     * Decide the verdict: only enforce mode with a
     * matching block rule becomes DENIED. Monitor mode
     * reports the match as a would-be block.
     */
    int verdict = CERBERUS_NET_VERDICT_ALLOWED;

    if (matched_block)
    {
        verdict = (
            enforced
                ? CERBERUS_NET_VERDICT_DENIED
                : CERBERUS_NET_VERDICT_BLOCKED_MONITOR
        );
    }
    else if (matched_allow)
    {
        verdict = CERBERUS_NET_VERDICT_ALLOWED;
    }

    emit_net_event(
        addr,
        (unsigned char)family,
        protocol,
        port,
        verdict,
        matched_block,
        matched_allow
    );


    /*
     * Deny the connection only when the kernel hook
     * actually rejects it; -EPERM reaches the caller.
     */
    if (matched_block && enforced)
        return -EPERM;

    return 0;
}


#endif /* CERBERUS_HOOK_SOCKET_CONNECT_BPF_H */
