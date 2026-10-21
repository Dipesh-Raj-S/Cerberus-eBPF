/*
 * Cerberus DNS capture hook.
 *
 * Attached as a TC classifier to non-loopback interfaces
 * (both ingress and egress), this program observes UDP
 * port-53 traffic and emits raw DNS *responses* to the
 * agent, which parses A/AAAA records and maintains the
 * domain-to-address association used for domain-level
 * enforcement.
 *
 * Emitting only responses (QR bit set) halves the event
 * volume: the payload bytes of a response already carry
 * the question-independent (domain, address) pairs.
 *
 * Limitations, mirrored in the README:
 *   - plaintext UDP DNS only (no TCP-53, no DoT/DoH),
 *   - answers whose data spans more than the capture cap
 *     lose their trailing records,
 *   - hosts with upstream resolver caches keep answering
 *     queries without any new DNS packet traffic; the
 *     association for such domains may lapse until the
 *     upstream cache expires.
 */
#ifndef CERBERUS_HOOK_DNS_CAPTURE_BPF_H
#define CERBERUS_HOOK_DNS_CAPTURE_BPF_H


#define CERBERUS_ETH_P_IP 0x0800
#define CERBERUS_ETH_P_IPV6 0x86dd
#define CERBERUS_ETH_P_VLAN 0x8100
#define CERBERUS_ETH_P_QINQ 0x88a8

#define CERBERUS_DNS_PORT 53

/* DNS message sizes below this are useless (header only) */
#define CERBERUS_DNS_MIN_MSG 32

/*
 * TC verdicts: OK lets the packet proceed; this program
 * never drops traffic.
 */
#define CERBERUS_TC_OK 0


/*
 * Copy exactly up to min(msg_len, CERBERUS_DNS_CAPTURE_MAX)
 * bytes of the DNS message into the event payload.
 *
 * bpf_skb_load_bytes bounds-checks every access against
 * the whole sk_buff (linear + fragments) and the verifier
 * proves the size against the payload capacity, so this
 * is one exact copy instead of a chunked approximation:
 * no trailing answers are lost to chunk granularity.
 *
 * A failed copy (short/truncated packet) is reported
 * honestly as no data.
 */
static __always_inline void dns_copy_payload(
    struct __sk_buff *skb,
    struct dns_event *ev,
    __u32 msg_off,
    __u32 msg_len)
{
    __u32 len = msg_len;

    ev->payload_len = 0;

    if (len > CERBERUS_DNS_CAPTURE_MAX)
        len = CERBERUS_DNS_CAPTURE_MAX;

    if (len == 0)
        return;

    if (bpf_skb_load_bytes(
            skb,
            msg_off,
            ev->payload,
            len) == 0)
        ev->payload_len = len;
}


SEC("tc")
int BPF_PROG(dns_sniff, struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    unsigned char *p = (unsigned char *)data;

    __u32 off;
    __u32 family;
    __u32 msg_len;
    __u32 msg_off = 0;

    struct dns_event *ev;

    __u16 eth_proto;
    __u16 dflags;

    /*
     * Ethernet frame; VLAN-aware single tag.
     */
    if (p + sizeof(struct ethhdr) > (unsigned char *)data_end)
        return CERBERUS_TC_OK;

    eth_proto = ((struct ethhdr *)p)->h_proto;

    off = sizeof(struct ethhdr);

    if (eth_proto == bpf_htons(CERBERUS_ETH_P_VLAN) ||
        eth_proto == bpf_htons(CERBERUS_ETH_P_QINQ))
    {
        if (p + off + 4 > (unsigned char *)data_end)
            return CERBERUS_TC_OK;

        /*
         * The encapsulated EtherType sits right after the
         * 4-byte VLAN tag.
         */
        eth_proto = *(__u16 *)(p + off + 2);

        off += 4;
    }

    if (eth_proto == bpf_htons(CERBERUS_ETH_P_IP))
    {
        struct iphdr *ip = (struct iphdr *)(p + off);

        if (p + off + sizeof(*ip) > (unsigned char *)data_end)
            return CERBERUS_TC_OK;

        if (ip->version != 4 || ip->ihl < 5)
            return CERBERUS_TC_OK;

        if (ip->protocol != CERBERUS_PROTO_UDP)
            return CERBERUS_TC_OK;

        /*
         * Any fragmentation (offset or more-flag) means the
         * UDP header is not here; skip.
         */
        if (bpf_ntohs(ip->frag_off) & 0x3fff)
            return CERBERUS_TC_OK;

        off += ip->ihl * 4;

        family = CERBERUS_AF_INET;
    }
    else if (eth_proto == bpf_htons(CERBERUS_ETH_P_IPV6))
    {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(p + off);

        if (p + off + sizeof(*ip6) > (unsigned char *)data_end)
            return CERBERUS_TC_OK;

        /*
         * Extension headers are not followed: DNS over
         * IPv6 with hop-by-hop/routing/fragment options is
         * vanishingly rare and skipped.
         */
        if (ip6->nexthdr != CERBERUS_PROTO_UDP)
            return CERBERUS_TC_OK;

        off += sizeof(*ip6);

        family = CERBERUS_AF_INET6;
    }
    else
    {
        return CERBERUS_TC_OK;
    }

    struct udphdr *udp;

    /*
     * UDP header pointer (bounds validated below).
     */
    udp = (struct udphdr *)(p + off);

    if (p + off + sizeof(*udp) > (unsigned char *)data_end)
        return CERBERUS_TC_OK;

    /*
     * DNS (plaintext UDP) traffic only.
     */
    if (bpf_ntohs(udp->dest) != CERBERUS_DNS_PORT &&
        bpf_ntohs(udp->source) != CERBERUS_DNS_PORT)
        return CERBERUS_TC_OK;

    /* UDP length includes the UDP header. */
    msg_len = bpf_ntohs(udp->len) - sizeof(*udp);

    if (msg_len < CERBERUS_DNS_MIN_MSG)
        return CERBERUS_TC_OK;

    if (msg_len > CERBERUS_DNS_CAPTURE_MAX)
        msg_len = CERBERUS_DNS_CAPTURE_MAX;

    /*
     * The DNS message starts right after the UDP header;
     * numeric offset for the bounded copy below.
     */
    msg_off = off + sizeof(*udp);

    if (msg_off + msg_len > skb->len)
        return CERBERUS_TC_OK;

    /*
     * Responses only (QR bit set): the answer section
     * carries the domain/address pairs.
     */
    if (bpf_skb_load_bytes(
            skb,
            msg_off + 2,
            &dflags,
            sizeof(dflags)))
        return CERBERUS_TC_OK;

    if (!(dflags & bpf_htons(0x8000)))
        return CERBERUS_TC_OK;

    ev = bpf_ringbuf_reserve(
        &rb,
        sizeof(*ev),
        0
    );

    if (!ev)
        return CERBERUS_TC_OK;

    ev->pid =
        bpf_get_current_pid_tgid() >> 32;

    ev->uid =
        bpf_get_current_uid_gid();

    ev->denied = 0;

    ev->rule_type = 0;

    ev->evt_type = CERBERUS_EVT_DNS_RESPONSE;

    ev->reserved = 0;

    __builtin_memset(
        ev->comm,
        0,
        sizeof(ev->comm)
    );

    bpf_get_current_comm(
        ev->comm,
        sizeof(ev->comm)
    );

    ev->family = family;

    dns_copy_payload(
        skb,
        ev,
        msg_off,
        msg_len
    );

    bpf_ringbuf_submit(ev, 0);

    return CERBERUS_TC_OK;
}


#endif /* CERBERUS_HOOK_DNS_CAPTURE_BPF_H */
