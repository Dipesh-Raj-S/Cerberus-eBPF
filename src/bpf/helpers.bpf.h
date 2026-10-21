/*
 * Cerberus BPF helpers.
 *
 * Event emission and file-rule key construction,
 * shared by the hook programs.
 */
#ifndef CERBERUS_HELPERS_BPF_H
#define CERBERUS_HELPERS_BPF_H


/*
 * Report a matched rule to user space.
 *
 * "key" is the exact rule key that matched, so the
 * agent can display which rule triggered the event.
 */
static __always_inline void emit_event(
    const char *key,
    unsigned char rule_type,
    int denied)
{
    struct event *e;

    e = bpf_ringbuf_reserve(
        &rb,
        sizeof(*e),
        0
    );

    if (!e)
        return;

    e->pid =
        bpf_get_current_pid_tgid() >> 32;

    e->uid =
        bpf_get_current_uid_gid();

    e->denied =
        denied ? 1 : 0;

    e->rule_type =
        rule_type;

    e->evt_type =
        CERBERUS_EVT_FILE_OPEN;

    e->reserved = 0;

    bpf_get_current_comm(
        &e->comm,
        sizeof(e->comm)
    );

    /*
     * Copy the matched rule key into the event.
     * For PATH rules this is the fixed slot layout.
     */
    __builtin_memcpy(
        e->rule,
        key,
        sizeof(e->rule)
    );

    bpf_ringbuf_submit(e, 0);
}


/*
 * Build a PATH rule key in the fixed slot layout:
 *
 *     [0 .. 63]   parent directory name
 *     [64]        '/'
 *     [65 .. 255] file name
 */
static __always_inline void build_path_key(
    char *key,
    const struct qstr *parent,
    const struct qstr *base)
{
    bpf_probe_read_kernel_str(
        key,
        CERBERUS_PATH_SLOT,
        parent->name
    );

    key[CERBERUS_PATH_SLOT] = '/';

    bpf_probe_read_kernel_str(
        key + CERBERUS_PATH_SLOT + 1,
        256 - CERBERUS_PATH_SLOT - 1,
        base->name
    );
}


/*
 * Build a NAME rule key: a plain NUL-terminated
 * file name.
 */
static __always_inline void build_name_key(
    char *key,
    const struct qstr *base)
{
    __builtin_memset(
        key,
        0,
        256
    );

    bpf_probe_read_kernel_str(
        key,
        256,
        base->name
    );
}


/*
 * ============================================================
 *  Network helpers (Phase 5)
 * ============================================================
 */

/*
 * Events above this per-PID, per-second rate are not
 * emitted to the ring buffer. Enforcement is unaffected.
 */
#define CERBERUS_NET_EVENT_RATE 64

/*
 * Current CLOCK_MONOTONIC time.
 *
 * bpf_ktime_get_ns is the only clock helper allowed from
 * every program type this project uses (LSM hooks and
 * TC); the coarse variant is rejected by the verifier for
 * LSM programs. Its CLOCK_MONOTONIC epoch also matches
 * the userspace side exactly, which is what TTL expiry
 * comparisons rely on.
 */
static __always_inline __u64 net_now_ns(void)
{
    return bpf_ktime_get_ns();
}

/*
 * Reserve and pre-fill a network event, or return NULL
 * when the ring buffer has no room (reservation
 * failures are silently counted as dropped; the
 * connection decision is never delayed by it).
 */
static __always_inline struct net_event *net_event_alloc(void)
{
    struct net_event *e;

    e = bpf_ringbuf_reserve(
        &rb,
        sizeof(*e),
        0
    );

    if (!e)
        return 0;

    e->pid =
        bpf_get_current_pid_tgid() >> 32;

    e->uid =
        bpf_get_current_uid_gid();

    e->denied = 0;

    e->rule_type = CERBERUS_NET_RULE_NONE;

    e->evt_type = CERBERUS_EVT_NET_CONNECT;

    e->flags = 0;

    __builtin_memset(
        e->comm,
        0,
        sizeof(e->comm)
    );

    bpf_get_current_comm(
        e->comm,
        sizeof(e->comm)
    );

    e->suppressed = 0;

    e->reserved2 = 0;

    return e;
}

/*
 * Copy a NUL-terminated domain string of at most
 * CERBERUS_NET_DOMAIN_MAX bytes (including the NUL) into
 * an event field.
 */
static __always_inline void net_copy_domain(
    char *dst,
    const char *src)
{
    __builtin_memset(
        dst,
        0,
        CERBERUS_NET_DOMAIN_MAX
    );

    __builtin_memcpy(
        dst,
        src,
        CERBERUS_NET_DOMAIN_MAX
    );
}

/*
 * Per-PID connect-event rate limiting.
 *
 * Returns 1 when the event may be emitted, 0 when it must
 * be suppressed. *suppressed_out carries how many events
 * of the previous or current window were suppressed (only
 * nonzero when a burst just ended).
 */
static __always_inline int net_rate_allow(
    __u32 pid,
    __u32 *suppressed_out)
{
    struct net_rate *r;
    struct net_rate fresh = {};
    __u32 now_sec =
        (__u32)(bpf_ktime_get_ns() / 1000000000ULL);

    r = bpf_map_lookup_elem(&net_rate, &pid);

    if (!r)
    {
        fresh.last_sec = now_sec;
        fresh.count = 1;

        bpf_map_update_elem(
            &net_rate,
            &pid,
            &fresh,
            BPF_ANY
        );

        *suppressed_out = 0;

        return 1;
    }

    if (r->last_sec != now_sec)
    {
        *suppressed_out = r->suppressed;

        r->last_sec = now_sec;
        r->count = 1;
        r->suppressed = 0;

        return 1;
    }

    *suppressed_out = r->suppressed;

    if (r->count >= CERBERUS_NET_EVENT_RATE)
    {
        r->suppressed++;

        return 0;
    }

    r->count++;

    return 1;
}


#endif /* CERBERUS_HELPERS_BPF_H */
