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


#endif /* CERBERUS_HELPERS_BPF_H */
