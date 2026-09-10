#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

#define EPERM 1

/*
 * Dynamic blocklist.
 *
 * Key:
 *     filename[256]
 *
 * Value:
 *     __u8
 *
 * Example:
 *     "sensitive.txt" -> 1
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[256]);
    __type(value, __u8);
} blocklist SEC(".maps");


/*
 * Events sent from kernel space to the Cerberus
 * user-space agent when something is blocked.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file)
{
    char filename[256] = {};

    /*
     * Get the filename from the dentry.
     *
     * For this first version we use the basename:
     *
     *     /tmp/sensitive.txt
     *
     * becomes:
     *
     *     sensitive.txt
     */
    struct qstr d_name = BPF_CORE_READ(
        file,
        f_path.dentry,
        d_name
    );

    bpf_probe_read_kernel_str(
        filename,
        sizeof(filename),
        d_name.name
    );


    /*
     * Look up the filename in the dynamic
     * BPF Hash Map.
     */
    __u8 *blocked = bpf_map_lookup_elem(
        &blocklist,
        filename
    );


    /*
     * Filename exists in blocklist.
     */
    if (blocked)
    {
        struct event *e;

        e = bpf_ringbuf_reserve(
            &rb,
            sizeof(*e),
            0
        );

        if (e)
        {
            e->pid =
                bpf_get_current_pid_tgid() >> 32;

            bpf_get_current_comm(
                &e->comm,
                sizeof(e->comm)
            );

            bpf_probe_read_kernel_str(
                e->filename,
                sizeof(e->filename),
                filename
            );

            bpf_ringbuf_submit(e, 0);
        }

        return -EPERM;
    }

    /*
     * Filename isn't in the blocklist.
     */
    return 0;
}


char LICENSE[] SEC("license") = "GPL";
