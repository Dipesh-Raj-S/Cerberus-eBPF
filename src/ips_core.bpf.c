#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");////Creates a Ring Buffer named rb --> communication channel

SEC("lsm/file_open")//Attach Cerberus to the Linux security hook
                    //Whenever Linux performs a file-open security check
                    //    ↓
                    //restrict_file_open() runs
int BPF_PROG(restrict_file_open, struct file *file)
{
    char filename[256] = {0};

    struct qstr d_name =
        BPF_CORE_READ(file, f_path.dentry, d_name);

    bpf_probe_read_kernel_str(
        filename,
        sizeof(filename),
        d_name.name
    );

    if (filename[0] == 's' &&
        filename[1] == 'e' &&
        filename[2] == 'n' &&
        filename[3] == 's' &&
        filename[4] == 'i' &&
        filename[5] == 't' &&
        filename[6] == 'i' &&
        filename[7] == 'v' &&
        filename[8] == 'e') {

        struct event *e =
            bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

        if (e) {
            e->pid = bpf_get_current_pid_tgid() >> 32;

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

    return 0;
}

char LICENSE[] SEC("license") = "GPL";