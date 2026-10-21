/*
 * Cerberus eBPF IPS core.
 *
 * Single BPF translation unit. The individual hook
 * programs and their shared maps/helpers live in
 * headers under this directory and are included here
 * so every hook shares the same maps and ring buffer.
 */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cerberus/common.h"

/*
 * <errno.h> cannot be safely included when compiling
 * with "-target bpf", so define the one error code
 * we need explicitly.
 *
 * EPERM == 1, meaning "Operation not permitted".
 */
#ifndef EPERM
#define EPERM 1
#endif

#include "maps.bpf.h"
#include "helpers.bpf.h"
#include "rules.bpf.h"

#include "hooks/file_open.bpf.h"


char LICENSE[] SEC("license") = "GPL";
