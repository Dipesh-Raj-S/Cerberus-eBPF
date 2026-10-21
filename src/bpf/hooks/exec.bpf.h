/*
 * Cerberus process-execution tracker.
 *
 * Attached to LSM bprm_creds_for_exec, this program
 * records the most recent exec of every process in an LRU
 * map. The connect hook consults it to flag network
 * activity from freshly exec'd processes — one piece of
 * evidence in the reverse-shell heuristics.
 *
 * No events are emitted here: the map write is the only
 * cost.
 */
#ifndef CERBERUS_HOOK_EXEC_BPF_H
#define CERBERUS_HOOK_EXEC_BPF_H


SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(track_exec, struct linux_binprm *bprm)
{
    struct exec_recent rec = {};
    __u32 pid;

    pid = bpf_get_current_pid_tgid() >> 32;

    rec.ts_ns = net_now_ns();

    __builtin_memset(
        rec.name,
        0,
        sizeof(rec.name)
    );

    bpf_probe_read_kernel_str(
        rec.name,
        sizeof(rec.name),
        BPF_CORE_READ(bprm, filename)
    );

    bpf_map_update_elem(
        &exec_recent,
        &pid,
        &rec,
        BPF_ANY
    );

    return 0;
}


#endif /* CERBERUS_HOOK_EXEC_BPF_H */
