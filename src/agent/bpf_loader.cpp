#include "bpf_loader.h"

#include <iostream>

#include <bpf/libbpf.h>

#include "cerberus/common.h"
#include "ips_core.skel.h"
#include "policy.h"


static struct ips_core_bpf *g_skel = nullptr;


bool bpf_runtime_start(bpf_maps& maps)
{
    /*
     * Open and load the eBPF skeleton.
     */
    g_skel = ips_core_bpf__open_and_load();

    if (!g_skel)
    {
        std::cerr
            << "[-] Failed to load BPF skeleton.\n";

        return false;
    }


    /*
     * Attach the LSM program.
     */
    if (ips_core_bpf__attach(g_skel))
    {
        std::cerr
            << "[-] Failed to attach BPF LSM hook.\n";

        bpf_runtime_stop();

        return false;
    }


    /*
     * Get file descriptors for our maps.
     */
    maps.policy.rules_fd =
        bpf_map__fd(g_skel->maps.blocklist);

    maps.policy.scoped_fd =
        bpf_map__fd(g_skel->maps.scoped_rules);

    maps.policy.allow_fd =
        bpf_map__fd(g_skel->maps.allowlist);

    maps.policy.sandbox_fd =
        bpf_map__fd(g_skel->maps.sandboxed);

    maps.policy.mode_fd =
        bpf_map__fd(g_skel->maps.policy_mode);

    maps.ringbuf_fd =
        bpf_map__fd(g_skel->maps.rb);

    if (
        maps.policy.rules_fd < 0 ||
        maps.policy.scoped_fd < 0 ||
        maps.policy.allow_fd < 0 ||
        maps.policy.sandbox_fd < 0 ||
        maps.policy.mode_fd < 0)
    {
        std::cerr
            << "[-] Failed to get BPF map FDs.\n";

        bpf_runtime_stop();

        return false;
    }

    return true;
}


void bpf_runtime_stop()
{
    if (g_skel)
    {
        ips_core_bpf__destroy(g_skel);

        g_skel = nullptr;
    }
}
