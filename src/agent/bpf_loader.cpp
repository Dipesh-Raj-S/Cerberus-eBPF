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
     * Open, load and attach step by step: the TC-based
     * DNS sniffer cannot be auto-attached and is wired
     * up by the DNS module after attach.
     */
    g_skel = ips_core_bpf__open();

    if (!g_skel)
    {
        std::cerr
            << "[-] Failed to open BPF skeleton.\n";

        return false;
    }

    bpf_program__set_autoattach(g_skel->progs.dns_sniff, false);

    if (ips_core_bpf__load(g_skel))
    {
        std::cerr
            << "[-] Failed to load BPF skeleton.\n";

        bpf_runtime_stop();

        return false;
    }

    if (ips_core_bpf__attach(g_skel))
    {
        std::cerr
            << "[-] Failed to attach BPF LSM hooks.\n";

        bpf_runtime_stop();

        return false;
    }

    /*
     * Flushed here (not buffered) so a broken startup
     * leaves a trail: seeing this line means load and
     * attach succeeded, and any hang below it is a later
     * startup step.
     */
    std::cout
        << "[+] eBPF programs loaded and attached."
        << std::endl;

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

    maps.policy.net_mode_fd =
        bpf_map__fd(g_skel->maps.net_policy_mode);

    maps.policy.net_flags_fd =
        bpf_map__fd(g_skel->maps.net_flags);

    maps.policy.net_ip_rules_fd =
        bpf_map__fd(g_skel->maps.net_ip_rules);

    maps.policy.net_ip_decisions_fd =
        bpf_map__fd(g_skel->maps.net_ip_decisions);

    maps.policy.shell_block_fd =
        bpf_map__fd(g_skel->maps.shell_block);

    maps.ringbuf_fd =
        bpf_map__fd(g_skel->maps.rb);

    if (
        maps.policy.rules_fd < 0 ||
        maps.policy.scoped_fd < 0 ||
        maps.policy.allow_fd < 0 ||
        maps.policy.sandbox_fd < 0 ||
        maps.policy.mode_fd < 0 ||
        maps.policy.net_mode_fd < 0 ||
        maps.policy.net_flags_fd < 0 ||
        maps.policy.net_ip_rules_fd < 0 ||
        maps.policy.net_ip_decisions_fd < 0 ||
        maps.policy.shell_block_fd < 0 ||
        maps.ringbuf_fd < 0)
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


/*
 * Skeleton accessor for the DNS TC attachment.
 */
struct ips_core_bpf* bpf_runtime_skel()
{
    return g_skel;
}
