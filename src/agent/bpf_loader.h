/*
 * Cerberus BPF loader.
 *
 * Owns the generated skeleton: open, load, attach and
 * acquire the map file descriptors. TC programs cannot
 * be auto-attached and are wired up by the DNS module.
 */
#ifndef CERBERUS_AGENT_BPF_LOADER_H
#define CERBERUS_AGENT_BPF_LOADER_H

#include "policy.h"

struct bpf_maps {
    policy_maps policy;
    int ringbuf_fd;
};

/*
 * Load the BPF object, attach the LSM hooks and fill
 * the map descriptors. Prints its own diagnostics and
 * cleans up after itself on failure.
 */
bool bpf_runtime_start(bpf_maps& maps);

/*
 * Detach and unload the BPF object.
 */
void bpf_runtime_stop();

/*
 * Accessor for the loaded skeleton (the DNS module uses
 * it for TC attachment).
 */
struct ips_core_bpf;
struct ips_core_bpf* bpf_runtime_skel();

#endif /* CERBERUS_AGENT_BPF_LOADER_H */
