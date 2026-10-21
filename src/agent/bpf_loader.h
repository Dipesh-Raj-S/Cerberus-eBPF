/*
 * Cerberus BPF loader.
 *
 * Owns the generated skeleton: load, attach and
 * acquire the map file descriptors.
 */
#ifndef CERBERUS_AGENT_BPF_LOADER_H
#define CERBERUS_AGENT_BPF_LOADER_H

#include "policy.h"

struct bpf_maps {
    policy_maps policy;
    int ringbuf_fd;
};

/*
 * Load the BPF object, attach the LSM hook and fill
 * the map descriptors. Prints its own diagnostics and
 * cleans up after itself on failure.
 */
bool bpf_runtime_start(bpf_maps& maps);

/*
 * Detach and unload the BPF program.
 */
void bpf_runtime_stop();

#endif /* CERBERUS_AGENT_BPF_LOADER_H */
