#include <iostream>
#include <iomanip>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "common.h"
#include "../build/ips_core.skel.h"

//This function runs whenever the agent receives an event from the Ring Buffer.
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = (const struct event *)data;

    std::cout << "\033[1;31m[BLOCKED INTRUSION]\033[0m "
              << "PID: " << std::setw(6) << e->pid
              << " | Process: " << std::setw(12) << e->comm
              << " | Protected Target: " << e->filename
              << std::endl;

    return 0;
}

//the skeleton basically gives our C++ agent an easy way to interact with the BPF program.
int main() {
    struct ips_core_bpf *skel = ips_core_bpf__open_and_load();//Load the eBPF Program
    //Error checking
    if (!skel) {
        std::cerr << "Failed to load BPF skeleton\n";
        return 1;
    }
    //We also need to attach it to its hook.
    if (ips_core_bpf__attach(skel)) {
        std::cerr << "Failed to attach BPF programs\n";
        ips_core_bpf__destroy(skel);
        return 1;
    }

    //Create the Ring Buffer Listener
    //Remember the kernel created:
    //rb SEC(".maps");
    //Now the user-space agent connects to that same Ring Buffer.

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        std::cerr << "Failed to initialize ring buffer\n";
        ips_core_bpf__destroy(skel);
        return 1;
    }

    std::cout << "Cerberus IPS Enforcer Active. Running in BLOCKING mode...\n";

    while (true) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0) break;
    }

    ring_buffer__free(rb);
    ips_core_bpf__destroy(skel);
    return 0;
}
