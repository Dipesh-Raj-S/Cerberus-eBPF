#include <iostream>
#include <iomanip>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "common.h"
#include "../build/ips_core.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = (const struct event *)data;
    std::cout << "[EVENT] PID: " << std::setw(6) << e->pid 
              << " | Process: " << std::setw(15) << e->comm 
              << " | File: " << e->filename << std::endl;
    return 0;
}

int main() {
    struct ips_core_bpf *skel = ips_core_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to load BPF skeleton\n";
        return 1;
    }

    if (ips_core_bpf__attach(skel)) {
        std::cerr << "Failed to attach BPF programs\n";
        ips_core_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        std::cerr << "Failed to initialize ring buffer\n";
        ips_core_bpf__destroy(skel);
        return 1;
    }

    std::cout << "Cerberus IPS Active. Monitoring openat syscalls...\n";

    while (true) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0) break;
    }

    ring_buffer__free(rb);
    ips_core_bpf__destroy(skel);
    return 0;
}
