#include "events.h"

#include <cstddef>
#include <iomanip>
#include <iostream>
#include <string>

#include <bpf/libbpf.h>

#include "cerberus/common.h"
#include "cli.h"
#include "net_events.h"
#include "policy.h"


static struct ring_buffer *g_ring_buffer = nullptr;

static unsigned long long g_event_count = 0;


/*
 * Called whenever the eBPF program reports
 * a matching access.
 */
static int handle_event(
    void *ctx,
    void *data,
    size_t data_sz)
{
    g_event_count++;

    /*
     * Records come through one shared ring buffer;
     * the record size distinguishes file events
     * (struct event) from network events
     * (struct net_event).
     */
    if (data_sz == sizeof(struct net_event))
    {
        print_net_event(
            static_cast<const struct net_event *>(data)
        );

        return 0;
    }

    const struct event *e =
        static_cast<const struct event *>(data);

    if (data_sz < sizeof(*e))
        return 0;

    std::string target;

    if (e->rule_type == CERBERUS_RULE_SANDBOX)
    {
        target =
            std::string("(sandbox default-deny) ") +
            policy_decode_rule(e->rule, e->rule_type);
    }
    else
    {
        target = policy_rule_label(e->rule, e->rule_type);
    }

    bool had_prompt = cli_prompt_active();

    if (had_prompt)
        std::cout << "\n";

    std::cout
        << (e->denied
            ? "\033[1;31m[BLOCKED INTRUSION]\033[0m "
            : "\033[1;33m[MONITOR ALERT]    \033[0m ")
        << "PID: "
        << std::setw(6)
        << e->pid
        << " | UID: "
        << std::setw(5)
        << e->uid
        << " | Process: "
        << std::setw(12)
        << e->comm
        << " | Target: "
        << target
        << std::endl;

    if (had_prompt)
        cli_print_prompt();

    return 0;
}


bool events_start(int ringbuf_fd)
{
    g_ring_buffer = ring_buffer__new(
        ringbuf_fd,
        handle_event,
        nullptr,
        nullptr
    );

    return g_ring_buffer != nullptr;
}


void events_stop()
{
    if (g_ring_buffer)
    {
        ring_buffer__free(g_ring_buffer);

        g_ring_buffer = nullptr;
    }
}


int events_poll(int timeout_ms)
{
    return ring_buffer__poll(
        g_ring_buffer,
        timeout_ms
    );
}


unsigned long long events_count()
{
    return g_event_count;
}
