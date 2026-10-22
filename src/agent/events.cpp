#include "events.h"

#include <cstddef>
#include <iomanip>
#include <iostream>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <bpf/libbpf.h>

#include "cerberus/common.h"
#include "cli.h"
#include "policy.h"


static struct ring_buffer *g_ring_buffer = nullptr;

static unsigned long long g_event_count = 0;


static std::string net_addr_text(const struct net_event *e)
{
    char buf[INET6_ADDRSTRLEN] = {};

    unsigned short af = (
        e->family == CERBERUS_AF_INET6 ? AF_INET6 : AF_INET
    );

    if (
        inet_ntop(
            af,
            e->addr,
            buf,
            sizeof(buf)
        ) == nullptr)
    {
        return "<malformed>";
    }

    return std::string(buf);
}


static std::string net_proto_text(const struct net_event *e)
{
    switch (e->protocol)
    {
    case CERBERUS_IPPROTO_TCP:
        return "tcp";

    case CERBERUS_IPPROTO_UDP:
        return "udp";

    default:
        return "proto " + std::to_string(e->protocol);
    }
}


static void print_net_event(const struct net_event *e)
{
    std::string tag;

    switch (e->verdict)
    {
    case CERBERUS_NET_VERDICT_DENIED:
        tag = "\033[1;31m[NET CONNECT BLOCKED]\033[0m";
        break;

    case CERBERUS_NET_VERDICT_BLOCKED_MONITOR:
        tag = "\033[1;33m[NET WOULD BLOCK   ]\033[0m";
        break;

    default:
        tag = "\033[1;32m[NET OUTBOUND      ]\033[0m";
        break;
    }

    if (e->matched_allow)
        tag += " (allow) ";

    if (e->matched_block)
        tag += " (block) ";

    bool had_prompt = cli_prompt_active();

    if (had_prompt)
        std::cout << "\n";

    std::cout
        << tag
        << " PID: "
        << std::setw(6)
        << e->pid
        << " | UID: "
        << std::setw(5)
        << e->uid
        << " | Process: "
        << std::setw(12)
        << e->comm
        << " | Target: "
        << net_addr_text(e)
        << ":"
        << ntohs(e->port)
        << " ("
        << net_proto_text(e)
        << ")"
        << std::endl;

    if (had_prompt)
        cli_print_prompt();
}


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
