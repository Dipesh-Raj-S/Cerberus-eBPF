/*
 * Cerberus event handling.
 *
 * Owns the BPF ring buffer, the alert output and the
 * lifetime event counter. Dispatches on evt_type:
 * file-access events, network connect events, and DNS
 * capture events.
 */
#include "events.h"

#include <arpa/inet.h>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include <time.h>

#include <bpf/libbpf.h>

#include "cerberus/common.h"
#include "cli.h"
#include "detection.h"
#include "dns.h"
#include "net_policy.h"
#include "policy.h"


static struct ring_buffer *g_ring_buffer = nullptr;

static unsigned long long g_event_count = 0;

static unsigned long long g_net_events = 0;


/*
 * Wall-clock-ish timestamp of a coarse-monotonic event
 * stamp: wall_now - (mono_now - event_mono).
 */
static void format_event_time(
    unsigned long long ts_ns,
    char (&out)[16])
{
    struct timespec mono = {};

    long long drift = 0;

    time_t wall = time(nullptr);

    out[0] = '\0';

    if (clock_gettime(CLOCK_MONOTONIC, &mono) != 0)
        return;

    unsigned long long now_ns =
        (unsigned long long)mono.tv_sec * 1000000000ULL +
        (unsigned long long)mono.tv_nsec;

    if (ts_ns != 0 && ts_ns <= now_ns && now_ns - ts_ns < 3600000000000ULL)
    {
        drift = (long long)((now_ns - ts_ns) / 1000000000ULL);

        wall -= drift;
    }

    char buf[9] = "";

    struct tm tmv = {};

    if (localtime_r(&wall, &tmv) != nullptr)
    {
        strftime(buf, sizeof(buf), "%H:%M:%S", &tmv);

        snprintf(out, sizeof(out), "%s", buf);
    }
}


static const char* net_proto_text(unsigned int proto)
{
    if (proto == CERBERUS_PROTO_TCP)
        return "tcp";

    if (proto == CERBERUS_PROTO_UDP)
        return "udp";

    return "ip";
}


/*
 * Matched-rule explanation for a network event:
 * what policy produced the verdict, and any extra
 * honesty notes.
 */
static std::string net_event_rule_text(const struct net_event* e)
{
    if (e->rule_type == CERBERUS_NET_RULE_IP_BLOCK ||
        e->rule_type == CERBERUS_NET_RULE_IP_ALLOW)
    {
        return std::string(
            e->rule_type == CERBERUS_NET_RULE_IP_BLOCK
                ? "block-ip "
                : "allow-ip ") +
            net_format_addr_text(e->family, e->dst);
    }

    if (e->rule_type == CERBERUS_NET_RULE_DOMAIN_BLOCK ||
        e->rule_type == CERBERUS_NET_RULE_DOMAIN_ALLOW)
    {
        return std::string(
            e->rule_type == CERBERUS_NET_RULE_DOMAIN_BLOCK
                ? "block-domain "
                : "allow-domain ") +
            e->rule;
    }

    if (e->rule_type == CERBERUS_NET_RULE_SUSPICIOUS)
        return "net-block-suspicious (shell + unmapped)";

    if (e->flags & CERBERUS_EF_DNS_EXEMPT)
        return "port-53 exemption";

    if (e->flags & CERBERUS_EF_DEFAULT_DENY)
    {
        if (e->flags & CERBERUS_EF_UNMAPPED)
            return "default-deny (unmapped destination)";

        return "default-deny (no allow rule for " +
            std::string(e->assoc) + ")";
    }

    if (e->flags & CERBERUS_EF_UNMAPPED)
        return "no matching rule (destination domain unknown)";

    return "no matching rule";
}


static void handle_net_event(
    void* /* ctx */,
    const struct net_event* e)
{
    std::string comm(
        e->comm,
        ::strnlen(e->comm, sizeof(e->comm))
    );

    char tbuf[16] = "";

    format_event_time(e->ts, tbuf);

    g_net_events++;

    bool had_prompt = cli_prompt_active();

    if (had_prompt)
        std::cout << "\n";

    /*
     * Blocked: connect() will really fail with -EPERM.
     */
    if (e->denied)
    {
        std::cout
            << "\033[1;31m[NET BLOCKED]     \033[0m "
            << tbuf << " | "
            << "PID: " << e->pid
            << " | UID: " << e->uid
            << " | Process: " << comm
            << " | Dest: "
            << net_format_addr_text(e->family, e->dst)
            << ":" << e->port
            << "/" << net_proto_text(e->proto)
            << " | Match: " << net_event_rule_text(e);

        if (e->assoc[0])
            std::cout << " | via: " << e->assoc;

        if (e->flags & CERBERUS_EF_SHARED_HOST)
            std::cout
                << " | (shared IP; deny wins over allow "
                << "and may affect other domains on this address)";

        if (e->flags & CERBERUS_EF_SUSPICIOUS)
            std::cout
                << " | (reverse-shell heuristic)";

        std::cout << std::endl;
    }
    else
    {
        std::cout
            << "\033[1;33m[NET " << (e->flags & CERBERUS_EF_DNS_EXEMPT ? "PORT-53 EXEMPT" : "MONITOR") << "]   \033[0m "
            << tbuf << " | "
            << "PID: " << e->pid
            << " | UID: " << e->uid
            << " | Process: " << comm
            << " | Dest: "
            << net_format_addr_text(e->family, e->dst)
            << ":" << e->port
            << "/" << net_proto_text(e->proto)
            << " | " << net_event_rule_text(e);

        if (e->flags & CERBERUS_EF_WOULD_DENY)
            std::cout
                << " | (would deny in enforce mode)";

        if (e->assoc[0])
            std::cout << " | via: " << e->assoc;

        if (e->flags & CERBERUS_EF_SHARED_HOST)
            std::cout
                << " | (shared IP; deny wins over allow)";

        if (e->suppressed)
            std::cout
                << " | (" << e->suppressed
                << " earlier events suppressed by rate limit)";

        std::cout << std::endl;
    }

    detection_handle_event(*e);

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
    if (data_sz < 12)
        return 0;

    const struct event *e =
        static_cast<const struct event *>(data);

    unsigned char evt_type = e->evt_type;

    if (evt_type == CERBERUS_EVT_FILE_OPEN)
    {
        if (data_sz < sizeof(struct event))
            return 0;

        g_event_count++;

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

    if (evt_type == CERBERUS_EVT_NET_CONNECT)
    {
        if (data_sz < sizeof(struct net_event))
            return 0;

        g_event_count++;

        handle_net_event(
            ctx,
            static_cast<const struct net_event *>(data)
        );

        return 0;
    }

    if (evt_type == CERBERUS_EVT_DNS_RESPONSE)
    {
        if (data_sz < sizeof(struct dns_event))
            return 0;

        dns_handle_event(
            static_cast<const struct dns_event *>(data)
        );

        return 0;
    }

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


unsigned long long events_net_count()
{
    return g_net_events;
}
