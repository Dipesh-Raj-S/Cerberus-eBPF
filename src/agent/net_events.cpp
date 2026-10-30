#include "net_events.h"

#include <iomanip>
#include <iostream>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "cerberus/common.h"
#include "cli.h"


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


void print_net_event(const struct net_event *e)
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
