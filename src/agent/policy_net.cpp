#include "policy_net.h"

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <bpf/bpf.h>

#include "cerberus/common.h"
#include "util.h"


/*
 * Validate and canonicalize an IP address literal.
 *
 * The address is stored in network byte order, exactly
 * as the BPF hook reads it from the sockaddr, so both
 * sides agree on byte layout. For IPv4 only the first
 * four bytes are populated.
 */
bool policy_net_parse_ip(
    const std::string& text,
    unsigned short& family,
    unsigned char (&addr)[16],
    std::string& canonical)
{
    std::string cleaned = trim_text(text);

    if (
        cleaned.empty() ||
        cleaned.find_first_of(" \t\n\r") != std::string::npos)
    {
        std::cerr
            << "[-] Expected a single IPv4 or IPv6 address\n";

        return false;
    }

    unsigned char raw[16] = {};

    if (cleaned.find(':') != std::string::npos)
    {
        if (
            inet_pton(
                AF_INET6,
                cleaned.c_str(),
                raw
            ) != 1)
        {
            std::cerr
                << "[-] Invalid IPv6 address: "
                << cleaned
                << "\n";

            return false;
        }

        family = AF_INET6;
    }
    else
    {
        if (
            inet_pton(
                AF_INET,
                cleaned.c_str(),
                raw
            ) != 1)
        {
            std::cerr
                << "[-] Invalid IPv4 address: "
                << cleaned
                << "\n";

            return false;
        }

        family = AF_INET;
    }

    char printed[INET6_ADDRSTRLEN] = {};

    if (
        inet_ntop(
            family,
            raw,
            printed,
            sizeof(printed)
        ) == nullptr ||
        printed[0] == 0)
    {
        std::cerr
            << "[-] Could not canonicalize address\n";

        return false;
    }

    std::memset(addr, 0, sizeof(addr));

    size_t bytes = (
        family == AF_INET6 ? 16 : 4
    );

    std::memcpy(addr, raw, bytes);

    canonical = printed;

    return true;
}


static std::string net_key_text(
    unsigned short family,
    const void *key)
{
    char buf[INET6_ADDRSTRLEN] = {};

    if (
        inet_ntop(
            family,
            key,
            buf,
            sizeof(buf)
        ) == nullptr)
    {
        return "<malformed>";
    }

    return std::string(buf);
}


std::string policy_net_decode_addr(
    const unsigned char (&addr)[16],
    unsigned short family)
{
    return net_key_text(
        family,
        static_cast<const void *>(addr)
    );
}


static bool net_add_rule(
    int fd,
    const unsigned char (&addr)[16],
    unsigned short family,
    const std::string& kind)
{
    unsigned char marker = 1;

    if (
        bpf_map_update_elem(
            fd,
            addr,
            &marker,
            BPF_ANY
        ) != 0)
    {
        std::cerr
            << "[-] Failed to add IP "
            << kind
            << " rule: "
            << strerror(errno)
            << "\n";

        return false;
    }

    std::cout
        << "[+] IP "
        << kind
        << " rule added: "
        << net_key_text(family, addr)
        << "\n";

    return true;
}


static bool net_remove_rule(
    int fd,
    const unsigned char (&addr)[16],
    unsigned short family,
    const std::string& kind)
{
    if (
        bpf_map_delete_elem(
            fd,
            addr
        ) != 0)
    {
        std::cerr
            << "[-] IP "
            << kind
            << " rule not found: "
            << net_key_text(family, addr)
            << "\n";

        return false;
    }

    std::cout
        << "[+] IP "
        << kind
        << " rule removed: "
        << net_key_text(family, addr)
        << "\n";

    return true;
}


/*
 * Warn when an IP is present in both rule kinds so an
 * operator never mistakes what the predictable
 * precedence (block wins) will do.
 */
static void warn_conflicting_rule(
    const policy_maps& maps,
    const unsigned char (&addr)[16],
    unsigned short family,
    bool adding_allow)
{
    int other_fd;

    if (adding_allow)
    {
        other_fd = (
            family == AF_INET6
                ? maps.net_block6_fd
                : maps.net_block4_fd
        );
    }
    else
    {
        other_fd = (
            family == AF_INET6
                ? maps.net_allow6_fd
                : maps.net_allow4_fd
        );
    }

    unsigned char marker = 0;

    if (
        bpf_map_lookup_elem(
            other_fd,
            addr,
            &marker
        ) == 0)
    {
        std::cout
            << "[!] Warning: this IP also has a conflicting rule; "
            << "the BLOCK rule takes precedence\n";
    }
}


bool policy_net_add_block(
    const policy_maps& maps,
    const std::string& ip)
{
    unsigned short family = 0;
    unsigned char addr[16] = {};
    std::string canonical;

    if (!policy_net_parse_ip(ip, family, addr, canonical))
        return false;

    int fd = (
        family == AF_INET6
            ? maps.net_block6_fd
            : maps.net_block4_fd
    );

    if (!net_add_rule(fd, addr, family, "block"))
        return false;

    warn_conflicting_rule(maps, addr, family, false);

    return true;
}


bool policy_net_remove_block(
    const policy_maps& maps,
    const std::string& ip)
{
    unsigned short family = 0;
    unsigned char addr[16] = {};
    std::string canonical;

    if (!policy_net_parse_ip(ip, family, addr, canonical))
        return false;

    int fd = (
        family == AF_INET6
            ? maps.net_block6_fd
            : maps.net_block4_fd
    );

    return net_remove_rule(fd, addr, family, "block");
}


bool policy_net_add_allow(
    const policy_maps& maps,
    const std::string& ip)
{
    unsigned short family = 0;
    unsigned char addr[16] = {};
    std::string canonical;

    if (!policy_net_parse_ip(ip, family, addr, canonical))
        return false;

    int fd = (
        family == AF_INET6
            ? maps.net_allow6_fd
            : maps.net_allow4_fd
    );

    if (!net_add_rule(fd, addr, family, "allow"))
        return false;

    warn_conflicting_rule(maps, addr, family, true);

    return true;
}


bool policy_net_remove_allow(
    const policy_maps& maps,
    const std::string& ip)
{
    unsigned short family = 0;
    unsigned char addr[16] = {};
    std::string canonical;

    if (!policy_net_parse_ip(ip, family, addr, canonical))
        return false;

    int fd = (
        family == AF_INET6
            ? maps.net_allow6_fd
            : maps.net_allow4_fd
    );

    return net_remove_rule(fd, addr, family, "allow");
}


bool policy_net_set_mode(int net_mode_fd, unsigned char mode)
{
    unsigned int zero = 0;

    return bpf_map_update_elem(
        net_mode_fd,
        &zero,
        &mode,
        BPF_ANY
    ) == 0;
}


unsigned char policy_net_get_mode(int net_mode_fd)
{
    unsigned int zero = 0;
    unsigned char mode = CERBERUS_MODE_MONITOR;

    if (
        bpf_map_lookup_elem(
            net_mode_fd,
            &zero,
            &mode
        ) != 0)
    {
        return CERBERUS_MODE_MONITOR;
    }

    return mode;
}


unsigned int policy_net_count_blocks(const policy_maps& maps)
{
    return count_map_entries(maps.net_block4_fd, 4) +
           count_map_entries(maps.net_block6_fd, 16);
}


unsigned int policy_net_count_allows(const policy_maps& maps)
{
    return count_map_entries(maps.net_allow4_fd, 4) +
           count_map_entries(maps.net_allow6_fd, 16);
}


/*
 * Walk a hash map of fixed-size keys and print each
 * one as an IP literal.
 */
static void list_net_map(
    int fd,
    size_t key_size,
    unsigned short family,
    const char* tag)
{
    unsigned char key[16] = {};
    unsigned char next_key[16] = {};

    bool first = true;
    bool found = false;

    while (
        bpf_map_get_next_key(
            fd,
            first ? nullptr : key,
            next_key
        ) == 0)
    {
        first = false;

        std::memcpy(
            key,
            next_key,
            key_size
        );

        std::cout
            << "[" << tag << "] "
            << net_key_text(family, next_key)
            << "\n";

        found = true;
    }

    if (!found)
        std::cout
            << "[EMPTY] No IP " << tag << " rules\n";
}


void policy_net_list(const policy_maps& maps)
{
    list_net_map(
        maps.net_block4_fd,
        4,
        AF_INET,
        "BLOCK4"
    );

    list_net_map(
        maps.net_block6_fd,
        16,
        AF_INET6,
        "BLOCK6"
    );

    list_net_map(
        maps.net_allow4_fd,
        4,
        AF_INET,
        "ALLOW4"
    );

    list_net_map(
        maps.net_allow6_fd,
        16,
        AF_INET6,
        "ALLOW6"
    );
}
