/*
 * Cerberus IP-based network policy.
 *
 * Owns the IP address parsing and display codec, all
 * network block/allow BPF map updates, the net mode
 * and the printable network rule view.
 */
#ifndef CERBERUS_AGENT_POLICY_NET_H
#define CERBERUS_AGENT_POLICY_NET_H

#include <string>

#include "cerberus/common.h"
#include "policy.h"


/*
 * IP-based network policy.
 *
 * Rules are exact IPv4/IPv6 addresses. Precedence:
 * block rule > allow rule > default (allow).
 */
bool policy_net_parse_ip(
    const std::string& text,
    unsigned short& family,
    unsigned char (&addr)[16],
    std::string& canonical);

bool policy_net_add_block(
    const policy_maps& maps,
    const std::string& ip);

bool policy_net_remove_block(
    const policy_maps& maps,
    const std::string& ip);

bool policy_net_add_allow(
    const policy_maps& maps,
    const std::string& ip);

bool policy_net_remove_allow(
    const policy_maps& maps,
    const std::string& ip);

bool policy_net_set_mode(int net_mode_fd, unsigned char mode);

unsigned char policy_net_get_mode(int net_mode_fd);

unsigned int policy_net_count_blocks(const policy_maps& maps);
unsigned int policy_net_count_allows(const policy_maps& maps);

std::string policy_net_decode_addr(
    const unsigned char (&addr)[16],
    unsigned short family);

/*
 * Printable network rules section.
 */
void policy_net_list(const policy_maps& maps);


#endif /* CERBERUS_AGENT_POLICY_NET_H */
