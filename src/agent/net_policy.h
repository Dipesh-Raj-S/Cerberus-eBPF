/*
 * Cerberus network policy management.
 *
 * Owns the network rule domain: domain normalization and
 * validation, IP parsing, the domain rule store, explicit
 * IP rules, network mode/runtime flags, and the per-address
 * verdict computation shared by the DNS module.
 */
#ifndef CERBERUS_AGENT_NET_POLICY_H
#define CERBERUS_AGENT_NET_POLICY_H

#include <map>
#include <string>
#include <vector>

#include "cerberus/common.h"
#include "policy.h"


/*
 * Formatting helpers.
 */
std::string net_format_addr(const struct net_addr& addr);
std::string net_format_addr_text(unsigned int family, const unsigned char* bytes);
std::string net_verdict_label(unsigned char verdict);

/*
 * Domain normalization.
 *
 * Rejects: empty, too long (> 63 chars), anything but
 * [a-z0-9-] labels, empty labels, labels starting or
 * ending with '-', IP literals (they belong in the IP
 * rules). Accepts Punycode (xn--...) labels as-is.
 */
bool net_domain_normalize(
    const std::string& text,
    std::string& out);

/*
 * IP parsing. Accepts dotted-quad IPv4 and full or
 * abbreviated IPv6 addresses. Returns the canonical text
 * form (via inet_ntop), the address family and the raw
 * bytes for BPF map keys.
 */
bool net_ip_parse(
    const std::string& text,
    std::string& canonical,
    unsigned int& family,
    unsigned char (&bytes)[16]);

struct net_addr net_addr_from_bytes(
    unsigned int family,
    const unsigned char (&bytes)[16]);

/*
 * Domain rules (block-domain / allow-domain).
 */
bool net_add_domain_rule(
    const policy_maps& maps,
    const std::string& domain,
    unsigned char rule_type /* DOMAIN_BLOCK or DOMAIN_ALLOW */);

bool net_remove_domain_rule(
    const policy_maps& maps,
    const std::string& domain,
    unsigned char rule_type /* DOMAIN_BLOCK or DOMAIN_ALLOW */);

/*
 * Explicit IP rules (block-ip / allow-ip).
 */
bool net_add_ip_rule(
    const policy_maps& maps,
    const std::string& ip_text,
    unsigned char rule_type /* IP_BLOCK or IP_ALLOW */);

bool net_remove_ip_rule(
    const policy_maps& maps,
    const std::string& ip_text,
    unsigned char rule_type);

/*
 * Network mode and runtime flags.
 */
bool net_mode_set(const policy_maps& maps, unsigned char mode);
unsigned char net_mode_get(const policy_maps& maps);

bool net_flags_set(const policy_maps& maps, unsigned char flags);
unsigned char net_flags_get(const policy_maps& maps);
bool net_flag_toggle(const policy_maps& maps, unsigned char bit, bool enable);

/*
 * Verdict computation.
 *
 * Given the domains a destination address has been seen
 * serving, decide which domain rule (if any) controls it.
 * Deny rules win over allow rules on conflicts (flagged
 * SHARED so shared-IP collateral is never silent).
 */
struct net_decision {
    struct net_addr addr;
    std::string rule;     /* matching rule key, "" if none */
    std::string assoc;    /* primary observed domain */
    unsigned char verdict;   /* CERBERUS_NET_VERDICT_NONE/ALLOW/DENY */
    unsigned char rule_type; /* DOMAIN_BLOCK / DOMAIN_ALLOW / NONE */
    unsigned char flags;     /* CERBERUS_EF_* pre-case */
};

net_decision net_compute_decision(
    const struct net_addr& addr,
    const std::string& primary_domain,
    const std::vector<std::string>& domains);

/*
 * Write a computed decision into the kernel map.
 * Returns false on map failures; caller decides policy.
 */
bool net_write_decision(
    const policy_maps& maps,
    const net_decision& d,
    unsigned long long expires_ns);

void net_delete_decision(
    const policy_maps& maps,
    const struct net_addr& addr);

/*
 * Rule change bookkeeping.
 *
 * A callback invoked whenever domain rules change so the
 * DNS module can sweep stored decisions.
 */
using net_rule_changed_fn = void (*)();
void net_set_rule_changed_callback(net_rule_changed_fn fn);

/*
 * Rule stores.
 */
const std::map<std::string, unsigned char>& net_domain_rules();

/*
 * Printable rule views.
 */
std::string net_domain_rule_label(const std::string& domain, unsigned char rule_type);
std::string net_ip_rule_label(const std::string& canonical, unsigned char rule_type);

void net_list_domain_rules();
void net_list_ip_rules(const policy_maps& maps);

unsigned int net_count_domain_rules();
unsigned int net_count_domain_rules_of(unsigned char rule_type);
unsigned int net_count_ip_rules(const policy_maps& maps);

#endif /* CERBERUS_AGENT_NET_POLICY_H */
