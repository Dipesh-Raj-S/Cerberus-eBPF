/*
 * Cerberus policy management.
 *
 * Owns the rule key codec, all BPF map updates, the
 * current policy mode and the printable rule view.
 */
#ifndef CERBERUS_AGENT_POLICY_H
#define CERBERUS_AGENT_POLICY_H

#include <string>

#include "cerberus/common.h"

/*
 * File descriptors of every policy-related map.
 *
 * Filled by the BPF loader once the program is
 * loaded and attached.
 */
struct policy_maps {
    int rules_fd;    /* blocklist          */
    int scoped_fd;   /* scoped_rules       */
    int allow_fd;    /* allowlist          */
    int sandbox_fd;  /* sandboxed          */
    int mode_fd;     /* policy_mode        */
    int net_block4_fd; /* net_block4       */
    int net_block6_fd; /* net_block6       */
    int net_allow4_fd; /* net_allow4       */
    int net_allow6_fd; /* net_allow6       */
    int net_mode_fd;   /* net_mode         */
};


/*
 * Input parsing.
 */
bool policy_parse_uid(const std::string& text, unsigned int& uid);

bool policy_make_name_key(
    const std::string& name,
    char (&key)[256]);

bool policy_make_path_key(
    const std::string& path,
    char (&key)[256]);

/*
 * Parse a user-supplied target: a path becomes
 * a PATH rule, a plain name becomes a NAME rule.
 */
bool policy_parse_target(
    const std::string& spec,
    char (&rule)[256],
    unsigned char& rule_type);


/*
 * Display helpers.
 */
std::string policy_decode_rule(
    const char (&key)[256],
    unsigned char rule_type);

std::string policy_rule_label(
    const char (&key)[256],
    unsigned char rule_type);

/*
 * Allowlist entries do not store a rule type, so
 * the layout of the key decides how to print it.
 */
std::string policy_decode_stored_rule(
    const char (&key)[256]);


/*
 * Global rules.
 */
bool policy_add_global(
    const policy_maps& maps,
    const char (&key)[256],
    unsigned char rule_type);

bool policy_remove_global(
    const policy_maps& maps,
    const char (&key)[256],
    unsigned char rule_type);


/*
 * Scoped rules.
 *
 * A process rule passes a real comm and
 * uid = CERBERUS_UID_ANY.
 *
 * A UID rule passes an empty comm and a real uid.
 */
bool policy_add_scoped(
    const policy_maps& maps,
    const std::string& comm,
    unsigned int uid,
    const char (&rule)[256],
    unsigned char rule_type);

bool policy_remove_scoped(
    const policy_maps& maps,
    const std::string& comm,
    unsigned int uid,
    const char (&rule)[256],
    unsigned char rule_type);


/*
 * Sandbox allowlist entries.
 */
bool policy_add_allow(
    const policy_maps& maps,
    const std::string& comm,
    const char (&rule)[256]);

bool policy_remove_allow(
    const policy_maps& maps,
    const std::string& comm,
    const char (&rule)[256]);

bool policy_set_sandbox(
    const policy_maps& maps,
    const std::string& comm,
    bool enable);


/*
 * Policy mode.
 */
bool policy_set_mode(int mode_fd, unsigned char mode);

unsigned char policy_get_mode(int mode_fd);


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
 * Printable state.
 */
void policy_list(const policy_maps& maps);

unsigned int policy_count_global(const policy_maps& maps);
unsigned int policy_count_scoped(const policy_maps& maps);
unsigned int policy_count_allow(const policy_maps& maps);
unsigned int policy_count_sandboxed(const policy_maps& maps);


#endif /* CERBERUS_AGENT_POLICY_H */
