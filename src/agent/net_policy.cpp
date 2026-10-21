#include "net_policy.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <map>

#include <bpf/bpf.h>

#include "cerberus/common.h"


/*
 * Network rule stores. std::map keeps the listing order
 * stable across calls.
 */
static std::map<std::string, unsigned char> g_domain_rules;

static std::map<std::string, unsigned char> g_ip_rules;

static net_rule_changed_fn g_rule_changed = nullptr;


const std::map<std::string, unsigned char>& net_domain_rules()
{
    return g_domain_rules;
}


void net_set_rule_changed_callback(net_rule_changed_fn fn)
{
    g_rule_changed = fn;
}


static void notify_rule_changed()
{
    if (g_rule_changed)
        g_rule_changed();
}


std::string net_format_addr(const struct net_addr& addr)
{
    char text[INET6_ADDRSTRLEN] = "";

    if (addr.family == CERBERUS_AF_INET)
        inet_ntop(AF_INET, addr.addr, text, sizeof(text));
    else if (addr.family == CERBERUS_AF_INET6)
        inet_ntop(AF_INET6, addr.addr, text, sizeof(text));
    else
        return "?";

    return text;
}


std::string net_format_addr_text(unsigned int family, const unsigned char* bytes)
{
    struct net_addr addr = {};

    addr.family = family;

    std::memcpy(addr.addr, bytes, sizeof(addr.addr));

    return net_format_addr(addr);
}


std::string net_verdict_label(unsigned char verdict)
{
    if (verdict == CERBERUS_NET_VERDICT_ALLOW)
        return "ALLOW";

    if (verdict == CERBERUS_NET_VERDICT_DENY)
        return "DENY";

    return "NONE";
}


bool net_domain_normalize(
    const std::string& text,
    std::string& out)
{
    std::string d = text;

    /*
     * Lowercase and strip a single trailing dot.
     */
    for (char& c : d)
    {
        if (c >= 'A' && c <= 'Z')
            c = char(c - 'A' + 'a');
    }

    if (!d.empty() && d.back() == '.')
        d.pop_back();

    if (d.empty() || d.size() >= CERBERUS_NET_DOMAIN_MAX)
    {
        std::cerr
            << "[-] Domain must be 1-"
            << CERBERUS_NET_DOMAIN_MAX - 1
            << " characters: "
            << text
            << "\n";

        return false;
    }

    /*
     * Reject IP literals: IP filtering belongs in the
     * explicit IP rules.
     */
    {
        struct in_addr tmp4;
        struct in6_addr tmp6;

        if (inet_pton(AF_INET, d.c_str(), &tmp4) == 1 ||
            inet_pton(AF_INET6, d.c_str(), &tmp6) == 1)
        {
            std::cerr
                << "[-] '" << text
                << "' is an IP address; use block-ip / allow-ip\n";

            return false;
        }
    }

    /*
     * RFC-style sanity: labels of [0-9a-z-], 1-63 chars,
     * not starting or ending with '-'.
     */
    {
        size_t i = 0;

        size_t label_start = 0;

        for (; i <= d.size(); i++)
        {
            char c = i < d.size() ? d[i] : '\0';

            bool end_of_label =
                (i == d.size() || c == '.');

            if (!end_of_label)
            {
                bool ok =
                    (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'z') ||
                    c == '-';

                if (!ok)
                {
                    std::cerr
                        << "[-] Invalid character '" << c
                        << "' in domain: " << text << "\n"
                        << "[-] Only [a-z0-9-] labels are accepted "
                        << "(Punycode 'xn--' names welcome)\n";

                    return false;
                }

                continue;
            }

            size_t label_len = i - label_start;

            if (label_len == 0 || label_len > 63)
            {
                std::cerr
                    << "[-] Empty or over-long domain label in '"
                    << text << "'\n";

                return false;
            }

            if (d[label_start] == '-' || d[i == d.size() ? d.size() - 1 : i - 1] == '-')
            {
                std::cerr
                    << "[-] Domain labels must not start or end "
                    << "with '-': " << text << "\n";

                return false;
            }

            label_start = i + 1;
        }
    }

    out = d;

    return true;
}


bool net_ip_parse(
    const std::string& text,
    std::string& canonical,
    unsigned int& family,
    unsigned char (&bytes)[16])
{
    struct in_addr v4;
    struct in6_addr v6;

    char nbuf[INET6_ADDRSTRLEN] = "";

    bytes[0] = '\0';

    std::memset(bytes, 0, sizeof(bytes));

    if (inet_pton(AF_INET, text.c_str(), &v4) == 1)
    {
        family = CERBERUS_AF_INET;

        if (!inet_ntop(AF_INET, &v4, nbuf, sizeof(nbuf)))
            return false;

        canonical = nbuf;

        std::memcpy(
            bytes,
            &v4,
            sizeof(v4)
        );

        return true;
    }

    if (inet_pton(AF_INET6, text.c_str(), &v6) == 1)
    {
        family = CERBERUS_AF_INET6;

        if (!inet_ntop(AF_INET6, &v6, nbuf, sizeof(nbuf)))
            return false;

        canonical = nbuf;

        std::memcpy(
            bytes,
            &v6,
            sizeof(v6)
        );

        return true;
    }

    return false;
}


struct net_addr net_addr_from_bytes(
    unsigned int family,
    const unsigned char (&bytes)[16])
{
    struct net_addr addr = {};

    addr.family = family;

    std::memcpy(
        addr.addr,
        bytes,
        sizeof(addr.addr)
    );

    return addr;
}


static std::string net_rule_suffix_match(
    const std::string& domain,
    unsigned char rule_type)
{
    /*
     * The rule matches the domain when the domain is
     * exactly the rule, or the domain ends in "." + rule
     * (subdomain matching is suffix-based, explicit and
     * asymmetric: rule "example.com" covers
     * "mail.example.com", but not vice versa).
     */
    const std::map<std::string, unsigned char>& rules = net_domain_rules();

    auto it = rules.find(domain);

    if (it != rules.end() && it->second == rule_type)
        return domain;

    size_t pos = 0;

    while (true)
    {
        pos = domain.find('.', pos);

        if (pos == std::string::npos)
            break;

        std::string suffix = domain.substr(pos + 1);

        auto it2 = rules.find(suffix);

        if (it2 != rules.end() && it2->second == rule_type)
            return suffix;

        pos = pos + 1;
    }

    return "";
}


static void update_ip_rule(
    const struct net_addr& addr,
    unsigned char rule_type,
    bool add)
{
    std::string ip = net_format_addr(addr);

    if (add)
        g_ip_rules[ip] = rule_type;
    else
        g_ip_rules.erase(ip);
}


static bool kernel_ip_rule_apply(
    const policy_maps& maps,
    const struct net_addr& addr,
    unsigned char rule_type,
    bool add)
{
    struct net_ip_rule value = {};

    std::memset(&value, 0, sizeof(value));

    if (rule_type == CERBERUS_NET_RULE_IP_BLOCK)
        value.verdict = CERBERUS_NET_VERDICT_DENY;
    else
        value.verdict = CERBERUS_NET_VERDICT_ALLOW;

    value.rule_type = rule_type;

    int ret = add
        ? bpf_map_update_elem(
            maps.net_ip_rules_fd,
            &addr,
            &value,
            BPF_ANY)
        : bpf_map_delete_elem(
            maps.net_ip_rules_fd,
            &addr);

    if (ret != 0)
    {
        std::cerr
            << "[-] Failed to "
            << (add ? "add" : "remove")
            << " IP rule: "
            << strerror(errno)
            << "\n";

        return false;
    }

    return true;
}


bool net_add_domain_rule(
    const policy_maps& maps,
    const std::string& domain,
    unsigned char rule_type)
{
    std::string norm;

    if (!net_domain_normalize(domain, norm))
        return false;

    if (
        g_domain_rules.count(norm) > 0 &&
        g_domain_rules[norm] == rule_type)
    {
        std::cerr
            << "[-] Domain rule already exists: "
            << net_domain_rule_label(norm, rule_type)
            << "\n";

        return false;
    }

    g_domain_rules[norm] = rule_type;

    notify_rule_changed();

    std::cout
        << "[+] Network rule added: "
        << net_domain_rule_label(norm, rule_type)
        << "\n";

    return true;
}


bool net_remove_domain_rule(
    const policy_maps& maps,
    const std::string& domain,
    unsigned char rule_type)
{
    std::string norm;

    if (!net_domain_normalize(domain, norm))
        return false;

    auto it = g_domain_rules.find(norm);

    if (it == g_domain_rules.end())
    {
        std::cerr
            << "[-] Domain rule not found: "
            << net_domain_rule_label(norm, rule_type)
            << "\n";

        return false;
    }

    g_domain_rules.erase(it);

    notify_rule_changed();

    std::cout
        << "[+] Network rule removed: "
        << net_domain_rule_label(norm, rule_type)
        << "\n";

    return true;
}


bool net_add_ip_rule(
    const policy_maps& maps,
    const std::string& ip_text,
    unsigned char rule_type)
{
    std::string canonical;
    unsigned int family = 0;
    unsigned char bytes[16];

    if (!net_ip_parse(ip_text, canonical, family, bytes))
    {
        std::cerr
            << "[-] Invalid IP address: "
            << ip_text
            << "\n";

        return false;
    }

    struct net_addr addr = net_addr_from_bytes(family, bytes);

    if (kernel_ip_rule_apply(maps, addr, rule_type, true) == false)
        return false;

    update_ip_rule(addr, rule_type, true);

    std::cout
        << "[+] Network rule added: "
        << net_ip_rule_label(canonical, rule_type)
        << "\n";

    return true;
}


bool net_remove_ip_rule(
    const policy_maps& maps,
    const std::string& ip_text,
    unsigned char rule_type)
{
    std::string canonical;
    unsigned int family = 0;
    unsigned char bytes[16];

    if (!net_ip_parse(ip_text, canonical, family, bytes))
    {
        std::cerr
            << "[-] Invalid IP address: "
            << ip_text
            << "\n";

        return false;
    }

    struct net_addr addr = net_addr_from_bytes(family, bytes);

    if (kernel_ip_rule_apply(maps, addr, rule_type, false) == false)
    {
        std::cerr
            << "[-] IP rule not found: "
            << net_ip_rule_label(canonical, rule_type)
            << "\n";

        return false;
    }

    update_ip_rule(addr, rule_type, false);

    std::cout
        << "[+] Network rule removed: "
        << net_ip_rule_label(canonical, rule_type)
        << "\n";

    return true;
}


bool net_mode_set(const policy_maps& maps, unsigned char mode)
{
    unsigned int zero = 0;

    return bpf_map_update_elem(
        maps.net_mode_fd,
        &zero,
        &mode,
        BPF_ANY
    ) == 0;
}


unsigned char net_mode_get(const policy_maps& maps)
{
    unsigned int zero = 0;
    unsigned char mode = CERBERUS_NET_MODE_MONITOR;

    if (
        bpf_map_lookup_elem(
            maps.net_mode_fd,
            &zero,
            &mode
        ) != 0)
    {
        return CERBERUS_NET_MODE_MONITOR;
    }

    return mode;
}


bool net_flags_set(const policy_maps& maps, unsigned char flags)
{
    unsigned int zero = 0;

    return bpf_map_update_elem(
        maps.net_flags_fd,
        &zero,
        &flags,
        BPF_ANY
    ) == 0;
}


unsigned char net_flags_get(const policy_maps& maps)
{
    unsigned int zero = 0;
    unsigned char flags = 0;

    if (
        bpf_map_lookup_elem(
            maps.net_flags_fd,
            &zero,
            &flags
        ) != 0)
    {
        return 0;
    }

    return flags;
}


bool net_flag_toggle(const policy_maps& maps, unsigned char bit, bool enable)
{
    unsigned char flags = net_flags_get(maps);

    if (enable)
        flags = static_cast<unsigned char>(flags | bit);
    else
        flags = static_cast<unsigned char>(flags & ~bit);

    return net_flags_set(maps, flags);
}


net_decision net_compute_decision(
    const struct net_addr& addr,
    const std::string& primary_domain,
    const std::vector<std::string>& domains)
{
    net_decision d = {};

    d.addr = addr;

    std::string deny_rule;
    std::string allow_rule;

    for (const std::string& dom : domains)
    {
        std::string matched;

        matched = net_rule_suffix_match(dom, CERBERUS_NET_RULE_DOMAIN_BLOCK);

        if (!matched.empty() &&
            (deny_rule.empty() || matched.size() < deny_rule.size()))
            deny_rule = matched;

        matched = net_rule_suffix_match(dom, CERBERUS_NET_RULE_DOMAIN_ALLOW);

        if (!matched.empty() &&
            (allow_rule.empty() || matched.size() < allow_rule.size()))
            allow_rule = matched;
    }

    /*
     * Deny wins over allow, flagged SHARED so that any
     * shared-IP side-effects are visible in the alerts
     * instead of silently applying.
     */
    if (!deny_rule.empty() && !allow_rule.empty() && deny_rule != allow_rule)
        d.flags |= CERBERUS_EF_SHARED_HOST;

    if (!deny_rule.empty())
    {
        d.verdict = CERBERUS_NET_VERDICT_DENY;
        d.rule_type = CERBERUS_NET_RULE_DOMAIN_BLOCK;
        d.rule = deny_rule;
    }
    else if (!allow_rule.empty())
    {
        d.verdict = CERBERUS_NET_VERDICT_ALLOW;
        d.rule_type = CERBERUS_NET_RULE_DOMAIN_ALLOW;
        d.rule = allow_rule;
    }
    else
    {
        d.verdict = CERBERUS_NET_VERDICT_NONE;
        d.rule_type = CERBERUS_NET_RULE_NONE;
        d.rule = "";
    }

    d.assoc = primary_domain;

    return d;
}


bool net_write_decision(
    const policy_maps& maps,
    const net_decision& d,
    unsigned long long expires_ns)
{
    struct net_ip_decision value = {};

    std::memset(&value, 0, sizeof(value));

    value.verdict =
        (d.verdict == CERBERUS_NET_VERDICT_DENY)
            ? CERBERUS_NET_VERDICT_DENY
            : d.verdict;

    value.rule_type = d.rule_type;

    value.flags = d.flags;

    strncpy(
        value.domain,
        d.rule.c_str(),
        CERBERUS_NET_DOMAIN_MAX - 1
    );

    strncpy(
        value.assoc,
        d.assoc.c_str(),
        CERBERUS_NET_DOMAIN_MAX - 1
    );

    value.expires = expires_ns;

    return bpf_map_update_elem(
        maps.net_ip_decisions_fd,
        &d.addr,
        &value,
        BPF_ANY
    ) == 0;
}


void net_delete_decision(
    const policy_maps& maps,
    const struct net_addr& addr)
{
    bpf_map_delete_elem(
        maps.net_ip_decisions_fd,
        &addr
    );
}


std::string net_domain_rule_label(
    const std::string& domain,
    unsigned char rule_type)
{
    if (rule_type == CERBERUS_NET_RULE_DOMAIN_ALLOW)
        return "allow " + domain;

    return "block " + domain;
}


std::string net_ip_rule_label(
    const std::string& canonical,
    unsigned char rule_type)
{
    if (rule_type == CERBERUS_NET_RULE_IP_ALLOW)
        return "allow " + canonical;

    return "block " + canonical;
}


void net_list_domain_rules()
{
    bool found = false;

    std::cout
        << "---------- domain rules -------------\n";

    for (const auto& entry : g_domain_rules)
    {
        std::cout
            << "["
            << net_domain_rule_label(entry.first, entry.second)
            << "]\n";

        found = true;
    }

    if (!found)
        std::cout << "[EMPTY] No domain rules loaded\n";
}


void net_list_ip_rules(const policy_maps& maps)
{
    bool found = false;

    std::cout
        << "---------- IP rules -----------------\n";

    for (const auto& entry : g_ip_rules)
    {
        std::cout
            << "["
            << net_ip_rule_label(entry.first, entry.second)
            << "]\n";

        found = true;
    }

    if (!found)
        std::cout << "[EMPTY] No IP rules loaded\n";
}


unsigned int net_count_domain_rules()
{
    return static_cast<unsigned int>(g_domain_rules.size());
}


unsigned int net_count_domain_rules_of(unsigned char rule_type)
{
    unsigned int n = 0;

    for (const auto& entry : g_domain_rules)
    {
        if (entry.second == rule_type)
            n++;
    }

    return n;
}


unsigned int net_count_ip_rules(const policy_maps& maps)
{
    return static_cast<unsigned int>(g_ip_rules.size());
}
