/*
 * Standalone unit test for the network policy logic.
 *
 * Covers the parts that do not need kernel access:
 *   - domain normalization rules,
 *   - IP parsing and canonicalization,
 *   - suffix-based domain matching,
 *   - verdict computation (deny wins over allow, shared
 *     host flagging).
 *
 * Runs as an unprivileged user; no BPF programs are
 * loaded.
 *
 * Usage:
 *   bash tests/test_units.sh
 */

#include <iostream>
#include <string>
#include <vector>

#include "cerberus/common.h"
#include "net_policy.h"

static int pass = 0;
static int fail = 0;

static void expect_eq(
    const char* desc,
    const std::string& expected,
    const std::string& actual)
{
    if (expected == actual)
    {
        std::cout << "PASS: " << desc << "\n";
        pass++;
    }
    else
    {
        std::cout
            << "FAIL: " << desc
            << " (expected '" << expected
            << "', got '" << actual << "')\n";
        fail++;
    }
}

static void expect_bool(
    const char* desc,
    bool expected,
    bool actual)
{
    expect_eq(desc, expected ? "yes" : "no", actual ? "yes" : "no");
}

int main()
{
    std::string out;

    /*
     * Domain normalization.
     */
    expect_bool("accepts simple domain",
        net_domain_normalize("Example.COM.", out), true);
    expect_eq("lowercases and strips trailing dot",
        "example.com", out);

    expect_bool("rejects empty domain",
        net_domain_normalize("", out), false);

    expect_bool("rejects over-long domain",
        net_domain_normalize(std::string(64, 'a') + ".com", out), false);

    expect_bool("rejects empty label",
        net_domain_normalize("a..b", out), false);

    expect_bool("rejects leading dash label",
        net_domain_normalize("-bad.example.com", out), false);

    expect_bool("rejects trailing dash label",
        net_domain_normalize("bad-.example.com", out), false);

    expect_bool("rejects underscore",
        net_domain_normalize("my_host.example.com", out), false);

    expect_bool("rejects IP literal",
        net_domain_normalize("10.0.0.1", out), false);

    expect_bool("accepts punycode",
        net_domain_normalize("xn--80ak6aa92e.com", out), true);

    /*
     * IP parsing.
     */
    std::string canonical;
    unsigned int family = 0;
    unsigned char bytes[16];

    expect_bool("parses IPv4",
        net_ip_parse("192.0.2.5", canonical, family, bytes), true);
    expect_eq("canonizes IPv4", "192.0.2.5", canonical);
    expect_eq("IPv4 family", "2", std::to_string(family));

    expect_bool("parses IPv6",
        net_ip_parse("2001:0DB8:0000::1", canonical, family, bytes), true);
    expect_eq("canonizes IPv6", "2001:db8::1", canonical);
    expect_eq("IPv6 family", "10", std::to_string(family));

    expect_bool("rejects bad IP",
        net_ip_parse("999.1.1.1", canonical, family, bytes), false);

    expect_bool("rejects word",
        net_ip_parse("banana", canonical, family, bytes), false);

    /*
     * Round-trip in isolation: a failing parse zeroes the
     * buffer, so reparse right before formatting.
     */
    net_ip_parse("192.0.2.5", canonical, family, bytes);

    expect_eq("net_format_addr round-trip",
        "192.0.2.5",
        net_format_addr(net_addr_from_bytes(
            CERBERUS_AF_INET, bytes)));

    /*
     * Verdict computation. Rules are added through the
     * public API; the callback is unset, so kernel map
     * writes would fail if any were attempted — none are,
     * because maps are not initialized here.
     */
    net_add_domain_rule(
        policy_maps{},
        "example.com",
        CERBERUS_NET_RULE_DOMAIN_BLOCK);

    struct net_addr addr = {};
    addr.family = CERBERUS_AF_INET;
    addr.addr[0] = 203;
    addr.addr[1] = 0;
    addr.addr[2] = 113;
    addr.addr[3] = 7;

    {
        net_decision d = net_compute_decision(
            addr,
            "mail.example.com",
            {"mail.example.com"});

        expect_eq("block parent rules the subdomain",
            "DENY", net_verdict_label(d.verdict));
        expect_eq("matched rule is reported",
            "example.com", d.rule);
    }

    /*
     * Remove the exact rule so only the more specific
     * "deep.example.com" block remains, then check that
     * rules never cover their own parent domain.
     */
    net_remove_domain_rule(
        policy_maps{},
        "example.com",
        CERBERUS_NET_RULE_DOMAIN_BLOCK);

    net_add_domain_rule(
        policy_maps{},
        "deep.example.com",
        CERBERUS_NET_RULE_DOMAIN_BLOCK);

    {
        net_decision d = net_compute_decision(
            addr,
            "example.com",
            {"example.com"});

        expect_eq("rule does not cover its own parent",
            "NONE", net_verdict_label(d.verdict));
    }

    {
        net_decision d = net_compute_decision(
            addr,
            "other.example.net",
            {"other.example.net"});

        expect_eq("unrelated domain is unmapped",
            "NONE", net_verdict_label(d.verdict));
    }

    net_add_domain_rule(
        policy_maps{},
        "safe.example.net",
        CERBERUS_NET_RULE_DOMAIN_ALLOW);

    {
        net_decision d = net_compute_decision(
            addr,
            "safe.example.net",
            {"safe.example.net"});

        expect_eq("allow rule matches exact domain",
            "ALLOW", net_verdict_label(d.verdict));
    }

    /*
     * Conflict case: re-add the parent block rule so that
     * "mild.example.com" matches the allow rule exactly
     * AND the block rule by suffix. Deny wins, and the
     * conflict is flagged so shared-IP effects are never
     * silent.
     */
    net_add_domain_rule(
        policy_maps{},
        "example.com",
        CERBERUS_NET_RULE_DOMAIN_BLOCK);

    net_add_domain_rule(
        policy_maps{},
        "mild.example.com",
        CERBERUS_NET_RULE_DOMAIN_ALLOW);

    {
        net_decision d = net_compute_decision(
            addr,
            "mild.example.com",
            {"mild.example.com"});

        expect_eq("deny wins over allow",
            "DENY", net_verdict_label(d.verdict));
        expect_eq("shared host flagged",
            "2", std::to_string(
                (d.flags & CERBERUS_EF_SHARED_HOST)
                    ? CERBERUS_EF_SHARED_HOST
                    : 0));
    }

    std::cout << "\nUnit tests: pass=" << pass
              << " fail=" << fail << "\n";

    return fail == 0 ? 0 : 1;
}
