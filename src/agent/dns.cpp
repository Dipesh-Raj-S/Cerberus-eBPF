#include "dns.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cerberus/common.h"
#include "ips_core.skel.h"
#include "net_policy.h"


/*
 * Association state for one destination address.
 */
struct dns_assoc {
    unsigned long long expires;          /* CLOCK_MONOTONIC ns */
    unsigned long long seen;             /* mono ns of last update */
    std::vector<std::string> domains;    /* newest first, capped */
};

#define CERBERUS_DNS_MAX_DOMAINS_PER_ADDR 4
#define CERBERUS_DNS_PURGE_PERIOD_MS 5000UL

static std::map<std::string, dns_assoc> g_assoc;

static policy_maps g_maps;

static bool g_initialized = false;

static dns_stats_t g_stats = {};


/*
 * Monotonic clock in nanoseconds.
 */
static unsigned long long now_ns()
{
    return static_cast<unsigned long long>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count());
}


/*
 * ============================================================
 *  DNS message parsing
 * ============================================================
 */

static unsigned short be16(
    const unsigned char* p)
{
    return static_cast<unsigned short>(
        (p[0] << 8) | p[1]);
}


static unsigned int be32(
    const unsigned char* p)
{
    return ((unsigned int)p[0] << 24) |
           ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) |
           (unsigned int)p[3];
}


/*
 * Parse (and decompress) a domain name inside a DNS
 * message. out is lowercased. Compression pointers must
 * point strictly before the start of this name to make
 * pointer loops provably impossible.
 */
static bool dns_parse_name(
    const unsigned char* msg,
    unsigned int msg_len,
    unsigned int start,
    unsigned int* end_out,
    std::string& out)
{
    unsigned int pos = start;
    int jumps = 0;

    out.clear();

    for (;;)
    {
        if (pos >= msg_len)
            return false;

        unsigned int len = msg[pos];

        if (len == 0)
        {
            pos++;
            break;
        }

        if ((len & 0xC0) == 0xC0)
        {
            unsigned int ptr = 0;

            if (pos + 1 >= msg_len)
                return false;

            ptr = (((unsigned int)(msg[pos] & 0x3F)) << 8) |
                  msg[pos + 1];

            if (++jumps > 8)
                return false;

            if (ptr >= start)
                return false;

            pos = ptr;

            continue;
        }

        if (len > 63)
            return false;

        if (pos + 1 + len > msg_len)
            return false;

        if (out.size() + len + 1 >= CERBERUS_NET_DOMAIN_MAX)
            return false;

        if (!out.empty())
            out += '.';

        for (unsigned int i = 0; i < len; i++)
        {
            char c = static_cast<char>(msg[pos + 1 + i]);

            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');

            out += c;
        }

        pos += 1 + len;
    }

    if (out.empty())
        return false;

    if (end_out)
        *end_out = pos;

    return true;
}


/*
 * Freshness/quality guard: never associate loopback,
 * unspecified, link-local or multicast addresses.
 */
static bool addr_is_special(
    unsigned int family,
    const unsigned char* bytes)
{
    if (family == CERBERUS_AF_INET)
    {
        if (bytes[0] == 0)
            return true; /* unspecified */
        if (bytes[0] == 127)
            return true; /* loopback */
        if (bytes[0] == 169 && bytes[1] == 254)
            return true; /* link-local */
        if (bytes[0] >= 224 && bytes[0] <= 239)
            return true; /* multicast */
    }
    else if (family == CERBERUS_AF_INET6)
    {
        int i;

        for (i = 0; i < 16; i++)
        {
            if (bytes[i])
                break;
        }

        if (i == 16)
            return true; /* unspecified */

        if (bytes[0] == 0 && bytes[1] == 0 && bytes[15] == 1)
            return true; /* loopback (::1) */

        if (bytes[0] == 0xfe && bytes[1] == 0x80)
            return true; /* link-local */

        if (bytes[0] == 0xff)
            return true; /* multicast */
    }

    return false;
}


struct dns_record {
    std::string domain;
    unsigned int family;
    unsigned char addr[16];
    unsigned int ttl;
};


static bool dns_parse_records(
    const struct dns_event* e,
    std::vector<dns_record>& out)
{
    const unsigned char* msg = e->payload;
    unsigned int msg_len = e->payload_len;

    unsigned int pos = 12; /* header */

    if (msg_len < 12)
        return false;

    /*
     * Only genuine responses reach here (the kernel
     * checks QR), keep a defensive re-check anyway.
     */
    if (!(be16(msg + 2) & 0x8000))
        return false;

    unsigned int qd = be16(msg + 4);
    unsigned int an = be16(msg + 6);

    if (qd > 8 || an > 64)
        return false;

    /*
     * Question section skip. A failure here means the
     * message never reaches us intact; bail out.
     */
    for (unsigned int i = 0; i < qd; i++)
    {
        std::string name;

        if (!dns_parse_name(msg, msg_len, pos, &pos, name))
            return false;

        pos += 4; /* type + class */

        if (pos + 4 > msg_len)
            return false;
    }

    /*
     * Answer section. Best effort: a record that does not
     * parse (truncated capture, unsupported RR shape) ends
     * the scan, but records parsed before it are kept.
     */
    for (unsigned int i = 0; i < an; i++)
    {
        std::string name;
        unsigned int type;
        unsigned int rdata_len;
        unsigned int ttl;

        if (!dns_parse_name(msg, msg_len, pos, &pos, name))
            break;

        if (pos + 10 > msg_len)
            break;

        type = be16(msg + pos);
        pos += 2;

        pos += 2; /* class */

        ttl = be32(msg + pos);
        pos += 4;

        rdata_len = be16(msg + pos);
        pos += 2;

        if (rdata_len > msg_len || pos + rdata_len > msg_len)
            break;

        dns_record rec = {};
        rec.domain = name;
        rec.family = 0;

        if (type == 1 && rdata_len == 4)
        {
            rec.family = CERBERUS_AF_INET;
            std::memcpy(rec.addr, msg + pos, 4);
        }
        else if (type == 28 && rdata_len == 16)
        {
            rec.family = CERBERUS_AF_INET6;
            std::memcpy(rec.addr, msg + pos, 16);
        }

        pos += rdata_len;

        rec.ttl = ttl > 86400 ? 86400 : ttl;

        if (rec.family != 0)
            out.push_back(rec);
    }

    return true;
}


/*
 * ============================================================
 *  Kernel decision writing
 * ============================================================
 */

static std::string addr_key(
    const struct net_addr& addr)
{
    return net_format_addr(addr);
}


static void update_assoc_and_kernel(
    const struct net_addr& addr,
    const std::string& domain,
    unsigned int ttl)
{
    std::string key = addr_key(addr);

    dns_assoc& a = g_assoc[key];

    a.seen = now_ns();

    unsigned long long expiry =
        a.seen + (unsigned long long)ttl * 1000000000ULL;

    if (expiry > a.expires)
        a.expires = expiry;

    /*
     * Newest domain first, duplicates moved, cap kept.
     */
    for (auto it = a.domains.begin(); it != a.domains.end(); ++it)
    {
        if (*it == domain)
        {
            a.domains.erase(it);
            break;
        }
    }

    a.domains.insert(a.domains.begin(), domain);

    if (a.domains.size() > CERBERUS_DNS_MAX_DOMAINS_PER_ADDR)
        a.domains.resize(CERBERUS_DNS_MAX_DOMAINS_PER_ADDR);

    /*
     * Recompute the verdict from the full domain set and
     * push it into the kernel.
     */
    net_decision d =
        net_compute_decision(addr, a.domains.front(), a.domains);

    net_write_decision(g_maps, d, a.expires);
}


void dns_handle_event(const struct dns_event* e)
{
    std::vector<dns_record> records;

    if (!g_initialized)
        return;

    g_stats.responses++;

    if (!dns_parse_records(e, records))
        return;

    for (const dns_record& r : records)
    {
        struct net_addr addr = {};

        addr.family = r.family;

        std::memcpy(
            addr.addr,
            r.addr,
            sizeof(addr.addr)
        );

        if (addr_is_special(r.family, r.addr))
            continue;

        g_stats.records++;

        update_assoc_and_kernel(addr, r.domain, r.ttl);
    }
}


/*
 * Remove one address association and its kernel entry.
 */
static void drop_assoc(
    const std::string& key)
{
    auto it = g_assoc.find(key);

    if (it == g_assoc.end())
        return;

    struct in_addr v4;
    struct in6_addr v6;

    struct net_addr addr = {};

    if (inet_pton(AF_INET, key.c_str(), &v4) == 1)
    {
        addr.family = CERBERUS_AF_INET;
        std::memcpy(addr.addr, &v4, sizeof(v4));
    }
    else if (inet_pton(AF_INET6, key.c_str(), &v6) == 1)
    {
        addr.family = CERBERUS_AF_INET6;
        std::memcpy(addr.addr, &v6, sizeof(v6));
    }
    else
    {
        g_assoc.erase(it);
        return;
    }

    g_assoc.erase(it);

    net_delete_decision(g_maps, addr);
}


/*
 * Recompute every kernel decision from the current assoc
 * cache. Called after domain rules change and during the
 * periodic purge.
 */
static void sweep_decisions()
{
    struct net_addr cur = {};

    bool first = true;
    unsigned long long now = now_ns();

    while (true)
    {
        int ret = bpf_map_get_next_key(
            g_maps.net_ip_decisions_fd,
            first ? nullptr : &cur,
            &cur
        );

        if (ret != 0)
            break;

        first = false;

        std::string k = net_format_addr(cur);

        auto it = g_assoc.find(k);

        bool stale =
            (it == g_assoc.end());

        if (!stale && it->second.expires < now)
            stale = true;

        if (stale)
        {
            net_delete_decision(g_maps, cur);
            continue;
        }

        net_decision d = net_compute_decision(
            cur,
            it->second.domains.front(),
            it->second.domains
        );

        net_write_decision(g_maps, d, it->second.expires);
    }
}


void dns_tick()
{
    static unsigned long long last_purge = 0;

    unsigned long long now = now_ns();

    if (!g_initialized)
        return;

    if (last_purge != 0 &&
        now - last_purge < CERBERUS_DNS_PURGE_PERIOD_MS * 1000000ULL)
        return;

    last_purge = now;

    /*
     * Drop our own expired associations.
     */
    std::vector<std::string> expired;

    for (const auto& kv : g_assoc)
    {
        if (kv.second.expires < now)
            expired.push_back(kv.first);
    }

    for (const std::string& k : expired)
        drop_assoc(k);

    sweep_decisions();
}


void dns_init(const policy_maps& maps)
{
    g_maps = maps;

    g_initialized = true;

    /*
     * Domain rule changes revoke/restore per-address
     * verdicts: recompute all stored decisions.
     */
    net_set_rule_changed_callback([]() {
        sweep_decisions();
    });

    sweep_decisions();
}


dns_stats_t dns_stats()
{
    dns_stats_t s = g_stats;

    s.associations =
        static_cast<unsigned int>(g_assoc.size());

    return s;
}


void dns_list_associations()
{
    unsigned long long now = now_ns();

    unsigned int shown = 0;

    std::cout
        << "---------- DNS associations ---------\n";

    for (const auto& kv : g_assoc)
    {
        std::string domains;

        for (const std::string& d : kv.second.domains)
        {
            if (!domains.empty())
                domains += ", ";
            domains += d;
        }

        long long rest = (long long)((kv.second.expires - now) / 1000000000ULL);

        if (rest < 0)
            rest = 0;

        std::cout
            << "["
            << kv.first
            << "] "
            << domains
            << " (ttl "
            << rest
            << "s)\n";

        if (++shown >= 64)
        {
            std::cout << "... (truncated)\n";
            break;
        }
    }

    if (shown == 0)
        std::cout << "[EMPTY] No DNS associations observed yet\n";
}


unsigned int dns_association_count()
{
    return static_cast<unsigned int>(g_assoc.size());
}


/*
 * ============================================================
 *  TC attachment
 * ============================================================
 */

struct tc_att {
    std::string name;
    int ifindex;
    __u32 prio[2];     /* EGRESS, INGRESS */
    __u32 handle[2];   /* kernel-assigned handle of the filter */
    bool created;
    bool armed[2];
};

static std::vector<tc_att> g_attachments;


bool dns_capture_attach(struct ips_core_bpf* skel)
{
    struct ifaddrs* ifap = nullptr;
    struct ifaddrs* ifa;

    int prog_fd;

    std::set<std::string> done;

    unsigned int attached = 0;
    unsigned int failed = 0;

    if (!skel)
        return false;

    prog_fd = bpf_program__fd(skel->progs.dns_sniff);

    if (prog_fd < 0)
    {
        std::cerr
            << "[-] DNS sniffer program unavailable\n";

        return false;
    }

    if (getifaddrs(&ifap) != 0)
    {
        std::cerr
            << "[-] getifaddrs failed: "
            << strerror(errno)
            << "\n";

        return false;
    }

    for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_name)
            continue;

        if (done.count(ifa->ifa_name))
            continue;

        done.insert(ifa->ifa_name);

        if (std::strcmp(ifa->ifa_name, "lo") == 0)
            continue;

        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        unsigned int idx = if_nametoindex(ifa->ifa_name);

        if (idx == 0)
            continue;

        tc_att att = {};

        att.name = ifa->ifa_name;
        att.ifindex = static_cast<int>(idx);

        for (int dir = 0; dir < 2; dir++)
        {
            enum bpf_tc_attach_point point =
                dir == 0 ? BPF_TC_EGRESS : BPF_TC_INGRESS;

            struct bpf_tc_hook hook = {};
            struct bpf_tc_opts opts = {};

            hook.sz = sizeof(hook);
            hook.ifindex = att.ifindex;
            hook.attach_point = BPF_TC_EGRESS;

            int ret = bpf_tc_hook_create(&hook);

            if (ret == 0)
                att.created = true;
            else if (ret != -EEXIST)
            {
                /* Some interface types refuse clsact. */
                att.armed[dir] = false;
                failed++;
                continue;
            }

            hook.attach_point = point;

            opts.sz = sizeof(opts);
            opts.prog_fd = prog_fd;
            opts.priority = 0;

            ret = bpf_tc_attach(&hook, &opts);

            if (ret != 0)
            {
                std::cerr
                    << "[-] DNS capture attach on "
                    << att.name
                    << (dir == 0 ? " egress: " : " ingress: ")
                    << strerror(-ret)
                    << "\n";

                failed++;
                continue;
            }

            att.prio[dir] = opts.priority;
            att.handle[dir] = opts.handle;
            att.armed[dir] = true;
            attached++;
        }

        g_attachments.push_back(att);
    }

    freeifaddrs(ifap);

    if (attached == 0)
    {
        std::cerr
            << "[-] DNS capture: no interface accepted a TC "
            << "attachment; DNS associations will stay empty\n";

        return false;
    }

    std::cout
        << "[+] DNS capture attached on "
        << attached
        << " interface direction(s)"
        << (failed ? " (some skipped)" : "")
        << "\n";

    return true;
}


void dns_capture_stop()
{
    for (tc_att& att : g_attachments)
    {
        for (int dir = 0; dir < 2; dir++)
        {
            if (!att.armed[dir])
                continue;

            struct bpf_tc_hook hook = {};
            struct bpf_tc_opts opts = {};

            hook.sz = sizeof(hook);
            hook.ifindex = att.ifindex;
            hook.attach_point =
                dir == 0 ? BPF_TC_EGRESS : BPF_TC_INGRESS;

            opts.sz = sizeof(opts);
            opts.handle = att.handle[dir];
            opts.priority = att.prio[dir];

            bpf_tc_detach(&hook, &opts);
        }

        if (att.created)
        {
            struct bpf_tc_hook hook = {};

            hook.sz = sizeof(hook);
            hook.ifindex = att.ifindex;
            hook.attach_point = BPF_TC_EGRESS;

            bpf_tc_hook_destroy(&hook);
        }
    }

    g_attachments.clear();
}
