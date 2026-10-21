#include "detection.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <string.h>
#include <deque>
#include <iostream>
#include <map>
#include <set>
#include <string>

#include <bpf/bpf.h>

#include "cli.h"
#include "events.h"
#include "net_policy.h"


/*
 * Default watch list. Deliberately a starting point: a
 * process named "bash" connecting directly to the outside
 * is unusual on a managed host; it is not proof of a
 * reverse shell.
 */
static const char* const g_default_shells[] = {
    "bash", "sh", "dash", "zsh", "ksh", "ash",
    "python", "python3", "perl", "ruby", "php", "node",
    "nc", "ncat", "socat", "telnet",
};

static std::set<std::string> g_watch;

static bool g_block_enabled = false;

static policy_maps g_maps;

static unsigned long long g_alerts = 0;

/*
 * Repeated-attempt tracking: (pid, family, ip, port) ->
 * recent event timestamps.
 */
struct rep_key {
    unsigned int pid;
    unsigned int family;
    unsigned int port;
    unsigned char dst[16];
};

static std::map<std::string, std::deque<unsigned long long>> g_repeats;

#define CERBERUS_REPEAT_WINDOW_MS 10000ULL
#define CERBERUS_REPEAT_LIMIT 3
#define CERBERUS_REPEAT_LIMIT_ALONE 5

/*
 * Ports commonly used by off-the-shelf reverse shells.
 * Evidence only — a connection to 4444 is not proof of
 * anything either.
 */
static bool port_is_suspect(unsigned int port)
{
    switch (port)
    {
        case 4444:
        case 4445:
        case 5555:
        case 1337:
        case 31337:
            return true;
        default:
            return false;
    }
}


static unsigned long long now_ms()
{
    using namespace std::chrono;

    return static_cast<unsigned long long>(
        duration_cast<milliseconds>(
            steady_clock::now().time_since_epoch()
        ).count());
}


void detection_init(const policy_maps& maps)
{
    g_maps = maps;

    for (const char* s : g_default_shells)
        g_watch.insert(s);
}


bool detection_shell_watched(const std::string& comm)
{
    return g_watch.count(comm) > 0;
}


bool detection_add_shell(const std::string& comm)
{
    if (comm.empty() || comm.size() > 15)
    {
        std::cerr
            << "[-] Process name must be 1-15 characters\n";

        return false;
    }

    g_watch.insert(comm);

    if (g_block_enabled)
    {
        char key[16] = {};

        std::memcpy(key, comm.data(), comm.size());

        unsigned char one = 1;

        bpf_map_update_elem(
            g_maps.shell_block_fd,
            key,
            &one,
            BPF_ANY
        );
    }

    std::cout
        << "[+] Shell watch: " << comm << "\n";

    return true;
}


bool detection_remove_shell(const std::string& comm)
{
    if (g_watch.erase(comm) == 0)
    {
        std::cerr
            << "[-] Not on the watch list: " << comm << "\n";

        return false;
    }

    if (g_block_enabled)
    {
        char key[16] = {};

        std::memcpy(key, comm.data(), comm.size());

        bpf_map_delete_elem(
            g_maps.shell_block_fd,
            key
        );
    }

    std::cout
        << "[+] Shell watch removed: " << comm << "\n";

    return true;
}


void detection_list_shells()
{
    bool first = true;

    std::cout
        << "---------- shell watch list ---------\n";

    for (const std::string& s : g_watch)
    {
        if (!first)
            std::cout << ", ";
        std::cout << s;

        first = false;
    }

    std::cout << "\n";
}


unsigned int detection_shell_count()
{
    return static_cast<unsigned int>(g_watch.size());
}


bool detection_block_enabled(const policy_maps&)
{
    return g_block_enabled;
}


void detection_set_block(const policy_maps& maps, bool enable)
{
    g_block_enabled = enable;

    if (enable)
    {
        for (const std::string& s : g_watch)
        {
            char key[16] = {};

            std::memcpy(key, s.data(), s.size());

            unsigned char one = 1;

            bpf_map_update_elem(
                maps.shell_block_fd,
                key,
                &one,
                BPF_ANY
            );
        }
    }
    else
    {
        char key[16] = {};
        char next_key[16] = {};

        bool first = true;

        while (
            bpf_map_get_next_key(
                maps.shell_block_fd,
                first ? nullptr : key,
                next_key
            ) == 0)
        {
            first = false;

            bpf_map_delete_elem(
                maps.shell_block_fd,
                next_key
            );

            std::memcpy(key, next_key, sizeof(key));
        }
    }
}


/*
 * Reverse-shell-style heuristics.
 */
static bool repeated_attempts(
    const struct net_event& e,
    unsigned int& count_out)
{
    char text[INET6_ADDRSTRLEN + 16] = "";

    std::string key;

    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    const char* s = nullptr;

    std::memset(&v4, 0, sizeof(v4));
    std::memset(&v6, 0, sizeof(v6));

    if (e.family == CERBERUS_AF_INET)
    {
        v4.sin_family = AF_INET;

        std::memcpy(
            &v4.sin_addr,
            e.dst,
            4
        );

        s = inet_ntop(AF_INET, &v4.sin_addr, text, sizeof(text));
    }
    else if (e.family == CERBERUS_AF_INET6)
    {
        v6.sin6_family = AF_INET6;

        std::memcpy(
            &v6.sin6_addr,
            e.dst,
            16
        );

        s = inet_ntop(AF_INET6, &v6.sin6_addr, text, sizeof(text));
    }

    if (!s)
        return false;

    key = std::string(s) + ":" + std::to_string(e.port) +
          "|" + std::to_string(e.pid);

    unsigned long long now = now_ms();

    auto& dq = g_repeats[key];

    dq.push_back(now);

    while (!dq.empty() && now - dq.front() > CERBERUS_REPEAT_WINDOW_MS)
        dq.pop_front();

    count_out = static_cast<unsigned int>(dq.size());

    return count_out >= CERBERUS_REPEAT_LIMIT;
}


static std::string event_dst_text(const struct net_event& e)
{
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;

    char text[INET6_ADDRSTRLEN] = "";
    const char* s = nullptr;

    std::memset(&v4, 0, sizeof(v4));
    std::memset(&v6, 0, sizeof(v6));

    if (e.family == CERBERUS_AF_INET)
    {
        v4.sin_family = AF_INET;

        std::memcpy(&v4.sin_addr, e.dst, 4);

        s = inet_ntop(AF_INET, &v4.sin_addr, text, sizeof(text));
    }
    else if (e.family == CERBERUS_AF_INET6)
    {
        v6.sin6_family = AF_INET6;

        std::memcpy(&v6.sin6_addr, e.dst, 16);

        s = inet_ntop(AF_INET6, &v6.sin6_addr, text, sizeof(text));
    }

    if (!s)
        return "?";

    return text;
}


void detection_handle_event(const struct net_event& e)
{
    std::string comm(e.comm, strnlen(e.comm, sizeof(e.comm)));

    bool shell = detection_shell_watched(comm);

    bool unmapped = (e.flags & CERBERUS_EF_UNMAPPED) != 0;

    bool recent = (e.flags & CERBERUS_EF_RECENT_EXEC) != 0;
    bool suspect = port_is_suspect(e.port);
    bool blocked = e.denied != 0;

    unsigned int rep_count = 0;

    bool repeated = repeated_attempts(e, rep_count);

    bool denied_suspicious =
        blocked && e.rule_type == CERBERUS_NET_RULE_SUSPICIOUS;

    /*
     * Alert conditions (ordered, weakest to strongest).
     */
    bool alert =
        (shell && (unmapped || recent || suspect || repeated)) ||
        (!shell && repeated && rep_count >= CERBERUS_REPEAT_LIMIT_ALONE);

    if (!alert && !denied_suspicious)
        return;

    /*
     * Evidence list.
     */
    std::string reasons;

    if (shell)
        reasons += "shell-process";

    if (unmapped)
    {
        if (!reasons.empty())
            reasons += ", ";
        reasons += "unmapped-destination";
    }

    if (recent)
    {
        if (!reasons.empty())
            reasons += ", ";
        reasons += "recent-exec";
    }

    if (suspect)
    {
        if (!reasons.empty())
            reasons += ", ";
        reasons += "suspect-port(" + std::to_string(e.port) + ")";
    }

    if (repeated)
    {
        if (!reasons.empty())
            reasons += ", ";
        reasons +=
            "repeated(" + std::to_string(rep_count) +
            " attempts/10s)";
    }

    bool had_prompt = cli_prompt_active();

    if (had_prompt)
        std::cout << "\n";

    if (denied_suspicious)
    {
        g_alerts++;

        std::cout
            << "\033[1;35m[SUSPICIOUS BLOCKED]\033[0m "
            << "PID: " << e.pid
            << " | UID: " << e.uid
            << " | Process: " << comm
            << " | Dest: " << event_dst_text(e)
            << ":" << e.port
            << " | reasons: " << reasons
            << " | (heuristic; blocked by net-block-suspicious)"
            << std::endl;
    }
    else
    {
        g_alerts++;

        std::cout
            << "\033[1;35m[NET SUSPICIOUS]  \033[0m "
            << "PID: " << e.pid
            << " | UID: " << e.uid
            << " | Process: " << comm
            << " | Dest: " << event_dst_text(e)
            << ":" << e.port
            << " | reasons: " << reasons
            << " | (heuristic; report-only "
            << "unless net-block-suspicious is on)"
            << std::endl;
    }

    if (had_prompt)
        cli_print_prompt();
}


unsigned long long detection_alert_count()
{
    return g_alerts;
}


const char* detection_state_label()
{
    return g_block_enabled ? "on" : "off";
}
