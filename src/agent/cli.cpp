#include "cli.h"

#include <cerrno>
#include <iostream>
#include <string>

#include <sys/select.h>
#include <unistd.h>

#include "cerberus/common.h"
#include "detection.h"
#include "dns.h"
#include "events.h"
#include "net_policy.h"
#include "policy.h"
#include "util.h"


static void print_help()
{
    std::cout
        << "Commands:\n"
        << "  add <name>                add a global file name rule\n"
        << "  addpath <path>            add a global parent/file path rule\n"
        << "  remove <name>             remove a global file name rule\n"
        << "  rmpath <path>             remove a global path rule\n"
        << "  addproc <comm> <target>   deny process access to target\n"
        << "  rmproc <comm> <target>    remove a process rule\n"
        << "  adduid <uid> <target>     deny uid access to target\n"
        << "  rmuid <uid> <target>      remove a uid rule\n"
        << "  sandbox <comm>            allowlist-only mode for process\n"
        << "  unsandbox <comm>          disable sandbox for process\n"
        << "  allow <comm> <target>     allow sandboxed process a target\n"
        << "  unallow <comm> <target>   remove an allowlist entry\n"
        << "  list                      list all file rules and sandboxes\n"
        << "  mode <m>                  monitor|enforce (file access)\n"
        << "  status                    show mode and counters\n"
        << "  --- network (Phase 5) ---\n"
        << "  block-domain <domain>     deny domains mapped to blocked domain rules\n"
        << "  unblock-domain <domain>   remove a domain block rule\n"
        << "  allow-domain <domain>     permit a domain (+subdomains) under deny-all\n"
        << "  remove-allow-domain <d>   remove a domain allow rule\n"
        << "  block-ip <ip>             deny connections to one address\n"
        << "  unblock-ip <ip>           remove an IP block rule\n"
        << "  allow-ip <ip>             permit an address under deny-all\n"
        << "  remove-allow-ip <ip>      remove an IP allow rule\n"
        << "  list-domains              list network domain/IP rules\n"
        << "  list-network              full network policy state and DNS cache\n"
        << "  network-mode <m>          monitor|enforce|deny-all (deny-all is opt-in)\n"
        << "  net-dns-port <on|off>     port-53 exemption in deny-all (default on)\n"
        << "  add-shellwatch <comm>     add a process name to the reverse-shell watch list\n"
        << "  rm-shellwatch <comm>      remove a process name from the watch list\n"
        << "  list-shellwatch           list watched process names\n"
        << "  block-suspicious <on|off> kernel-deny watched shells, unmapped destinations\n"
        << "  help                      show this help\n"
        << "  quit                      stop Cerberus\n";
}


static const char* net_mode_label(unsigned char m)
{
    if (m == CERBERUS_NET_MODE_ENFORCE)
        return "ENFORCE";

    if (m == CERBERUS_NET_MODE_DENY_ALL)
        return "DENY_ALL";

    return "MONITOR";
}


static void print_status(const policy_maps& maps)
{
    unsigned char mode = policy_get_mode(maps.mode_fd);
    unsigned char netmode = net_mode_get(maps);
    unsigned char nflags = net_flags_get(maps);

    dns_stats_t ds = dns_stats();

    std::cout
        << "\n---------- CERBERUS STATUS ----------\n"
        << "File mode: "
        << (mode == CERBERUS_MODE_ENFORCE ? "ENFORCE" : "MONITOR")
        << "\n"
        << "Network mode: "
        << net_mode_label(netmode)
        << "\n"
        << "Network flags: "
        << ((nflags & CERBERUS_NETF_ALLOW_DNS_PORT) ? "dns-port-exempt " : "")
        << ((nflags & CERBERUS_NETF_BLOCK_SUSPICIOUS) ? "block-suspicious " : "")
        << (nflags == 0 ? "none" : "")
        << "\n"
        << "Events received: "
        << events_count()
        << "\n"
        << "Network connect events: "
        << events_net_count()
        << "\n"
        << "DNS responses parsed: "
        << ds.responses
        << " ("
        << ds.associations
        << " live associations)\n"
        << "Suspicious alerts: "
        << detection_alert_count()
        << "\n"
        << "Global rules: "
        << policy_count_global(maps)
        << "\n"
        << "Scoped rules: "
        << policy_count_scoped(maps)
        << "\n"
        << "Allowlist entries: "
        << policy_count_allow(maps)
        << "\n"
        << "Sandboxed processes: "
        << policy_count_sandboxed(maps)
        << "\n"
        << "-------------------------------------\n\n";
}


static std::string g_input_buffer;

static bool g_prompt_active = false;


static cli_result handle_command(
    const policy_maps& maps,
    const std::string& command);


void cli_print_prompt()
{
    std::cout << "cerberus> " << std::flush;

    g_prompt_active = true;
}


bool cli_prompt_active()
{
    return g_prompt_active;
}


/*
 * Dispatch every complete line currently buffered.
 *
 * The prompt is printed after each line rather than only
 * before reading, so it stays visible while the ring
 * buffer is polled and pasted command batches behave
 * like a shell.
 */
static cli_result drain_commands(const policy_maps& maps)
{
    size_t newline;

    while ((newline = g_input_buffer.find('\n')) != std::string::npos)
    {
        std::string command =
            g_input_buffer.substr(0, newline);

        g_input_buffer.erase(0, newline + 1);

        command = trim_text(command);

        /*
         * A complete command line was consumed; the
         * prompt is no longer pending while its output
         * is produced.
         */
        g_prompt_active = false;

        if (!command.empty())
        {
            cli_result result = handle_command(maps, command);

            if (result == cli_result::quit)
                return result;
        }

        cli_print_prompt();
    }

    return cli_result::none;
}


cli_result cli_process_pending(const policy_maps& maps)
{
    /*
     * A previous read may have delivered several
     * commands at once; serve any complete lines
     * before waiting for more input.
     */
    if (g_input_buffer.find('\n') != std::string::npos)
        return drain_commands(maps);


    fd_set readfds;

    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);

    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    int ready =
        select(
            STDIN_FILENO + 1,
            &readfds,
            nullptr,
            nullptr,
            &tv
        );

    if (ready < 0)
    {
        return (
            errno == EINTR
                ? cli_result::none
                : cli_result::quit
        );
    }

    if (ready == 0)
        return cli_result::none;


    char buffer[4096];

    ssize_t n = read(
        STDIN_FILENO,
        buffer,
        sizeof(buffer)
    );

    if (n == 0)
    {
        /*
         * EOF: process a final unterminated line,
         * then leave the main loop.
         */
        if (!g_input_buffer.empty())
        {
            g_input_buffer.push_back('\n');

            cli_result result = drain_commands(maps);

            if (result == cli_result::quit)
                return result;
        }

        return cli_result::quit;
    }

    if (n < 0)
    {
        if (
            errno == EINTR ||
            errno == EAGAIN ||
            errno == EWOULDBLOCK)
        {
            return cli_result::none;
        }

        return cli_result::quit;
    }

    g_input_buffer.append(
        buffer,
        static_cast<size_t>(n)
    );

    return drain_commands(maps);
}


static cli_result handle_command(
    const policy_maps& maps,
    const std::string& command)
{
    if (command.empty())
        return cli_result::none;

    if (command == "quit" || command == "exit")
        return cli_result::quit;

    if (command == "help")
    {
        print_help();
    }
    else if (command == "list")
    {
        policy_list(maps);
    }
    else if (command == "status")
    {
        print_status(maps);
    }
    else if (command.rfind("mode ", 0) == 0)
    {
        std::string value = trim_text(command.substr(5));

        if (value == "monitor")
        {
            policy_set_mode(maps.mode_fd, CERBERUS_MODE_MONITOR);

            std::cout
                << "[+] Mode: MONITOR (report only)\n";
        }
        else if (value == "enforce")
        {
            policy_set_mode(maps.mode_fd, CERBERUS_MODE_ENFORCE);

            std::cout
                << "[+] Mode: ENFORCE (deny matching access)\n";
        }
        else
        {
            std::cerr
                << "[-] Usage: mode <monitor|enforce>\n";
        }
    }
    else if (
        command.rfind("addproc ", 0) == 0 ||
        command.rfind("rmproc ", 0) == 0)
    {
        bool adding = command.rfind("addproc ", 0) == 0;

        size_t offset = adding ? 8 : 7;

        std::string comm;
        std::string target;

        if (!split_two(command.substr(offset), comm, target))
        {
            std::cerr
                << "[-] Usage: "
                << (adding ? "addproc" : "rmproc")
                << " <comm> <target>\n";

            return cli_result::none;
        }

        char rule[256] = {};
        unsigned char rule_type = 0;

        if (!policy_parse_target(target, rule, rule_type))
            return cli_result::none;

        if (adding)
        {
            policy_add_scoped(
                maps,
                comm,
                CERBERUS_UID_ANY,
                rule,
                rule_type);
        }
        else
        {
            policy_remove_scoped(
                maps,
                comm,
                CERBERUS_UID_ANY,
                rule,
                rule_type);
        }
    }
    else if (
        command.rfind("adduid ", 0) == 0 ||
        command.rfind("rmuid ", 0) == 0)
    {
        bool adding = command.rfind("adduid ", 0) == 0;

        size_t offset = adding ? 7 : 6;

        std::string who;
        std::string target;

        if (!split_two(command.substr(offset), who, target))
        {
            std::cerr
                << "[-] Usage: "
                << (adding ? "adduid" : "rmuid")
                << " <uid> <target>\n";

            return cli_result::none;
        }

        unsigned int uid = 0;

        if (!policy_parse_uid(who, uid))
        {
            std::cerr
                << "[-] Invalid uid: "
                << who
                << "\n";

            return cli_result::none;
        }

        char rule[256] = {};
        unsigned char rule_type = 0;

        if (!policy_parse_target(target, rule, rule_type))
            return cli_result::none;

        if (adding)
        {
            policy_add_scoped(
                maps,
                "",
                uid,
                rule,
                rule_type);
        }
        else
        {
            policy_remove_scoped(
                maps,
                "",
                uid,
                rule,
                rule_type);
        }
    }
    else if (command.rfind("sandbox ", 0) == 0)
    {
        policy_set_sandbox(
            maps,
            trim_text(command.substr(8)),
            true);
    }
    else if (command.rfind("unsandbox ", 0) == 0)
    {
        policy_set_sandbox(
            maps,
            trim_text(command.substr(10)),
            false);
    }
    else if (
        command.rfind("allow ", 0) == 0 ||
        command.rfind("unallow ", 0) == 0)
    {
        bool adding = command.rfind("allow ", 0) == 0;

        size_t offset = adding ? 6 : 8;

        std::string comm;
        std::string target;

        if (!split_two(command.substr(offset), comm, target))
        {
            std::cerr
                << "[-] Usage: "
                << (adding ? "allow" : "unallow")
                << " <comm> <target>\n";

            return cli_result::none;
        }

        char rule[256] = {};
        unsigned char rule_type = 0;

        if (!policy_parse_target(target, rule, rule_type))
            return cli_result::none;

        if (adding)
            policy_add_allow(maps, comm, rule);
        else
            policy_remove_allow(maps, comm, rule);
    }
    else if (command.rfind("addpath ", 0) == 0)
    {
        char key[256] = {};

        if (policy_make_path_key(command.substr(8), key))
        {
            policy_add_global(
                maps,
                key,
                CERBERUS_RULE_PATH);
        }
    }
    else if (command.rfind("rmpath ", 0) == 0)
    {
        char key[256] = {};

        if (policy_make_path_key(command.substr(7), key))
        {
            policy_remove_global(
                maps,
                key,
                CERBERUS_RULE_PATH);
        }
    }
    else if (command.rfind("add ", 0) == 0)
    {
        char key[256] = {};

        if (policy_make_name_key(command.substr(4), key))
        {
            policy_add_global(
                maps,
                key,
                CERBERUS_RULE_NAME);
        }
    }
    else if (command.rfind("remove ", 0) == 0)
    {
        char key[256] = {};

        if (policy_make_name_key(command.substr(7), key))
        {
            policy_remove_global(
                maps,
                key,
                CERBERUS_RULE_NAME);
        }
    }
    else if (command.rfind("block-domain ", 0) == 0)
    {
        std::string arg = trim_text(command.substr(13));

        if (!arg.empty())
            net_add_domain_rule(
                maps,
                arg,
                CERBERUS_NET_RULE_DOMAIN_BLOCK
            );
        else
            std::cout << "Usage: block-domain <domain>\n";
    }
    else if (command.rfind("unblock-domain ", 0) == 0)
    {
        std::string arg = trim_text(command.substr(15));

        if (!arg.empty())
            net_remove_domain_rule(
                maps,
                arg,
                CERBERUS_NET_RULE_DOMAIN_BLOCK
            );
        else
            std::cout << "Usage: unblock-domain <domain>\n";
    }
    else if (command.rfind("allow-domain ", 0) == 0)
    {
        std::string arg = trim_text(command.substr(13));

        if (!arg.empty())
            net_add_domain_rule(
                maps,
                arg,
                CERBERUS_NET_RULE_DOMAIN_ALLOW
            );
        else
            std::cout << "Usage: allow-domain <domain>\n";
    }
    else if (
        command.rfind("remove-allow-domain ", 0) == 0 ||
        command.rfind("remove-allowed-domain ", 0) == 0 ||
        command.rfind("unallow-domain ", 0) == 0)
    {
        size_t pos = command.find(' ');

        std::string arg = trim_text(command.substr(pos + 1));

        if (!arg.empty())
            net_remove_domain_rule(
                maps,
                arg,
                CERBERUS_NET_RULE_DOMAIN_ALLOW
            );
        else
            std::cout << "Usage: remove-allow-domain <domain>\n";
    }
    else if (command.rfind("block-ip ", 0) == 0)
    {
        std::string arg = trim_text(command.substr(9));

        if (!arg.empty())
            net_add_ip_rule(
                maps,
                arg,
                CERBERUS_NET_RULE_IP_BLOCK
            );
        else
            std::cout << "Usage: block-ip <ip>\n";
    }
    else if (
        command.rfind("unblock-ip ", 0) == 0 ||
        command.rfind("remove-block-ip ", 0) == 0)
    {
        size_t pos = command.find(' ');

        std::string arg = trim_text(command.substr(pos + 1));

        if (!arg.empty())
            net_remove_ip_rule(
                maps,
                arg,
                CERBERUS_NET_RULE_IP_BLOCK
            );
        else
            std::cout << "Usage: unblock-ip <ip>\n";
    }
    else if (command.rfind("allow-ip ", 0) == 0)
    {
        std::string arg = trim_text(command.substr(9));

        if (!arg.empty())
            net_add_ip_rule(
                maps,
                arg,
                CERBERUS_NET_RULE_IP_ALLOW
            );
        else
            std::cout << "Usage: allow-ip <ip>\n";
    }
    else if (
        command.rfind("remove-allow-ip ", 0) == 0 ||
        command.rfind("unallow-ip ", 0) == 0)
    {
        size_t pos = command.find(' ');

        std::string arg = trim_text(command.substr(pos + 1));

        if (!arg.empty())
            net_remove_ip_rule(
                maps,
                arg,
                CERBERUS_NET_RULE_IP_ALLOW
            );
        else
            std::cout << "Usage: remove-allow-ip <ip>\n";
    }
    else if (command == "list-domains")
    {
        net_list_domain_rules();
        net_list_ip_rules(maps);
    }
    else if (command == "list-network")
    {
        unsigned char mode = net_mode_get(maps);
        unsigned char flags = net_flags_get(maps);

        std::cout
            << "Network mode: "
            << (mode == CERBERUS_NET_MODE_ENFORCE
                    ? "ENFORCE"
                    : mode == CERBERUS_NET_MODE_DENY_ALL
                        ? "DENY_ALL (default-deny)"
                        : "MONITOR")
            << "\n"
            << "DNS port exemption (deny-all): "
            << (flags & CERBERUS_NETF_ALLOW_DNS_PORT ? "on" : "off")
            << "\n"
            << "Suspicious blocking: "
            << (flags & CERBERUS_NETF_BLOCK_SUSPICIOUS ? "on" : "off")
            << " (report-only heuristics are always on)\n\n";

        net_list_domain_rules();
        net_list_ip_rules(maps);
        detection_list_shells();
        dns_list_associations();
    }
    else if (command == "network-mode")
    {
        unsigned char mode = net_mode_get(maps);

        std::cout
            << "Network mode: "
            << (mode == CERBERUS_NET_MODE_ENFORCE
                    ? "ENFORCE"
                    : mode == CERBERUS_NET_MODE_DENY_ALL
                        ? "DENY_ALL (default-deny)"
                        : "MONITOR")
            << "\n";
    }
    else if (command.rfind("network-mode ", 0) == 0)
    {
        std::string first;
        std::string rest;

        split_two(command, first, rest);

        if (rest == "monitor")
        {
            if (net_mode_set(maps, CERBERUS_NET_MODE_MONITOR))
                std::cout
                    << "[+] Network mode: MONITOR (report only)\n";
        }
        else if (rest == "enforce")
        {
            if (net_mode_set(maps, CERBERUS_NET_MODE_ENFORCE))
                std::cout
                    << "[+] Network mode: ENFORCE (matching denies "
                    << "fail connect with EPERM)\n";
        }
        else if (rest == "deny-all")
        {
            std::cout
                << "\n[!] WARNING: deny-all blocks EVERY outgoing\n"
                << "    connection except:\n"
                << "      - explicit allow rules (allow-domain, allow-ip),\n"
                << "      - port 53 DNS while the exemption is on,\n"
                << "      - loopback, link-local and multicast.\n"
                << "\n"
                << "    Recovery: run 'network-mode monitor' or\n"
                << "    'network-mode enforce'.\n"
                << "\n"
                << "    Type 'network-mode deny-all confirm' to enable.\n\n";
        }
        else if (rest == "deny-all confirm")
        {
            if (net_mode_set(maps, CERBERUS_NET_MODE_DENY_ALL))
                std::cout
                    << "[+] Network mode: DENY_ALL enabled by explicit "
                    << "confirmation\n";
        }
        else
        {
            std::cout
                << "Usage: network-mode monitor|enforce|deny-all\n";
        }
    }
    else if (command.rfind("net-dns-port ", 0) == 0)
    {
        std::string arg = trim_text(command.substr(13));

        if (arg == "on")
        {
            net_flag_toggle(
                maps,
                CERBERUS_NETF_ALLOW_DNS_PORT,
                true
            );

            std::cout
                << "[+] Port-53 exemption: on "
                << "(DNS resolution keeps working in deny-all; "
                << "port 53 is also an exfiltration channel)\n";
        }
        else if (arg == "off")
        {
            net_flag_toggle(
                maps,
                CERBERUS_NETF_ALLOW_DNS_PORT,
                false
            );

            std::cout
                << "[+] Port-53 exemption: off "
                << "(deny-all will block port 53 too)\n";
        }
        else
        {
            std::cout << "Usage: net-dns-port on|off\n";
        }
    }
    else if (command.rfind("add-shellwatch ", 0) == 0)
    {
        std::string arg = trim_text(command.substr(15));

        if (!arg.empty())
            detection_add_shell(arg);
        else
            std::cout << "Usage: add-shellwatch <process-name>\n";
    }
    else if (command.rfind("rm-shellwatch ", 0) == 0)
    {
        std::string arg = trim_text(command.substr(14));

        if (!arg.empty())
            detection_remove_shell(arg);
        else
            std::cout << "Usage: rm-shellwatch <process-name>\n";
    }
    else if (command == "list-shellwatch")
    {
        detection_list_shells();
    }
    else if (command.rfind("block-suspicious ", 0) == 0)
    {
        std::string arg = trim_text(command.substr(17));

        if (arg == "on")
        {
            detection_set_block(maps, true);

            net_flag_toggle(
                maps,
                CERBERUS_NETF_BLOCK_SUSPICIOUS,
                true
            );

            std::cout
                << "[+] Suspicious blocking: on "
                << "(watched shells to unmapped destinations are "
                << "denied outside monitor mode)\n";
        }
        else if (arg == "off")
        {
            net_flag_toggle(
                maps,
                CERBERUS_NETF_BLOCK_SUSPICIOUS,
                false
            );

            detection_set_block(maps, false);

            std::cout
                << "[+] Suspicious blocking: off "
                << "(heuristics stay report-only)\n";
        }
        else
        {
            std::cout << "Usage: block-suspicious on|off\n";
        }
    }
    else
    {
        std::cout
            << "Unknown command. Type 'help'.\n";
    }

    return cli_result::none;
}
