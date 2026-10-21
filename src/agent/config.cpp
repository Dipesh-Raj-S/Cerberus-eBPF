#include "config.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "cerberus/common.h"
#include "detection.h"
#include "net_policy.h"
#include "policy.h"
#include "util.h"


/*
 * Load rules and mode from a config file.
 *
 * Format, one directive per line:
 *
 *     # comment
 *     mode monitor | enforce
 *     name <file>
 *     path <path>
 *     proc <comm> <path-or-name>
 *     uid <uid> <path-or-name>
 *     sandbox <comm>
 *     allow <comm> <path-or-name>
 *
 * Network directives (Phase 5), kept separate from the
 * file-access directives above:
 *
 *     net-mode monitor | enforce | deny-all
 *     block-domain <domain>
 *     allow-domain <domain>
 *     block-ip <ip>
 *     allow-ip <ip>
 *     block-suspicious on | off
 *     net-dns-port on | off
 *     add-shellwatch <comm>
 *
 * net-mode deny-all is honored here because a config file
 * is explicit human intent; the CLI requires a separate
 * confirmation step instead. A warning is printed either
 * way.
 */
int config_load(
    const std::string& path,
    const policy_maps& maps)
{
    std::ifstream in(path);

    if (!in)
        return -1;

    std::string line;
    int lineno = 0;
    int loaded = 0;

    while (std::getline(in, line))
    {
        lineno++;

        std::string entry = trim_text(line);

        if (entry.empty() || entry[0] == '#')
            continue;

        std::istringstream iss(entry);

        std::string directive;
        iss >> directive;

        std::string value;
        std::getline(iss, value);

        value = trim_text(value);

        if (directive == "mode")
        {
            if (value == "monitor")
            {
                policy_set_mode(maps.mode_fd, CERBERUS_MODE_MONITOR);
            }
            else if (value == "enforce")
            {
                policy_set_mode(maps.mode_fd, CERBERUS_MODE_ENFORCE);
            }
            else
            {
                std::cerr
                    << "[-] " << path << ":" << lineno
                    << ": unknown mode '" << value << "'\n";
            }

            continue;
        }

        /*
         * Network directives (Phase 5).
         */
        if (directive == "net-mode")
        {
            if (value == "monitor")
            {
                net_mode_set(maps, CERBERUS_NET_MODE_MONITOR);
            }
            else if (value == "enforce")
            {
                net_mode_set(maps, CERBERUS_NET_MODE_ENFORCE);
            }
            else if (value == "deny-all")
            {
                std::cerr
                    << "[!] " << path << ":" << lineno
                    << ": net-mode deny-all is enabled from the config "
                    << "file. This blocks every outgoing connection "
                    << "except allow rules, port 53 (while the exemption "
                    << "is on), and loopback/link-local/multicast.\n";

                net_mode_set(maps, CERBERUS_NET_MODE_DENY_ALL);

                loaded++;
            }
            else
            {
                std::cerr
                    << "[-] " << path << ":" << lineno
                    << ": unknown net-mode '" << value << "'\n";
            }

            continue;
        }

        if (directive == "block-domain" ||
            directive == "allow-domain")
        {
            if (value.empty())
            {
                std::cerr
                    << "[-] " << path << ":" << lineno
                    << ": expected a domain name\n";

                continue;
            }

            if (net_add_domain_rule(
                    maps,
                    value,
                    directive == "block-domain"
                        ? CERBERUS_NET_RULE_DOMAIN_BLOCK
                        : CERBERUS_NET_RULE_DOMAIN_ALLOW))
                loaded++;

            continue;
        }

        if (directive == "block-ip" ||
            directive == "allow-ip")
        {
            if (value.empty())
            {
                std::cerr
                    << "[-] " << path << ":" << lineno
                    << ": expected an IP address\n";

                continue;
            }

            if (net_add_ip_rule(
                    maps,
                    value,
                    directive == "block-ip"
                        ? CERBERUS_NET_RULE_IP_BLOCK
                        : CERBERUS_NET_RULE_IP_ALLOW))
                loaded++;

            continue;
        }

        if (directive == "block-suspicious")
        {
            if (value == "on" || value == "off")
            {
                detection_set_block(maps, value == "on");

                net_flag_toggle(
                    maps,
                    CERBERUS_NETF_BLOCK_SUSPICIOUS,
                    value == "on");

                loaded++;
            }
            else
            {
                std::cerr
                    << "[-] " << path << ":" << lineno
                    << ": expected 'on' or 'off'\n";
            }

            continue;
        }

        if (directive == "net-dns-port")
        {
            if (value == "on" || value == "off")
            {
                net_flag_toggle(
                    maps,
                    CERBERUS_NETF_ALLOW_DNS_PORT,
                    value == "on");

                loaded++;
            }
            else
            {
                std::cerr
                    << "[-] " << path << ":" << lineno
                    << ": expected 'on' or 'off'\n";
            }

            continue;
        }

        if (directive == "add-shellwatch")
        {
            if (detection_add_shell(value))
                loaded++;

            continue;
        }

        if (directive == "sandbox")
        {
            if (policy_set_sandbox(maps, value, true))
                loaded++;

            continue;
        }

        char rule[256] = {};

        if (directive == "name")
        {
            if (!policy_make_name_key(value, rule))
            {
                std::cerr
                    << "[-] " << path << ":" << lineno
                    << ": invalid name rule\n";

                continue;
            }

            if (policy_add_global(maps, rule, CERBERUS_RULE_NAME))
                loaded++;
        }
        else if (directive == "path")
        {
            if (!policy_make_path_key(value, rule))
            {
                std::cerr
                    << "[-] " << path << ":" << lineno
                    << ": invalid path rule\n";

                continue;
            }

            if (policy_add_global(maps, rule, CERBERUS_RULE_PATH))
                loaded++;
        }
        else if (
            directive == "proc" ||
            directive == "uid" ||
            directive == "allow")
        {
            std::string who;
            std::string target;

            if (!split_two(value, who, target))
            {
                std::cerr
                    << "[-] " << path << ":" << lineno
                    << ": expected '<process-or-uid> <path>'\n";

                continue;
            }

            unsigned char rule_type = 0;

            if (!policy_parse_target(target, rule, rule_type))
            {
                std::cerr
                    << "[-] " << path << ":" << lineno
                    << ": invalid target '" << target << "'\n";

                continue;
            }

            if (directive == "proc")
            {
                if (policy_add_scoped(
                        maps,
                        who,
                        CERBERUS_UID_ANY,
                        rule,
                        rule_type))
                {
                    loaded++;
                }
            }
            else if (directive == "uid")
            {
                unsigned int uid = 0;

                if (!policy_parse_uid(who, uid))
                {
                    std::cerr
                        << "[-] " << path << ":" << lineno
                        << ": invalid uid '" << who << "'\n";

                    continue;
                }

                if (policy_add_scoped(
                        maps,
                        "",
                        uid,
                        rule,
                        rule_type))
                {
                    loaded++;
                }
            }
            else
            {
                if (policy_add_allow(maps, who, rule))
                    loaded++;
            }
        }
        else
        {
            std::cerr
                << "[-] " << path << ":" << lineno
                << ": unknown directive '" << directive << "'\n";
        }
    }

    std::cout
        << "[+] Loaded "
        << loaded
        << " entr(ies) from "
        << path
        << "\n";

    return loaded;
}
