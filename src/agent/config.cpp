#include "config.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "cerberus/common.h"
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
