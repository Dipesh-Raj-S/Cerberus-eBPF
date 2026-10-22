#include "cli.h"

#include <cerrno>
#include <iostream>
#include <string>

#include <sys/select.h>
#include <unistd.h>

#include "cerberus/common.h"
#include "events.h"
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
        << "  block-ip <ip>             block connections to an IPv4/IPv6 address\n"
        << "  unblock-ip <ip>           remove an IP block rule\n"
        << "  allow-ip <ip>             explicitly allow connections to an IP\n"
        << "  remove-allow-ip <ip>      remove an IP allow rule\n"
        << "  net-mode <m>              monitor|enforce for network policy only\n"
        << "  list                      list all rules and sandboxes\n"
        << "  mode <m>                  monitor|enforce\n"
        << "  status                    show mode and counters\n"
        << "  help                      show this help\n"
        << "  quit                      stop Cerberus\n";
}


static void print_status(const policy_maps& maps)
{
    unsigned char mode = policy_get_mode(maps.mode_fd);
    unsigned char net_mode = policy_net_get_mode(maps.net_mode_fd);

    std::cout
        << "\n---------- CERBERUS STATUS ----------\n"
        << "Mode: "
        << (mode == CERBERUS_MODE_ENFORCE ? "ENFORCE" : "MONITOR")
        << "\n"
        << "Net mode: "
        << (net_mode == CERBERUS_MODE_ENFORCE ? "ENFORCE" : "MONITOR")
        << "\n"
        << "Events received: "
        << events_count()
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
        << "IP block rules: "
        << policy_net_count_blocks(maps)
        << "\n"
        << "IP allow rules: "
        << policy_net_count_allows(maps)
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
    else if (command.rfind("block-ip ", 0) == 0)
    {
        policy_net_add_block(
            maps,
            command.substr(9));
    }
    else if (command.rfind("unblock-ip ", 0) == 0)
    {
        policy_net_remove_block(
            maps,
            command.substr(11));
    }
    else if (command.rfind("allow-ip ", 0) == 0)
    {
        policy_net_add_allow(
            maps,
            command.substr(9));
    }
    else if (command.rfind("remove-allow-ip ", 0) == 0)
    {
        policy_net_remove_allow(
            maps,
            command.substr(16));
    }
    else if (command.rfind("net-mode ", 0) == 0)
    {
        std::string value = trim_text(command.substr(9));

        if (value == "monitor")
        {
            policy_net_set_mode(
                maps.net_mode_fd,
                CERBERUS_MODE_MONITOR);

            std::cout
                << "[+] Net mode: MONITOR (report only)\n";
        }
        else if (value == "enforce")
        {
            policy_net_set_mode(
                maps.net_mode_fd,
                CERBERUS_MODE_ENFORCE);

            std::cout
                << "[+] Net mode: ENFORCE (deny blocked IPs)\n";
        }
        else
        {
            std::cerr
                << "[-] Usage: net-mode <monitor|enforce>\n";
        }
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
    else
    {
        std::cout
            << "Unknown command. Type 'help'.\n";
    }

    return cli_result::none;
}
