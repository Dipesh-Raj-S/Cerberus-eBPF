#include "net_cli.h"

#include <iostream>
#include <string>

#include "cerberus/common.h"
#include "policy_net.h"
#include "util.h"


bool net_cli_command(
    const policy_maps& maps,
    const std::string& command)
{
    if (command.rfind("block-ip ", 0) == 0)
    {
        policy_net_add_block(
            maps,
            command.substr(9));

        return true;
    }

    if (command.rfind("unblock-ip ", 0) == 0)
    {
        policy_net_remove_block(
            maps,
            command.substr(11));

        return true;
    }

    if (command.rfind("allow-ip ", 0) == 0)
    {
        policy_net_add_allow(
            maps,
            command.substr(9));

        return true;
    }

    if (command.rfind("remove-allow-ip ", 0) == 0)
    {
        policy_net_remove_allow(
            maps,
            command.substr(16));

        return true;
    }

    if (command.rfind("net-mode ", 0) == 0)
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

        return true;
    }

    return false;
}
