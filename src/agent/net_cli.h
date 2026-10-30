/*
 * Cerberus network CLI commands.
 *
 * Implements the interactive commands that belong to the
 * network policy:
 *
 *   block-ip <ip>        unblock-ip <ip>
 *   allow-ip <ip>        remove-allow-ip <ip>
 *   net-mode <m>
 */
#ifndef CERBERUS_AGENT_NET_CLI_H
#define CERBERUS_AGENT_NET_CLI_H

#include <string>

#include "cli.h"
#include "policy.h"

/*
 * Run one command line that belongs to the network
 * policy.
 *
 * Returns true when the command was handled (the
 * response is already printed); false when the command
 * belongs to another module.
 */
bool net_cli_command(
    const policy_maps& maps,
    const std::string& command);

#endif /* CERBERUS_AGENT_NET_CLI_H */
