/*
 * Cerberus interactive command interface.
 */
#ifndef CERBERUS_AGENT_CLI_H
#define CERBERUS_AGENT_CLI_H

#include "policy.h"

enum class cli_result {
    none,  /* nothing to do, or a command was handled */
    quit   /* leave the main loop                        */
};

/*
 * Print the interactive prompt ("cerberus> ").
 * Called once at startup and after every command.
 */
void cli_print_prompt();

/*
 * True when the prompt is on screen and no command output
 * is in progress. Used by the event printer to keep
 * asynchronous alerts on their own line.
 */
bool cli_prompt_active();

/*
 * Read and dispatch any pending commands from stdin.
 * Never blocks waiting for input.
 */
cli_result cli_process_pending(const policy_maps& maps);

#endif /* CERBERUS_AGENT_CLI_H */
