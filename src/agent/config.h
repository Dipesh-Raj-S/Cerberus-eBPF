/*
 * Cerberus policy file loading.
 */
#ifndef CERBERUS_AGENT_CONFIG_H
#define CERBERUS_AGENT_CONFIG_H

#include <string>

#include "policy.h"

/*
 * Load rules, sandboxes and mode from a policy file.
 *
 * Returns the number of loaded entries, or -1 when
 * the file cannot be opened.
 */
int config_load(
    const std::string& path,
    const policy_maps& maps);

#endif /* CERBERUS_AGENT_CONFIG_H */
