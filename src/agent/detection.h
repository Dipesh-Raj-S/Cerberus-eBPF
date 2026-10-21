/*
 * Cerberus suspicious-connection detection.
 *
 * A staged, heuristic correlation layer on top of the
 * network events:
 *
 *   stage 1 — events: network connects (kernel),
 *             process exec information (kernel map)
 *   stage 2 — correlation: process/network identity,
 *             timestamps, repeated attempts
 *   stage 3 — explainable alerts: every detection carries
 *             its evidence
 *   stage 4 — policy: heuristic detection is report-only
 *             by default; the kernel only denies watched
 *             shell processes to unmapped destinations
 *             when the administrator enables that
 *             explicitly (net-block-suspicious).
 *
 * Honest framing: these are heuristics, not a complete
 * intrusion-detection engine. None of them proves a
 * reverse shell; they surface suspicious combinations.
 */
#ifndef CERBERUS_AGENT_DETECTION_H
#define CERBERUS_AGENT_DETECTION_H

#include <string>

#include "cerberus/common.h"
#include "policy.h"

/*
 * Initialize: builds the default watch list and caches
 * map FDs. Does not enable kernel-side blocking.
 */
void detection_init(const policy_maps& maps);

/*
 * Evaluate one network connect event. Prints an alert
 * line when the evidence crosses the heuristic
 * threshold. Called from the event dispatcher.
 */
void detection_handle_event(const struct net_event& e);

/*
 * Watch-list management.
 */
bool detection_add_shell(const std::string& comm);
bool detection_remove_shell(const std::string& comm);
void detection_list_shells();
unsigned int detection_shell_count();
bool detection_shell_watched(const std::string& comm);

/*
 * Kernel-side suspicious blocking switch. Mirrors the
 * watch list into the shell_block map.
 */
void detection_set_block(const policy_maps& maps, bool enable);
bool detection_block_enabled(const policy_maps& maps);

/*
 * Correlation statistics.
 */
unsigned long long detection_alert_count();

/*
 * Heuristic knobs (evidence constants used when printing
 * reasons).
 */
const char* detection_state_label();

#endif /* CERBERUS_AGENT_DETECTION_H */
