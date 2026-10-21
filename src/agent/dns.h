/*
 * Cerberus DNS association module.
 *
 * Owns:
 *   - the TC attachment for DNS packet capture,
 *   - parsing of captured DNS responses (A / AAAA only),
 *   - the per-address domain association cache with TTL
 *     expiry,
 *   - writing and sweeping the kernel decision map.
 */
#ifndef CERBERUS_AGENT_DNS_H
#define CERBERUS_AGENT_DNS_H

#include "policy.h"

struct ips_core_bpf;

/*
 * Initialize the module: registers itself as the rule
 * change callback of net_policy so decisions are swept
 * when domain rules change.
 */
void dns_init(const policy_maps& maps);

/*
 * Attach the TC DNS sniffer to every non-loopback
 * interface that is up (both directions). Warnings are
 * printed per interface on failure; missing attachment
 * only degrades DNS coverage.
 */
bool dns_capture_attach(struct ips_core_bpf* skel);

/*
 * Detach every TC attachment made above.
 */
void dns_capture_stop();

/*
 * Handle one CERBERUS_EVT_DNS_RESPONSE record.
 */
void dns_handle_event(const struct dns_event* e);

/*
 * Periodic work: purge expired associations, delete
 * their kernel entries, and re-sweep stored decisions.
 * Cheap; call often, internal 5 s pacing.
 */
void dns_tick();

struct dns_stats_t {
    unsigned long long responses;
    unsigned long long records;
    unsigned int associations;
};

dns_stats_t dns_stats();

/*
 * Printable views.
 */
void dns_list_associations();

unsigned int dns_association_count();

#endif /* CERBERUS_AGENT_DNS_H */
