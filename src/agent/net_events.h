/*
 * Cerberus network event printing.
 *
 * Decodes and prints struct net_event records delivered
 * by the BPF socket_connect hook: address, protocol and
 * verdict rendering.
 */
#ifndef CERBERUS_AGENT_NET_EVENTS_H
#define CERBERUS_AGENT_NET_EVENTS_H

#include "cerberus/common.h"

/*
 * Print one network event record exactly as it is
 * delivered by the BPF hook.
 */
void print_net_event(const struct net_event *e);

#endif /* CERBERUS_AGENT_NET_EVENTS_H */
