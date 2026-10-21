/*
 * Cerberus event handling.
 *
 * Owns the BPF ring buffer, the alert output and the
 * lifetime event counter.
 */
#ifndef CERBERUS_AGENT_EVENTS_H
#define CERBERUS_AGENT_EVENTS_H

/*
 * Attach the ring buffer consumer to the BPF map.
 * Returns false when the ring buffer cannot be created.
 */
bool events_start(int ringbuf_fd);

void events_stop();

/*
 * Drain events for up to timeout_ms.
 * Returns the value of ring_buffer__poll().
 */
int events_poll(int timeout_ms);

/*
 * Total events received and rendered (file + network).
 */
unsigned long long events_count();

/*
 * Network connect events received and rendered.
 */
unsigned long long events_net_count();

#endif /* CERBERUS_AGENT_EVENTS_H */
