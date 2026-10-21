/*
 * Cerberus user-space agent entry point.
 *
 * Role: process lifecycle. Loads and attaches the BPF
 * program, loads the configured policy, runs the main
 * event/command loop and performs a clean shutdown.
 */
#include <cstring>
#include <iostream>
#include <string>

#include <signal.h>

#include "bpf_loader.h"
#include "cerberus/common.h"
#include "cli.h"
#include "config.h"
#include "detection.h"
#include "dns.h"
#include "events.h"
#include "net_policy.h"
#include "policy.h"


/*
 * Set by the SIGINT / SIGTERM handler so the main
 * loop can shut down the BPF program cleanly.
 */
static volatile sig_atomic_t g_stop = 0;


static void handle_signal(int)
{
    g_stop = 1;
}


static void setup_signals()
{
    struct sigaction sa;

    std::memset(&sa, 0, sizeof(sa));

    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);

    /*
     * No SA_RESTART: we want blocking calls
     * such as poll() to return with EINTR so
     * the main loop can notice g_stop.
     */
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}


int main(int argc, char **argv)
{
    std::string config_path = "blocklist.txt";

    if (argc > 2)
    {
        std::cerr
            << "Usage: "
            << argv[0]
            << " [config-file]\n";

        return 1;
    }

    if (argc == 2)
        config_path = argv[1];


    setup_signals();


    /*
     * Load the BPF program and attach the LSM hook.
     */
    bpf_maps maps = {};

    if (!bpf_runtime_start(maps))
        return 1;


    /*
     * Monitor-only by default, so a
     * misconfigured rule can never lock
     * the whole system. The same applies
     * to the network policy: monitor mode,
     * with the port-53 exemption armed for
     * an opt-in deny-all.
     */
    policy_set_mode(
        maps.policy.mode_fd,
        CERBERUS_MODE_MONITOR);

    net_mode_set(
        maps.policy,
        CERBERUS_NET_MODE_MONITOR);

    net_flags_set(
        maps.policy,
        CERBERUS_NETF_ALLOW_DNS_PORT);

    detection_init(maps.policy);

    dns_init(maps.policy);


    /*
     * Create the Ring Buffer.
     */
    if (!events_start(maps.ringbuf_fd))
    {
        std::cerr
            << "[-] Failed to initialize ring buffer.\n";

        bpf_runtime_stop();

        return 1;
    }


    /*
     * Attach the TC DNS sniffer on every up,
     * non-loopback interface. Failure degrades
     * domain coverage but never file protection.
     */
    dns_capture_attach(bpf_runtime_skel());


    /*
     * Load rules from the config file.
     *
     * A missing default config file is fine;
     * an explicitly requested one must exist.
     */
    int config_entries = config_load(config_path, maps.policy);

    if (config_entries < 0)
    {
        if (argc == 2)
        {
            std::cerr
                << "[-] Failed to open config file: "
                << config_path
                << "\n";

            events_stop();
            bpf_runtime_stop();

            return 1;
        }

        std::cout
            << "[i] No config file at "
            << config_path
            << ", starting with an empty ruleset\n";
    }


    unsigned char mode = policy_get_mode(maps.policy.mode_fd);
    unsigned char netmode = net_mode_get(maps.policy);

    std::cout
        << "\n[+] Cerberus BPF IPS is ACTIVE.\n"
        << "[+] File mode: "
        << (mode == CERBERUS_MODE_ENFORCE ? "ENFORCE" : "MONITOR")
        << (mode == CERBERUS_MODE_ENFORCE
            ? " (matching access is denied)\n"
            : " (matching access is only reported)\n")
        << "[+] Network mode: "
        << (netmode == CERBERUS_NET_MODE_ENFORCE ? "ENFORCE"
            : netmode == CERBERUS_NET_MODE_DENY_ALL ? "DENY_ALL"
            : "MONITOR")
        << " (outgoing connections are monitored"
        << (netmode == CERBERUS_NET_MODE_MONITOR
            ? ")\n"
            : " and matching rules deny connect())\n")
        << "[+] Type 'help' for commands.\n\n";

    cli_print_prompt();


    /*
     * Main loop: keep the ring buffer drained
     * while accepting interactive commands.
     */
    while (!g_stop)
    {
        int err = events_poll(100);

        if (err == -EINTR)
            continue;

        if (err < 0)
        {
            std::cerr
                << "[-] Ring buffer poll failed: "
                << strerror(-err)
                << "\n";

            break;
        }

        if (g_stop)
            break;

        if (cli_process_pending(maps.policy) == cli_result::quit)
            break;

        /*
         * Periodic DNS work: TTL purge and decision
         * re-sweep. Internally paced at 5 s.
         */
        dns_tick();
    }


    std::cout
        << "\n[+] Cerberus stopped. Events received: "
        << events_count()
        << "\n";


    dns_capture_stop();
    events_stop();
    bpf_runtime_stop();

    return 0;
}
