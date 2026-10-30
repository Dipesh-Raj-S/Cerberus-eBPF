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
#include "events.h"
#include "policy.h"
#include "policy_net.h"


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
     * the whole system.
     */
    policy_set_mode(
        maps.policy.mode_fd,
        CERBERUS_MODE_MONITOR);

    /*
     * The network policy starts independently in
     * monitor-only mode as well.
     */
    policy_net_set_mode(
        maps.policy.net_mode_fd,
        CERBERUS_MODE_MONITOR);


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
    unsigned char net_mode = policy_net_get_mode(maps.policy.net_mode_fd);

    std::cout
        << "\n[+] Cerberus BPF IPS is ACTIVE.\n"
        << "[+] Mode: "
        << (mode == CERBERUS_MODE_ENFORCE ? "ENFORCE" : "MONITOR")
        << (mode == CERBERUS_MODE_ENFORCE
            ? " (matching access is denied)\n"
            : " (matching access is only reported)\n")
        << "[+] Net mode: "
        << (net_mode == CERBERUS_MODE_ENFORCE ? "ENFORCE" : "MONITOR")
        << (net_mode == CERBERUS_MODE_ENFORCE
            ? " (blocked IPs are denied)\n"
            : " (IP rule matches are only reported)\n")
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
    }


    std::cout
        << "\n[+] Cerberus stopped. Events received: "
        << events_count()
        << "\n";


    events_stop();
    bpf_runtime_stop();

    return 0;
}
