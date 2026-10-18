#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include <cerrno>
#include <sys/select.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <unistd.h>

#include "common.h"
#include "../build/ips_core.skel.h"


/*
 * Called whenever the eBPF program reports
 * a blocked access.
 */
static int handle_event(
    void *ctx,
    void *data,
    size_t data_sz)
{
    const struct event *e =
        static_cast<const struct event *>(data);

    std::cout
        << "\033[1;31m[BLOCKED INTRUSION]\033[0m "
        << "PID: "
        << std::setw(6)
        << e->pid
        << " | Process: "
        << std::setw(12)
        << e->comm
        << " | Protected Target: "
        << e->filename
        << std::endl;

    return 0;
}


/*
 * Add a filename to the BPF blocklist.
 */
static bool add_block(
    int map_fd,
    const std::string& filename)
{
    if (filename.empty() || filename.size() >= 256)
    {
        std::cerr
            << "[-] Filename must be 1-255 characters\n";

        return false;
    }

    char key[256] = {};

    std::strncpy(
        key,
        filename.c_str(),
        sizeof(key) - 1
    );

    __u8 value = 1;

    int ret = bpf_map_update_elem(
        map_fd,
        key,
        &value,
        BPF_ANY
    );

    if (ret != 0)
    {
        std::cerr
            << "[-] Failed to add blocklist entry: "
            << strerror(errno)
            << "\n";

        return false;
    }

    std::cout
        << "[+] Added to blocklist: "
        << filename
        << "\n";

    return true;
}


/*
 * Remove a filename from the BPF blocklist.
 */
static bool remove_block(
    int map_fd,
    const std::string& filename)
{
    char key[256] = {};

    std::strncpy(
        key,
        filename.c_str(),
        sizeof(key) - 1
    );

    int ret = bpf_map_delete_elem(
        map_fd,
        key
    );

    if (ret != 0)
    {
        std::cerr
            << "[-] Failed to remove entry: "
            << strerror(errno)
            << "\n";

        return false;
    }

    std::cout
        << "[+] Removed from blocklist: "
        << filename
        << "\n";

    return true;
}


/*
 * Display all filenames currently in
 * the BPF blocklist.
 */
static void list_blocks(int map_fd)
{
    char key[256] = {};
    char next_key[256] = {};

    bool found = false;

    std::cout
        << "\n========== CERBERUS BLOCKLIST ==========\n";

    while (
        bpf_map_get_next_key(
            map_fd,
            found ? key : nullptr,
            next_key
        ) == 0)
    {
        std::cout
            << "[BLOCKED] "
            << next_key
            << "\n";

        std::memcpy(
            key,
            next_key,
            sizeof(key)
        );

        found = true;
    }

    if (!found)
    {
        std::cout
            << "[EMPTY] Blocklist is empty\n";
    }

    std::cout
        << "========================================\n\n";
}


int main()
{
    /*
     * Open and load the eBPF skeleton.
     */
    struct ips_core_bpf *skel =
        ips_core_bpf__open_and_load();

    if (!skel)
    {
        std::cerr
            << "[-] Failed to load BPF skeleton.\n";

        return 1;
    }


    /*
     * Attach the LSM program.
     */
    if (ips_core_bpf__attach(skel))
    {
        std::cerr
            << "[-] Failed to attach BPF LSM hook.\n";

        ips_core_bpf__destroy(skel);

        return 1;
    }


    /*
     * Get file descriptor for our Hash Map.
     */
    int blocklist_fd =
        bpf_map__fd(skel->maps.blocklist);

    if (blocklist_fd < 0)
    {
        std::cerr
            << "[-] Failed to get blocklist map FD.\n";

        ips_core_bpf__destroy(skel);

        return 1;
    }


    /*
     * Create Ring Buffer.
     */
    struct ring_buffer *rb =
        ring_buffer__new(
            bpf_map__fd(skel->maps.rb),
            handle_event,
            nullptr,
            nullptr
        );

    if (!rb)
    {
        std::cerr
            << "[-] Failed to initialize ring buffer.\n";

        ips_core_bpf__destroy(skel);

        return 1;
    }


    std::cout
        << "\n[+] Cerberus BPF IPS is ACTIVE.\n"
        << "[+] Dynamic Hash Map blocklist enabled.\n";


    /*
     * We use a separate process for the
     * command interface so that the Ring
     * Buffer can continuously receive events.
     *
     * For the first implementation we will
     * use a simple polling loop and command
     * handling below.
     */

    std::cout
        << "[+] Blocklist Map FD: "
        << blocklist_fd
        << "\n";


    /*
     * Initial command interface.
     *
     * NOTE:
     * ring_buffer__poll blocks for the specified
     * timeout. We'll use a small timeout while
     * checking stdin.
     */

    std::cout
        << "\nType 'help' for commands.\n\n";


    /*
     * Simple interactive mode.
     */
    while (true)
    {
        int err =
            ring_buffer__poll(
                rb,
                100
            );

        if (err < 0)
        {
            break;
        }

        /*
         * stdin is handled using getline.
         *
         * Check whether input is available.
         */
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);

        struct timeval tv;

        tv.tv_sec = 0;
        tv.tv_usec = 0;

        int ready =
            select(
                STDIN_FILENO + 1,
                &readfds,
                nullptr,
                nullptr,
                &tv
            );

        if (ready > 0 &&
            FD_ISSET(
                STDIN_FILENO,
                &readfds))
        {
            std::string command;

            std::cout << "Cerberus> ";
            std::getline(
                std::cin,
                command
            );

            if (command == "quit" ||
                command == "exit")
            {
                break;
            }

            if (command == "list")
            {
                list_blocks(blocklist_fd);
            }
            else if (
                command == "help")
            {
                std::cout
                    << "Commands:\n"
                    << "  add <filename>\n"
                    << "  remove <filename>\n"
                    << "  list\n"
                    << "  help\n"
                    << "  quit\n";
            }
            else if (
                command.rfind("add ", 0) == 0)
            {
                add_block(
                    blocklist_fd,
                    command.substr(4)
                );
            }
            else if (
                command.rfind("remove ", 0) == 0)
            {
                remove_block(
                    blocklist_fd,
                    command.substr(7)
                );
            }
            else
            {
                std::cout
                    << "Unknown command. "
                    << "Type 'help'.\n";
            }
        }
    }


    ring_buffer__free(rb);

    ips_core_bpf__destroy(skel);

    return 0;
}
