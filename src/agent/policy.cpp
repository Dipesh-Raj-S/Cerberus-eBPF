#include "policy.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include <bpf/bpf.h>

#include "cerberus/common.h"


bool policy_parse_uid(
    const std::string& text,
    unsigned int& uid)
{
    if (text.empty())
        return false;

    errno = 0;

    char *end = nullptr;

    unsigned long value =
        std::strtoul(text.c_str(), &end, 10);

    if (errno != 0 || !end || *end != '\0')
        return false;

    if (value > 0xFFFFFFFEul)
        return false;

    uid = static_cast<unsigned int>(value);

    return true;
}


bool policy_make_name_key(
    const std::string& name,
    char (&key)[256])
{
    if (name.empty() || name.size() > 255)
    {
        std::cerr
            << "[-] File name must be 1-255 characters\n";

        return false;
    }

    std::memset(key, 0, sizeof(key));

    std::memcpy(
        key,
        name.data(),
        name.size()
    );

    return true;
}


bool policy_make_path_key(
    const std::string& path,
    char (&key)[256])
{
    std::string cleaned = path;

    while (!cleaned.empty() && cleaned.back() == '/')
        cleaned.pop_back();

    size_t slash = cleaned.find_last_of('/');

    if (slash == std::string::npos)
    {
        std::cerr
            << "[-] Path rules need at least a parent directory, "
            << "e.g. /tmp/sensitive.txt "
            << "(use a plain file name for NAME rules)\n";

        return false;
    }

    std::string parent = cleaned.substr(0, slash);
    std::string base = cleaned.substr(slash + 1);

    size_t parent_slash = parent.find_last_of('/');

    if (parent_slash != std::string::npos)
        parent = parent.substr(parent_slash + 1);

    if (base.empty())
    {
        std::cerr
            << "[-] Path does not end in a file name\n";

        return false;
    }

    if (parent.size() > CERBERUS_PATH_SLOT - 1)
    {
        std::cerr
            << "[-] Parent directory name is too long "
            << "(max " << CERBERUS_PATH_SLOT - 1 << " characters)\n";

        return false;
    }

    if (base.size() > 255 - CERBERUS_PATH_SLOT - 1)
    {
        std::cerr
            << "[-] File name is too long "
            << "(max " << 255 - CERBERUS_PATH_SLOT - 1 << " characters)\n";

        return false;
    }

    std::memset(key, 0, sizeof(key));

    std::memcpy(
        key,
        parent.data(),
        parent.size()
    );

    key[CERBERUS_PATH_SLOT] = '/';

    std::memcpy(
        key + CERBERUS_PATH_SLOT + 1,
        base.data(),
        base.size()
    );

    return true;
}


bool policy_parse_target(
    const std::string& spec,
    char (&rule)[256],
    unsigned char& rule_type)
{
    if (spec.find('/') != std::string::npos)
    {
        rule_type = CERBERUS_RULE_PATH;

        return policy_make_path_key(spec, rule);
    }

    rule_type = CERBERUS_RULE_NAME;

    return policy_make_name_key(spec, rule);
}


std::string policy_decode_rule(
    const char (&key)[256],
    unsigned char rule_type)
{
    if (
        rule_type == CERBERUS_RULE_NAME ||
        rule_type == CERBERUS_RULE_SANDBOX)
    {
        return std::string(key);
    }

    std::string parent(key);
    std::string base(key + CERBERUS_PATH_SLOT + 1);

    if (parent.empty())
        return "/" + base;

    return "/" + parent + "/" + base;
}


std::string policy_rule_label(
    const char (&key)[256],
    unsigned char rule_type)
{
    if (rule_type == CERBERUS_RULE_SANDBOX)
        return "sandbox-deny " + policy_decode_rule(key, rule_type);

    return (
        rule_type == CERBERUS_RULE_PATH ? "path " : "name "
    ) + policy_decode_rule(key, rule_type);
}


std::string policy_decode_stored_rule(
    const char (&key)[256])
{
    for (int i = 0; i < CERBERUS_PATH_SLOT; i++)
    {
        if (key[i] == 0)
        {
            if (key[CERBERUS_PATH_SLOT] == '/')
            {
                return policy_decode_rule(
                    key,
                    CERBERUS_RULE_PATH
                );
            }

            break;
        }
    }

    return policy_decode_rule(key, CERBERUS_RULE_NAME);
}


/*
 * Build a scoped rule key:
 *
 *   process rule -> comm + CERBERUS_UID_ANY
 *   UID rule     -> empty comm + uid
 */
static bool make_scoped_key(
    const std::string& comm,
    unsigned int uid,
    const char (&rule)[256],
    struct scoped_rule_key& key)
{
    if (comm.size() > 15)
    {
        std::cerr
            << "[-] Process name must be 1-15 characters\n";

        return false;
    }

    std::memset(&key, 0, sizeof(key));

    std::memcpy(
        key.comm,
        comm.data(),
        comm.size()
    );

    key.uid = uid;

    std::memcpy(
        key.rule,
        rule,
        sizeof(key.rule)
    );

    return true;
}


static std::string scoped_label(
    const struct scoped_rule_key& key)
{
    if (key.comm[0] != 0)
        return "proc " + std::string(key.comm);

    return "uid " + std::to_string(key.uid);
}


bool policy_add_global(
    const policy_maps& maps,
    const char (&key)[256],
    unsigned char rule_type)
{
    struct rule_value value = {};

    value.type = rule_type;

    int ret = bpf_map_update_elem(
        maps.rules_fd,
        key,
        &value,
        BPF_ANY
    );

    if (ret != 0)
    {
        std::cerr
            << "[-] Failed to add rule: "
            << strerror(errno)
            << "\n";

        return false;
    }

    std::cout
        << "[+] Rule added: "
        << policy_rule_label(key, rule_type)
        << "\n";

    return true;
}


bool policy_remove_global(
    const policy_maps& maps,
    const char (&key)[256],
    unsigned char rule_type)
{
    int ret = bpf_map_delete_elem(
        maps.rules_fd,
        key
    );

    if (ret != 0)
    {
        std::cerr
            << "[-] Rule not found: "
            << policy_rule_label(key, rule_type)
            << "\n";

        return false;
    }

    std::cout
        << "[+] Rule removed: "
        << policy_rule_label(key, rule_type)
        << "\n";

    return true;
}


bool policy_add_scoped(
    const policy_maps& maps,
    const std::string& comm,
    unsigned int uid,
    const char (&rule)[256],
    unsigned char rule_type)
{
    struct scoped_rule_key key = {};

    if (!make_scoped_key(comm, uid, rule, key))
        return false;

    struct rule_value value = {};

    value.type = rule_type;

    if (
        bpf_map_update_elem(
            maps.scoped_fd,
            &key,
            &value,
            BPF_ANY
        ) != 0)
    {
        std::cerr
            << "[-] Failed to add scoped rule: "
            << strerror(errno)
            << "\n";

        return false;
    }

    std::cout
        << "[+] Scoped rule added: "
        << scoped_label(key)
        << " -> "
        << policy_rule_label(key.rule, rule_type)
        << "\n";

    return true;
}


bool policy_remove_scoped(
    const policy_maps& maps,
    const std::string& comm,
    unsigned int uid,
    const char (&rule)[256],
    unsigned char rule_type)
{
    struct scoped_rule_key key = {};

    if (!make_scoped_key(comm, uid, rule, key))
        return false;

    if (
        bpf_map_delete_elem(
            maps.scoped_fd,
            &key
        ) != 0)
    {
        std::cerr
            << "[-] Scoped rule not found: "
            << scoped_label(key)
            << " -> "
            << policy_rule_label(key.rule, rule_type)
            << "\n";

        return false;
    }

    std::cout
        << "[+] Scoped rule removed: "
        << scoped_label(key)
        << " -> "
        << policy_rule_label(key.rule, rule_type)
        << "\n";

    return true;
}


bool policy_add_allow(
    const policy_maps& maps,
    const std::string& comm,
    const char (&rule)[256])
{
    struct scoped_rule_key key = {};

    if (!make_scoped_key(comm, CERBERUS_UID_ANY, rule, key))
        return false;

    unsigned char marker = 1;

    if (
        bpf_map_update_elem(
            maps.allow_fd,
            &key,
            &marker,
            BPF_ANY
        ) != 0)
    {
        std::cerr
            << "[-] Failed to add allow entry: "
            << strerror(errno)
            << "\n";

        return false;
    }

    std::cout
        << "[+] Allow entry added: "
        << scoped_label(key)
        << " -> "
        << policy_decode_stored_rule(key.rule)
        << "\n";

    return true;
}


bool policy_remove_allow(
    const policy_maps& maps,
    const std::string& comm,
    const char (&rule)[256])
{
    struct scoped_rule_key key = {};

    if (!make_scoped_key(comm, CERBERUS_UID_ANY, rule, key))
        return false;

    if (
        bpf_map_delete_elem(
            maps.allow_fd,
            &key
        ) != 0)
    {
        std::cerr
            << "[-] Allow entry not found\n";

        return false;
    }

    std::cout
        << "[+] Allow entry removed: "
        << scoped_label(key)
        << "\n";

    return true;
}


bool policy_set_sandbox(
    const policy_maps& maps,
    const std::string& comm,
    bool enable)
{
    if (comm.empty() || comm.size() > 15)
    {
        std::cerr
            << "[-] Process name must be 1-15 characters\n";

        return false;
    }

    char key[16] = {};

    std::memcpy(
        key,
        comm.data(),
        comm.size()
    );

    int ret;

    if (enable)
    {
        unsigned char marker = 1;

        ret = bpf_map_update_elem(
            maps.sandbox_fd,
            key,
            &marker,
            BPF_ANY
        );
    }
    else
    {
        ret = bpf_map_delete_elem(
            maps.sandbox_fd,
            key
        );
    }

    if (ret != 0)
    {
        std::cerr
            << "[-] Failed to "
            << (enable ? "enable" : "disable")
            << " sandbox for "
            << comm
            << ": "
            << strerror(errno)
            << "\n";

        return false;
    }

    std::cout
        << "[+] Sandbox "
        << (enable ? "enabled" : "disabled")
        << " for process: "
        << comm
        << "\n";

    return true;
}


bool policy_set_mode(
    int mode_fd,
    unsigned char mode)
{
    unsigned int zero = 0;

    return bpf_map_update_elem(
        mode_fd,
        &zero,
        &mode,
        BPF_ANY
    ) == 0;
}


unsigned char policy_get_mode(int mode_fd)
{
    unsigned int zero = 0;
    unsigned char mode = CERBERUS_MODE_MONITOR;

    if (
        bpf_map_lookup_elem(
            mode_fd,
            &zero,
            &mode
        ) != 0)
    {
        return CERBERUS_MODE_MONITOR;
    }

    return mode;
}


static unsigned int count_map_entries(int fd, size_t key_size)
{
    char key[512] = {};
    char next_key[512] = {};

    bool first = true;
    unsigned int count = 0;

    while (
        bpf_map_get_next_key(
            fd,
            first ? nullptr : key,
            next_key
        ) == 0)
    {
        first = false;

        std::memcpy(
            key,
            next_key,
            key_size
        );

        count++;
    }

    return count;
}


unsigned int policy_count_global(const policy_maps& maps)
{
    return count_map_entries(maps.rules_fd, 256);
}


unsigned int policy_count_scoped(const policy_maps& maps)
{
    return count_map_entries(
        maps.scoped_fd,
        sizeof(struct scoped_rule_key)
    );
}


unsigned int policy_count_allow(const policy_maps& maps)
{
    return count_map_entries(
        maps.allow_fd,
        sizeof(struct scoped_rule_key)
    );
}


unsigned int policy_count_sandboxed(const policy_maps& maps)
{
    return count_map_entries(maps.sandbox_fd, 16);
}


void policy_list(const policy_maps& maps)
{
    char key[256] = {};
    char next_key[256] = {};

    bool first = true;
    bool found = false;

    std::cout
        << "\n========== CERBERUS RULES ==========\n";

    while (
        bpf_map_get_next_key(
            maps.rules_fd,
            first ? nullptr : key,
            next_key
        ) == 0)
    {
        first = false;

        struct rule_value value = {};

        if (
            bpf_map_lookup_elem(
                maps.rules_fd,
                next_key,
                &value
            ) == 0)
        {
            std::cout
                << "["
                << (value.type == CERBERUS_RULE_PATH ? "PATH" : "NAME")
                << "] "
                << policy_decode_rule(next_key, value.type)
                << "\n";

            found = true;
        }

        std::memcpy(
            key,
            next_key,
            sizeof(key)
        );
    }

    if (!found)
        std::cout << "[EMPTY] No global rules loaded\n";

    std::cout
        << "---------- scoped rules -------------\n";

    struct scoped_rule_key scoped_key = {};
    struct scoped_rule_key scoped_next = {};

    first = true;
    found = false;

    while (
        bpf_map_get_next_key(
            maps.scoped_fd,
            first ? nullptr : &scoped_key,
            &scoped_next
        ) == 0)
    {
        first = false;

        struct rule_value value = {};

        if (
            bpf_map_lookup_elem(
                maps.scoped_fd,
                &scoped_next,
                &value
            ) == 0)
        {
            std::cout
                << "["
                << scoped_label(scoped_next)
                << " "
                << (value.type == CERBERUS_RULE_PATH ? "PATH" : "NAME")
                << "] "
                << policy_decode_rule(scoped_next.rule, value.type)
                << "\n";

            found = true;
        }

        std::memcpy(
            &scoped_key,
            &scoped_next,
            sizeof(scoped_key)
        );
    }

    if (!found)
        std::cout << "[EMPTY] No scoped rules loaded\n";

    std::cout
        << "---------- allowlist entries ---------\n";

    first = true;
    found = false;

    struct scoped_rule_key allow_key = {};
    struct scoped_rule_key allow_next = {};

    while (
        bpf_map_get_next_key(
            maps.allow_fd,
            first ? nullptr : &allow_key,
            &allow_next
        ) == 0)
    {
        first = false;

        unsigned char marker = 0;

        if (
            bpf_map_lookup_elem(
                maps.allow_fd,
                &allow_next,
                &marker
            ) == 0)
        {
            std::cout
                << "["
                << scoped_label(allow_next)
                << "] "
                << policy_decode_stored_rule(allow_next.rule)
                << "\n";

            found = true;
        }

        std::memcpy(
            &allow_key,
            &allow_next,
            sizeof(allow_key)
        );
    }

    if (!found)
        std::cout << "[EMPTY] No allowlist entries loaded\n";

    std::cout
        << "---------- sandboxed processes ------\n";

    char sandbox_key[16] = {};
    char sandbox_next[16] = {};

    first = true;
    found = false;

    while (
        bpf_map_get_next_key(
            maps.sandbox_fd,
            first ? nullptr : sandbox_key,
            sandbox_next
        ) == 0)
    {
        first = false;

        std::cout
            << "[SANDBOX] "
            << sandbox_next
            << "\n";

        found = true;

        std::memcpy(
            sandbox_key,
            sandbox_next,
            sizeof(sandbox_key)
        );
    }

    if (!found)
        std::cout << "[EMPTY] No sandboxed processes\n";

    std::cout
        << "====================================\n\n";
}
