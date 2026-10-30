/*
 * Small text and BPF map helpers shared by the agent
 * modules.
 *
 * These are header-only inline functions so every
 * consumer shares one implementation without needing a
 * separate translation unit.
 */
#ifndef CERBERUS_AGENT_UTIL_H
#define CERBERUS_AGENT_UTIL_H

#include <cstddef>
#include <cstring>
#include <string>
#include <sstream>

#include <bpf/bpf.h>

/*
 * Strip leading and trailing whitespace.
 */
inline std::string trim_text(const std::string& s)
{
    size_t begin = s.find_first_not_of(" \t\r\n");

    if (begin == std::string::npos)
        return "";

    size_t end = s.find_last_not_of(" \t\r\n");

    return s.substr(begin, end - begin + 1);
}


/*
 * Split "<first> <rest of line>".
 *
 * Returns false when no first token exists or the
 * remainder is empty.
 */
inline bool split_two(
    const std::string& text,
    std::string& first,
    std::string& second)
{
    std::istringstream iss(text);

    if (!(iss >> first))
        return false;

    std::getline(iss, second);

    second = trim_text(second);

    return !second.empty();
}


/*
 * Count entries in a BPF hash map with keys no
 * larger than 512 bytes.
 *
 * Walks the whole map, so the cost is linear in
 * the number of stored entries.
 */
inline unsigned int count_map_entries(int fd, size_t key_size)
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


#endif /* CERBERUS_AGENT_UTIL_H */
