/*
 * Small text helpers shared by the agent modules.
 *
 * These are header-only inline functions so the two
 * consumers (config and CLI parsing) do not need a
 * separate translation unit.
 */
#ifndef CERBERUS_AGENT_UTIL_H
#define CERBERUS_AGENT_UTIL_H

#include <string>
#include <sstream>

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


#endif /* CERBERUS_AGENT_UTIL_H */
