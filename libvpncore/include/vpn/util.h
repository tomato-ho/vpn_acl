#pragma once

#include <string>
#include <vector>

namespace vpn {

std::string trim(const std::string& value);
std::vector<std::string> split(const std::string& value, char delimiter);
std::string to_lower(const std::string& value);
bool parse_bool(const std::string& value, bool fallback = false);

} // namespace vpn