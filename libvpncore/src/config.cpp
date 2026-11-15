#include "vpn/config.h"

#include "vpn/util.h"

#include <sys/stat.h>

#include <cstdlib>
#include <fstream>
#include <stdexcept>

namespace vpn {
namespace {

std::string unquote(const std::string& value) {
    if (value.size() >= 2 &&
        ((value.front() == '"' && value.back() == '"') ||
         (value.front() == '\'' && value.back() == '\''))) {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

} // namespace

std::string resolve_config_path(const std::string& path) {
    struct stat info {};
    if (::stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode)) {
        return path + "/vpn-policy.conf";
    }
    return path;
}

bool config_file_exists(const std::string& path) {
    struct stat info {};
    return ::stat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode);
}

Config Config::load(const std::string& path) {
    Config config;
    std::ifstream input(path);
    if (input) {
        std::string line;
        while (std::getline(input, line)) {
            line = trim(line);
            if (line.empty() || line.front() == '#' || line.front() == ';') {
                continue;
            }
            const auto separator = line.find('=');
            if (separator == std::string::npos) {
                continue;
            }
            const std::string key = trim(line.substr(0, separator));
            const std::string value = unquote(trim(line.substr(separator + 1)));
            if (!key.empty()) {
                config.values_[key] = value;
            }
        }
    }

    const std::pair<const char*, const char*> environment_overrides[] = {
        {"VPN_DB_HOST", "db_host"},
        {"VPN_DB_PORT", "db_port"},
        {"VPN_DB_NAME", "db_name"},
        {"VPN_DB_USER", "db_user"},
        {"VPN_DB_PASSWORD", "db_password"},
        {"VPN_RADIUS_SECRET", "radius_secret"},
    };
    for (const auto& entry : environment_overrides) {
        if (const char* value = std::getenv(entry.first)) {
            if (*value != '\0') {
                config.values_[entry.second] = value;
            }
        }
    }

    return config;
}

bool Config::has(const std::string& key) const {
    return values_.find(key) != values_.end();
}

std::string Config::get(const std::string& key,
                        const std::string& fallback) const {
    const auto found = values_.find(key);
    return found == values_.end() ? fallback : found->second;
}

unsigned int Config::get_uint(const std::string& key,
                              unsigned int fallback) const {
    const auto found = values_.find(key);
    if (found == values_.end() || found->second.empty()) {
        return fallback;
    }
    std::size_t consumed = 0;
    unsigned long parsed = 0;
    try {
        parsed = std::stoul(found->second, &consumed, 10);
    } catch (const std::exception&) {
        throw std::runtime_error("invalid unsigned value for key: " + key);
    }
    if (consumed != found->second.size()) {
        throw std::runtime_error("invalid unsigned value for key: " + key);
    }
    return static_cast<unsigned int>(parsed);
}

} // namespace vpn