#pragma once

#include <map>
#include <string>

namespace vpn {

std::string resolve_config_path(const std::string& path);
bool config_file_exists(const std::string& path);

class Config {
public:
    static Config load(const std::string& path);

    bool has(const std::string& key) const;
    std::string get(const std::string& key,
                    const std::string& fallback = "") const;
    unsigned int get_uint(const std::string& key,
                          unsigned int fallback) const;

private:
    std::map<std::string, std::string> values_;
};

} // namespace vpn