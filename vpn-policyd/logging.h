#pragma once

#include <cstddef>
#include <string>

namespace vpn {

struct LogConfig {
    std::string file{"/var/log/vpn-policyd/vpn-policyd.log"};
    std::string level{"info"};
    std::size_t max_size{10 * 1024 * 1024};
    std::size_t max_files{10};
    bool console{true};
};

void init_logging(const LogConfig& config);
void log_info(const std::string& message);
void log_warn(const std::string& message);
void log_error(const std::string& message);

} // namespace vpn