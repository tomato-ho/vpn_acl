#pragma once

#include <cstdint>
#include <ctime>
#include <map>
#include <string>

namespace vpn {

struct StatusClient {
    std::string username;
    std::string virtual_ip;
    std::string client_id;
    std::string remote_ip;
    std::time_t connected_since{0};
    std::uint64_t bytes_received{0};
    std::uint64_t bytes_sent{0};
};

struct StatusSnapshot {
    bool valid{false};
    std::map<std::string, StatusClient> clients;
};

StatusSnapshot parse_openvpn_status(const std::string& path);

} // namespace vpn