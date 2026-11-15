#pragma once

#include "vpn/db.h"

#include <string>

namespace vpn::admin {

struct AdminConfig {
    std::string bind{"127.0.0.1"};
    unsigned int port{8080};
    unsigned int session_ttl{28800};
    bool cookie_secure{true};
    bool trust_proxy{false};
    std::string status_file{"/run/openvpn-server/status.log"};
    std::string policyd_socket{"/run/vpn-policyd/policyd.sock"};
    unsigned int db_pool_size{4};
    unsigned int metrics_cache_seconds{10};
    DbConfig db;
};

AdminConfig load_admin_config(const std::string& path);

} // namespace vpn::admin