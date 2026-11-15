#include "admin_config.h"

#include "vpn/config.h"
#include "vpn/db_config.h"
#include "vpn/util.h"

#include <algorithm>
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace vpn::admin {

AdminConfig load_admin_config(const std::string& path) {
    if (!config_file_exists(path)) {
        throw std::runtime_error("config file not found: " + path);
    }
    const Config config = Config::load(path);

    AdminConfig out;
    out.bind = config.get("bind", out.bind);
    // 容器里必须监听 0.0.0.0，否则端口映射（DNAT 到容器 eth0）连不上；
    // 对宿主暴露的范围仍由 compose 的 ports 限制在 127.0.0.1。
    if (const char* value = std::getenv("VPN_ADMIN_BIND"); value && *value) {
        out.bind = value;
    }
    if (out.bind.empty()) {
        throw std::runtime_error("bind must not be empty");
    }

    out.port = config.get_uint("port", out.port);
    if (out.port == 0 || out.port > 65535) {
        throw std::runtime_error("invalid port");
    }

    out.session_ttl = std::max<unsigned int>(
        300, config.get_uint("session_ttl", out.session_ttl));
    out.cookie_secure = parse_bool(config.get("cookie_secure", "1"), true);
    out.trust_proxy = parse_bool(config.get("trust_proxy", "0"), false);
    out.status_file = config.get("status_file", out.status_file);
    out.policyd_socket = config.get("policyd_socket", out.policyd_socket);

    out.db_pool_size = std::clamp<unsigned int>(
        config.get_uint("db_pool_size", out.db_pool_size), 1, 32);
    out.metrics_cache_seconds = std::clamp<unsigned int>(
        config.get_uint("metrics_cache_seconds", out.metrics_cache_seconds),
        1, 300);
    out.db = make_db_config(config);
    return out;
}

} // namespace vpn::admin