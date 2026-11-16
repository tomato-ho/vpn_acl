#include "admin_config.h"
#include "auth.h"
#include "db_pool.h"
#include "http_server.h"

#include <csignal>
#include <unistd.h>

#include <iostream>
#include <string>

namespace {

vpn::admin::HttpServer* g_server = nullptr;

void handle_stop_signal(int) {
    if (g_server != nullptr) {
        g_server->stop();
    }
}

int run_check(const vpn::admin::AdminConfig& config) {
    int failures = 0;
    auto warn = [](const std::string& message) {
        std::cerr << "check: warning: " << message << "\n";
    };
    if (::access(config.status_file.c_str(), R_OK) != 0) {
        warn("status file is not readable: " + config.status_file);
    }
    if (config.policyd_socket.size() + 1 >= 108) {
        std::cerr << "check: policyd socket path is too long\n";
        ++failures;
    }
    if (config.db_pool_size == 0 || config.db_pool_size > 32) {
        std::cerr << "check: invalid db_pool_size\n";
        ++failures;
    }
    if (failures == 0) {
        std::cerr << "check: ok\n";
        return 0;
    }
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    std::string config_path = "/etc/vpn-policy/admin.conf";
    bool check_only = false;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (argument == "--check") {
            check_only = true;
        } else {
            std::cerr << "usage: vpn-admin [--config PATH] [--check]\n";
            return 2;
        }
    }

    try {
        const auto config = vpn::admin::load_admin_config(config_path);
        if (check_only) {
            return run_check(config);
        }

        vpn::admin::DbPool pool(config.db, config.db_pool_size);
        vpn::admin::SessionStore sessions(config.session_ttl);
        vpn::admin::LoginLimiter limiter;
        vpn::admin::MetricsCollector metrics(config, pool);
        vpn::admin::HttpServer server(config, pool, sessions, limiter,
                                      metrics);

        g_server = &server;
        // 容器里本进程是 PID 1，默认会忽略 SIGTERM；显式处理才能优雅退出。
        std::signal(SIGTERM, handle_stop_signal);
        std::signal(SIGINT, handle_stop_signal);

        std::cerr << "vpn-admin listening on " << config.bind << ":"
                  << config.port << "\n";
        if (!server.run()) {
            std::cerr << "vpn-admin: failed to listen on " << config.bind << ":"
                      << config.port << "\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "vpn-admin: " << error.what() << "\n";
        return 1;
    }
}