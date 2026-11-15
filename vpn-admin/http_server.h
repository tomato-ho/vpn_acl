#pragma once

#include "admin_config.h"
#include "auth.h"
#include "db_pool.h"
#include "metrics.h"

#include <httplib.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>

namespace vpn::admin {

class HttpServer {
public:
    HttpServer(const AdminConfig& config,
               DbPool& pool,
               SessionStore& sessions,
               LoginLimiter& limiter,
               MetricsCollector& metrics);

    bool run();

private:
    void setup_routes();

    std::string admin_metrics();

    const AdminConfig& config_;
    DbPool& pool_;
    SessionStore& sessions_;
    LoginLimiter& limiter_;
    MetricsCollector& metrics_;
    httplib::Server server_;
    std::atomic<std::uint64_t> login_failures_{0};
    std::mutex counter_mutex_;
    std::map<std::string, std::uint64_t> request_counts_;
};

} // namespace vpn::admin