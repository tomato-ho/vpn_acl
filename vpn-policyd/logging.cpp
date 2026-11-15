#include "logging.h"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <mutex>

#ifdef VPN_USE_SPDLOG
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <vector>
#endif

namespace vpn {
namespace {

#ifndef VPN_USE_SPDLOG
std::mutex fallback_mutex;
#endif

#ifdef VPN_USE_SPDLOG
spdlog::level::level_enum parse_level(const std::string& value) {
    if (value == "trace") {
        return spdlog::level::trace;
    }
    if (value == "debug") {
        return spdlog::level::debug;
    }
    if (value == "warn" || value == "warning") {
        return spdlog::level::warn;
    }
    if (value == "error") {
        return spdlog::level::err;
    }
    if (value == "critical") {
        return spdlog::level::critical;
    }
    return spdlog::level::info;
}
#endif

#ifndef VPN_USE_SPDLOG
void fallback_log(const char* level, const std::string& message) {
    std::lock_guard<std::mutex> lock(fallback_mutex);
    const auto now = std::chrono::system_clock::now();
    const std::time_t current = std::chrono::system_clock::to_time_t(now);
    std::tm local {};
    localtime_r(&current, &local);
    char timestamp[32]{};
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &local);
    std::cerr << timestamp << " [" << level << "] " << message << "\n";
}
#endif

} // namespace

void init_logging(const LogConfig& config) {
#ifdef VPN_USE_SPDLOG
    std::vector<spdlog::sink_ptr> sinks;

    if (!config.file.empty()) {
        const std::filesystem::path path(config.file);
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }
        sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            config.file, config.max_size, config.max_files));
    }

    if (config.console || sinks.empty()) {
        sinks.push_back(
            std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
    }

    auto logger = std::make_shared<spdlog::logger>(
        "vpn-policyd", sinks.begin(), sinks.end());
    spdlog::set_default_logger(logger);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");
    spdlog::set_level(parse_level(config.level));
    spdlog::flush_on(spdlog::level::info);
    spdlog::flush_every(std::chrono::seconds(3));
#else
    (void)config;
#endif
}

void log_info(const std::string& message) {
#ifdef VPN_USE_SPDLOG
    spdlog::info(message);
#else
    fallback_log("info", message);
#endif
}

void log_warn(const std::string& message) {
#ifdef VPN_USE_SPDLOG
    spdlog::warn(message);
#else
    fallback_log("warn", message);
#endif
}

void log_error(const std::string& message) {
#ifdef VPN_USE_SPDLOG
    spdlog::error(message);
#else
    fallback_log("error", message);
#endif
}

} // namespace vpn