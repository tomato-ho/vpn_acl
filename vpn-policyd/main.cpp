#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "accounting_worker.h"
#include "logging.h"
#include "nft_manager.h"
#include "status.h"

#include "vpn/accounting.h"
#include "vpn/cidr.h"
#include "vpn/config.h"
#include "vpn/db.h"
#include "vpn/db_config.h"
#include "vpn/ipc.h"
#include "vpn/parse.h"
#include "vpn/policy_store.h"
#include "vpn/util.h"
#include "vpn/validation.h"

#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace vpn;

constexpr int kTerminateUserRequest = 1;
constexpr int kTerminateLostCarrier = 2;
constexpr int kTerminateAdminReset = 6;

std::string terminate_cause_name(int cause) {
    switch (cause) {
    case kTerminateUserRequest:
        return "User-Request";
    case kTerminateLostCarrier:
        return "Lost-Carrier";
    case kTerminateAdminReset:
        return "Admin-Reset";
    case 4:
        return "Idle-Timeout";
    case 5:
        return "Session-Timeout";
    default:
        return std::to_string(cause);
    }
}

volatile sig_atomic_t running = 1;

struct PolicydConfig {
    std::string socket_path{"/run/vpn-policyd/policyd.sock"};
    std::string nft_bin{"/usr/sbin/nft"};
    std::string nft_table{"vpn_acl"};
    std::string tun_iface{"tun0"};
    std::string work_dir{"/run/vpn-policyd"};
    std::string status_file{"/run/openvpn-server/status.log"};
    std::string management_socket{"/run/openvpn-server/management.sock"};
    RadiusServerConfig radius;
    std::uint32_t nas_ip{0};
    bool accounting_enabled{true};
    bool dry_run{false};
    int interim_interval{300};
    int reconcile_interval{30};
    int reconcile_grace{120};
    uid_t allowed_uid{0};
    std::string log_file{"/var/log/vpn-policyd/vpn-policyd.log"};
    std::string log_level{"info"};
    std::size_t log_max_size{10 * 1024 * 1024};
    std::size_t log_max_files{10};
    bool log_console{true};
    DbConfig db;
};

struct Session {
    std::string session_id;
    std::string username;
    std::uint32_t virtual_ip{0};
    std::string remote_ip;
    std::string acct_session_id;
    std::time_t start_time{0};
    std::uint64_t bytes_in{0};
    std::uint64_t bytes_out{0};
};

struct PolicyCache {
    std::map<std::string, std::string> fingerprints;
    std::uint64_t last_full_version{0};
};

struct RuntimeStats {
    std::uint64_t refresh_total{0};
    std::uint64_t refresh_errors{0};
    std::uint64_t refresh_fallback_total{0};
    std::uint64_t refresh_nft_calls_total{0};
    std::uint64_t last_refresh_duration_ms{0};
    std::uint64_t last_refresh_time{0};
    std::uint64_t reconcile_total{0};
    std::uint64_t reconcile_errors{0};
    std::uint64_t last_reconcile_duration_ms{0};
    std::uint64_t last_reconcile_time{0};
};

struct RefreshTimer {
    RuntimeStats& stats;
    std::chrono::steady_clock::time_point started;
    bool ok{false};

    ~RefreshTimer() {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - started)
                                 .count();
        stats.last_refresh_duration_ms =
            elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0;
        stats.last_refresh_time =
            static_cast<std::uint64_t>(std::time(nullptr));
        if (!ok) {
            ++stats.refresh_errors;
        }
    }
};

std::string runtime_stats_line(const RuntimeStats& stats) {
    return "refresh_total=" + std::to_string(stats.refresh_total) +
           ";refresh_errors=" + std::to_string(stats.refresh_errors) +
           ";refresh_fallback_total=" +
           std::to_string(stats.refresh_fallback_total) +
           ";refresh_nft_calls_total=" +
           std::to_string(stats.refresh_nft_calls_total) +
           ";last_refresh_duration_ms=" +
           std::to_string(stats.last_refresh_duration_ms) +
           ";last_refresh_time=" + std::to_string(stats.last_refresh_time) +
           ";reconcile_total=" + std::to_string(stats.reconcile_total) +
           ";reconcile_errors=" + std::to_string(stats.reconcile_errors) +
           ";last_reconcile_duration_ms=" +
           std::to_string(stats.last_reconcile_duration_ms) +
           ";last_reconcile_time=" +
           std::to_string(stats.last_reconcile_time);
}

std::uint64_t read_policy_version(Db& db) {
    const auto rows =
        db.query("SELECT version FROM vpn_policy_version WHERE id = 1");
    if (rows.empty() || rows[0].empty()) {
        throw std::runtime_error("policy version is missing");
    }
    try {
        return static_cast<std::uint64_t>(std::stoull(rows[0][0]));
    } catch (const std::exception&) {
        throw std::runtime_error("policy version is invalid");
    }
}

std::string policy_fingerprint(const PolicydConfig& config,
                               const std::string& username,
                               std::uint32_t virtual_ip,
                               const std::vector<Cidr>& allow,
                               const std::vector<Service>& services) {
    return nft_session_script(config.nft_table, config.tun_iface, username,
                              virtual_ip, allow, services);
}

void stop_handler(int) {
    running = 0;
}

PolicydConfig load_config(const std::string& path) {
    if (!config_file_exists(path)) {
        throw std::runtime_error("config file not found: " + path);
    }
    const Config config = Config::load(path);
    PolicydConfig out;
    out.socket_path = config.get("socket_path", out.socket_path);
    if (out.socket_path.size() + 1 >= sizeof(sockaddr_un::sun_path)) {
        throw std::runtime_error("socket_path is too long");
    }
    out.nft_bin = config.get("nft_bin", out.nft_bin);
    out.nft_table = config.get("nft_table", out.nft_table);
    out.tun_iface = config.get("tun_iface", out.tun_iface);
    out.work_dir = config.get("work_dir", out.work_dir);
    out.status_file = config.get("status_file", out.status_file);
    out.management_socket =
        config.get("management_socket", out.management_socket);
    out.radius.host = config.get("radius_server", out.radius.host);
    const unsigned int radius_port =
        config.get_uint("radius_port", out.radius.port);
    if (radius_port == 0 || radius_port > 65535) {
        throw std::runtime_error("invalid radius_port");
    }
    out.radius.port = static_cast<std::uint16_t>(radius_port);
    out.radius.secret = config.get("radius_secret", out.radius.secret);
    out.radius.timeout_ms = std::clamp<unsigned int>(
        config.get_uint("radius_timeout_ms", out.radius.timeout_ms), 100,
        60000);
    out.radius.retries = std::clamp<unsigned int>(
        config.get_uint("radius_retries", out.radius.retries), 0, 10);
    out.nas_ip = ip_or_throw(config.get("nas_ip", "192.168.100.109"), "nas_ip");
    out.accounting_enabled = parse_bool(config.get("accounting_enabled", "1"), true);
    out.dry_run = parse_bool(config.get("dry_run", "0"), false);
    out.interim_interval = std::max(
        30, static_cast<int>(parse_u32_or_throw(
                config.get("interim_interval", "300"), "interim_interval")));
    out.reconcile_interval = std::max(
        5, static_cast<int>(parse_u32_or_throw(
               config.get("reconcile_interval", "30"), "reconcile_interval")));
    out.reconcile_grace = std::max(
        30, static_cast<int>(parse_u32_or_throw(
                config.get("reconcile_grace", "120"), "reconcile_grace")));
    out.allowed_uid = static_cast<uid_t>(
        parse_u32_or_throw(config.get("allowed_uid", "0"), "allowed_uid"));
    out.log_file = config.get("log_file", out.log_file);
    out.log_level = config.get("log_level", out.log_level);
    out.log_max_size = parse_u32_or_throw(
        config.get("log_max_size", "10485760"), "log_max_size");
    out.log_max_files = parse_u32_or_throw(
        config.get("log_max_files", "10"), "log_max_files");
    out.log_console = parse_bool(config.get("log_console", "1"), true);
    out.db = make_db_config(config);
    return out;
}

bool sleep_interruptible(int seconds) {
    for (int i = 0; i < seconds * 10; ++i) {
        if (!running) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return running != 0;
}

bool status_snapshot_fresh(const PolicydConfig& config) {
    struct stat info {};
    if (::stat(config.status_file.c_str(), &info) != 0) {
        return false;
    }
    const std::time_t now = std::time(nullptr);
    const std::time_t age = now > info.st_mtime ? now - info.st_mtime : 0;
    return age <= config.reconcile_grace;
}

std::time_t session_age(const Session& session) {
    const std::time_t now = std::time(nullptr);
    return now > session.start_time ? now - session.start_time : 0;
}

std::optional<std::time_t> parse_start_time(const std::string& value) {
    if (value.empty()) {
        return std::nullopt;
    }
    std::size_t consumed = 0;
    long long parsed = 0;
    try {
        parsed = std::stoll(value, &consumed, 10);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (consumed != value.size() || parsed <= 0) {
        return std::nullopt;
    }
    return static_cast<std::time_t>(parsed);
}

int run_check(const PolicydConfig& config, bool require_db) {
    int failures = 0;
    auto fail_check = [&failures](const std::string& message) {
        std::cerr << "check: " << message << "\n";
        ++failures;
    };
    auto warn_check = [](const std::string& message) {
        std::cerr << "check: warning: " << message << "\n";
    };

    const auto separator = config.log_file.find_last_of('/');
    if (separator != std::string::npos && separator > 0) {
        const std::string directory = config.log_file.substr(0, separator);
        if (::access(directory.c_str(), W_OK) != 0) {
            warn_check("log directory is not writable: " + directory + ": " +
                       std::strerror(errno));
        }
    }

    if (config.accounting_enabled && !config.dry_run) {
        if (config.radius.host.empty()) {
            fail_check("radius_server is empty");
        }
        if (config.radius.secret.empty()) {
            fail_check("radius_secret is empty");
        }
        try {
            RadiusAccounting accounting(config.radius);
        } catch (const std::exception& exception) {
            fail_check(std::string("radius accounting configuration is invalid: ") +
                       exception.what());
        }
    }

    NftManager nft(config.nft_bin, config.nft_table, config.tun_iface,
                   config.work_dir, false);
    std::string nft_error;
    if (!nft.check_base(&nft_error)) {
        fail_check("nftables validation failed: " + nft_error);
    } else if (nft.table_exists()) {
        NftState state;
        std::string state_error;
        if (!nft.read_state(&state, &state_error)) {
            fail_check("nftables state read failed: " + state_error);
        }
    }

    try {
        Db db(config.db);
        db.connect();
        db.query("SELECT 1");
    } catch (const std::exception& exception) {
        if (require_db) {
            fail_check(std::string("database check failed: ") + exception.what());
        } else {
            warn_check(std::string("database unavailable: ") + exception.what());
        }
    }

    if (failures == 0) {
        std::cerr << "check: ok\n";
        return 0;
    }
    return 1;
}

std::string require_field(const IpcFields& fields, const std::string& name) {
    const auto found = fields.find(name);
    if (found == fields.end() || found->second.empty()) {
        throw std::runtime_error("missing field: " + name);
    }
    return found->second;
}

std::string optional_field(const IpcFields& fields,
                           const std::string& name,
                           const std::string& fallback = "") {
    const auto found = fields.find(name);
    return found == fields.end() ? fallback : found->second;
}

std::uint64_t parse_u64_field(const IpcFields& fields,
                              const std::string& name,
                              std::uint64_t fallback) {
    const auto found = fields.find(name);
    if (found == fields.end() || found->second.empty()) {
        return fallback;
    }
    std::size_t consumed = 0;
    unsigned long long value = 0;
    try {
        value = std::stoull(found->second, &consumed, 10);
    } catch (const std::exception&) {
        throw std::runtime_error("invalid field: " + name);
    }
    if (consumed != found->second.size()) {
        throw std::runtime_error("invalid field: " + name);
    }
    return value;
}

std::optional<Session> row_to_session(const std::vector<std::string>& row) {
    if (row.size() < 8) {
        return std::nullopt;
    }
    Session session;
    session.session_id = row[0];
    session.username = row[1];
    session.virtual_ip = ip_or_throw(row[2], "session virtual IP");
    session.remote_ip = row[3];
    session.acct_session_id = row[4];
    try {
        session.start_time = static_cast<std::time_t>(std::stoll(row[5]));
    } catch (const std::exception&) {
        session.start_time = std::time(nullptr);
    }
    try {
        session.bytes_in = std::stoull(row[6]);
    } catch (const std::exception&) {
        session.bytes_in = 0;
    }
    try {
        session.bytes_out = std::stoull(row[7]);
    } catch (const std::exception&) {
        session.bytes_out = 0;
    }
    return session;
}

const char* kSessionColumns =
    "session_id, username, virtual_ip, remote_ip, acct_session_id, "
    "UNIX_TIMESTAMP(start_time), bytes_in, bytes_out";

std::optional<Session> find_session_by_username(Db& db,
                                                const std::string& username) {
    const auto rows = db.query(
        std::string("SELECT ") + kSessionColumns +
        " FROM vpn_sessions WHERE username = '" + db.quote(username) +
        "' ORDER BY start_time DESC LIMIT 1");
    if (rows.empty()) {
        return std::nullopt;
    }
    return row_to_session(rows[0]);
}

std::optional<Session> find_session_by_username_and_start(
    Db& db, const std::string& username, std::time_t start_time) {
    const auto rows = db.query(
        std::string("SELECT ") + kSessionColumns +
        " FROM vpn_sessions WHERE username = '" + db.quote(username) +
        "' AND UNIX_TIMESTAMP(start_time) = " + std::to_string(start_time) +
        " ORDER BY start_time DESC LIMIT 1");
    if (rows.empty()) {
        return std::nullopt;
    }
    return row_to_session(rows[0]);
}

std::optional<Session> find_session_by_id(Db& db,
                                          const std::string& session_id) {
    const auto rows = db.query(
        std::string("SELECT ") + kSessionColumns +
        " FROM vpn_sessions WHERE session_id = '" + db.quote(session_id) + "'");
    if (rows.empty()) {
        return std::nullopt;
    }
    return row_to_session(rows[0]);
}

std::optional<Session> find_session_by_ip(Db& db, std::uint32_t virtual_ip) {
    const auto rows = db.query(
        std::string("SELECT ") + kSessionColumns +
        " FROM vpn_sessions WHERE virtual_ip = '" + format_ipv4(virtual_ip) + "'");
    if (rows.empty()) {
        return std::nullopt;
    }
    return row_to_session(rows[0]);
}

std::vector<Session> list_sessions(Db& db) {
    const auto rows = db.query(std::string("SELECT ") + kSessionColumns +
                               " FROM vpn_sessions");
    std::vector<Session> sessions;
    for (const auto& row : rows) {
        const auto session = row_to_session(row);
        if (session) {
            sessions.push_back(*session);
        }
    }
    return sessions;
}

void insert_session(Db& db, const Session& session) {
    db.execute(
        "INSERT INTO vpn_sessions "
        "(session_id, username, virtual_ip, remote_ip, acct_session_id, "
        "start_time, last_seen, bytes_in, bytes_out) VALUES ('" +
        db.quote(session.session_id) + "', '" + db.quote(session.username) +
        "', '" + format_ipv4(session.virtual_ip) + "', '" +
        db.quote(session.remote_ip) + "', '" + db.quote(session.acct_session_id) +
        "', FROM_UNIXTIME(" + std::to_string(session.start_time) +
        "), NOW(), 0, 0)");
}

void update_session_stats(Db& db,
                          const std::string& session_id,
                          std::uint64_t bytes_in,
                          std::uint64_t bytes_out) {
    db.execute(
        "UPDATE vpn_sessions SET bytes_in = " + std::to_string(bytes_in) +
        ", bytes_out = " + std::to_string(bytes_out) +
        ", last_seen = NOW() WHERE session_id = '" + db.quote(session_id) + "'");
}

void delete_session(Db& db, const std::string& session_id) {
    db.execute("DELETE FROM vpn_sessions WHERE session_id = '" +
               db.quote(session_id) + "'");
}

// 把已结束的会话写入历史表（替代 radacct 的持久化角色）。
// acct_session_id 上有唯一键，重试时用 ON DUPLICATE KEY 覆盖，保证幂等。
void archive_session(Db& db,
                     const Session& session,
                     std::uint64_t bytes_in,
                     std::uint64_t bytes_out,
                     std::uint32_t session_time,
                     int terminate_cause) {
    db.execute(
        "INSERT INTO vpn_session_history "
        "(username, virtual_ip, remote_ip, acct_session_id, start_time, "
        "stop_time, duration_seconds, bytes_in, bytes_out, terminate_cause) "
        "VALUES ('" +
        db.quote(session.username) + "', '" +
        format_ipv4(session.virtual_ip) + "', '" +
        db.quote(session.remote_ip) + "', '" +
        db.quote(session.acct_session_id) + "', FROM_UNIXTIME(" +
        std::to_string(session.start_time) + "), NOW(), " +
        std::to_string(session_time) + ", " + std::to_string(bytes_in) + ", " +
        std::to_string(bytes_out) + ", '" +
        db.quote(terminate_cause_name(terminate_cause)) + "') "
        "ON DUPLICATE KEY UPDATE stop_time = VALUES(stop_time), "
        "duration_seconds = VALUES(duration_seconds), "
        "bytes_in = VALUES(bytes_in), bytes_out = VALUES(bytes_out), "
        "terminate_cause = VALUES(terminate_cause)");
}

void send_start(AccountingWorker* accounting,
                const Session& session,
                std::uint32_t nas_ip) {
    if (!accounting) {
        return;
    }
    AcctRecord record;
    record.username = session.username;
    record.session_id = session.acct_session_id;
    record.framed_ip = session.virtual_ip;
    record.nas_ip = nas_ip;
    record.calling_station_id = session.remote_ip;
    if (!accounting->enqueue(AcctStatus::Start, record)) {
        log_warn("accounting queue full, dropped start for " + session.username);
    }
}

void send_stop(AccountingWorker* accounting,
               const Session& session,
               std::uint32_t nas_ip,
               std::uint64_t bytes_in,
               std::uint64_t bytes_out,
               std::uint32_t session_time,
               int terminate_cause) {
    if (!accounting) {
        return;
    }
    AcctRecord record;
    record.username = session.username;
    record.session_id = session.acct_session_id;
    record.framed_ip = session.virtual_ip;
    record.nas_ip = nas_ip;
    record.calling_station_id = session.remote_ip;
    record.session_time = session_time;
    record.input_octets = bytes_in;
    record.output_octets = bytes_out;
    record.terminate_cause = terminate_cause;
    if (!accounting->enqueue(AcctStatus::Stop, record)) {
        log_warn("accounting queue full, dropped stop for " + session.username);
    }
}

void send_interim(AccountingWorker* accounting,
                  const Session& session,
                  std::uint32_t nas_ip,
                  std::uint64_t bytes_in,
                  std::uint64_t bytes_out,
                  std::uint32_t session_time) {
    if (!accounting) {
        return;
    }
    AcctRecord record;
    record.username = session.username;
    record.session_id = session.acct_session_id;
    record.framed_ip = session.virtual_ip;
    record.nas_ip = nas_ip;
    record.calling_station_id = session.remote_ip;
    record.session_time = session_time;
    record.input_octets = bytes_in;
    record.output_octets = bytes_out;
    if (!accounting->enqueue(AcctStatus::Interim, record)) {
        log_warn("accounting queue full, dropped interim for " + session.username);
    }
}

bool cleanup_session(Db& db,
                     NftManager& nft,
                     AccountingWorker* accounting,
                     std::uint32_t nas_ip,
                     const Session& session,
                     std::uint64_t bytes_in,
                     std::uint64_t bytes_out,
                     std::uint32_t session_time,
                     int terminate_cause) {
    std::string nft_error;
    if (!nft.remove_session(session.username, session.virtual_ip, &nft_error)) {
        log_error("nft cleanup failed for " + session.username + " ip=" +
                  format_ipv4(session.virtual_ip) + ": " + nft_error +
                  "; keeping session for retry");
        return false;
    }
    send_stop(accounting, session, nas_ip, bytes_in, bytes_out, session_time,
              terminate_cause);
    try {
        archive_session(db, session, bytes_in, bytes_out, session_time,
                        terminate_cause);
        delete_session(db, session.session_id);
    } catch (const std::exception& error) {
        log_error("failed to archive session " + session.session_id + ": " +
                  error.what());
        return false;
    }
    return true;
}

enum class ReapplyResult {
    applied,
    removed,
    failed,
};

ReapplyResult reapply_session(Db& db,
                              NftManager& nft,
                              const Session& session,
                              const ValidationConfig& validation,
                              std::string* error) {
    try {
        const auto data = load_policy(db, session.username);
        const auto policy = compute_effective_policy(data, validation);
        if (policy.fixed_ip != session.virtual_ip) {
            log_warn("reapply: fixed IP changed for " + session.username +
                     ", active session keeps " +
                     format_ipv4(session.virtual_ip));
        }

        std::string nft_error;
        if (!nft.apply_session(session.username, session.virtual_ip,
                               policy.push_routes, policy.services,
                               &nft_error)) {
            if (error) {
                *error = nft_error;
            }
            return ReapplyResult::failed;
        }
        return ReapplyResult::applied;
    } catch (const DbError& exception) {
        if (error) {
            *error = exception.what();
        }
        return ReapplyResult::failed;
    } catch (const ValidationError& exception) {
        log_warn("reapply policy invalid for " + session.username + ": " +
                 exception.what() + "; removing nft rules");
        std::string nft_error;
        if (!nft.remove_session(session.username, session.virtual_ip,
                                &nft_error)) {
            if (error) {
                *error = nft_error;
            }
            return ReapplyResult::failed;
        }
        return ReapplyResult::removed;
    } catch (const std::exception& exception) {
        const std::string message = exception.what();
        log_warn("reapply policy data invalid for " + session.username +
                 ": " + message + "; removing nft rules");
        std::string nft_error;
        if (!nft.remove_session(session.username, session.virtual_ip,
                                &nft_error)) {
            if (error) {
                *error = nft_error;
            }
            return ReapplyResult::failed;
        }
        return ReapplyResult::removed;
    }
}

std::uint32_t session_duration(const Session& session) {
    const std::time_t now = std::time(nullptr);
    if (now <= session.start_time) {
        return 0;
    }
    const auto duration = static_cast<std::uint64_t>(now - session.start_time);
    return duration > 0xFFFFFFFFu
               ? 0xFFFFFFFFu
               : static_cast<std::uint32_t>(duration);
}

void recover_sessions(Db& db,
                      NftManager& nft,
                      AccountingWorker* accounting,
                      const PolicydConfig& config) {
    if (config.dry_run) {
        return;
    }

    const auto snapshot = parse_openvpn_status(config.status_file);
    const bool fresh = status_snapshot_fresh(config);
    const auto validation = load_validation_config(db);
    for (const auto& session : list_sessions(db)) {
        const std::string ip = format_ipv4(session.virtual_ip);
        const bool online =
            snapshot.valid && snapshot.clients.find(ip) != snapshot.clients.end();

        if (snapshot.valid && fresh && !online &&
            session_age(session) >=
                static_cast<std::time_t>(config.reconcile_grace)) {
            log_info("recovery cleanup user=" + session.username + " ip=" + ip +
                     " age=" + std::to_string(session_age(session)));
            if (!cleanup_session(db, nft, accounting, config.nas_ip, session,
                                 session.bytes_in, session.bytes_out,
                                 session_duration(session),
                                 kTerminateLostCarrier)) {
                log_error("recovery cleanup deferred for " + session.username);
            }
            continue;
        }

        std::string error;
        const auto result =
            reapply_session(db, nft, session, validation, &error);
        if (result == ReapplyResult::failed) {
            log_error("recovery policy failed for " + session.username + ": " +
                      error + "; keeping existing nftables rules untouched");
        } else if (result == ReapplyResult::removed) {
            log_warn("recovery removed invalid policy rules for " +
                     session.username);
        }
    }
}

void handle_connect(const IpcFields& fields,
                    Db& db,
                    NftManager& nft,
                    AccountingWorker* accounting,
                    const PolicydConfig& config,
                    PolicyCache& cache) {
    const std::string username = require_field(fields, "username");
    if (!validate_username(username)) {
        throw std::runtime_error("invalid username");
    }
    const std::string session_id = require_field(fields, "session_id");
    if (session_id.size() > 64) {
        throw std::runtime_error("session_id is too long");
    }
    const std::uint32_t virtual_ip =
        ip_or_throw(require_field(fields, "virtual_ip"), "virtual_ip");
    const std::string remote_ip = require_field(fields, "remote_ip");
    const std::string acct_session_id =
        optional_field(fields, "acct_session_id", session_id);

    std::time_t start_time = std::time(nullptr);
    if (const auto parsed =
            parse_start_time(optional_field(fields, "start_time"))) {
        const long long now_value = static_cast<long long>(std::time(nullptr));
        const long long parsed_value = static_cast<long long>(*parsed);
        const long long delta = parsed_value > now_value
                                    ? parsed_value - now_value
                                    : now_value - parsed_value;
        if (delta <= 86400) {
            start_time = *parsed;
        }
    }

    const auto data = load_policy(db, username);
    const auto validation = load_validation_config(db);
    const auto policy = compute_effective_policy(data, validation);
    if (policy.fixed_ip != virtual_ip) {
        throw std::runtime_error("fixed IP does not match policy");
    }
    const auto allow = policy.push_routes;
    const auto services = policy.services;

    if (config.dry_run) {
        std::string error;
        if (!nft.apply_session(username, virtual_ip, allow, services, &error)) {
            throw std::runtime_error("nft apply failed: " + error);
        }
        log_info("dry-run connect user=" + username + " ip=" +
                 format_ipv4(virtual_ip));
        return;
    }

    if (const auto existing = find_session_by_username(db, username)) {
        if (!cleanup_session(db, nft, accounting, config.nas_ip, *existing,
                             existing->bytes_in, existing->bytes_out,
                             session_duration(*existing),
                             kTerminateAdminReset)) {
            throw std::runtime_error(
                "failed to clean previous session; retry later");
        }
    }
    if (const auto by_ip = find_session_by_ip(db, virtual_ip)) {
        if (by_ip->username != username) {
            throw std::runtime_error("virtual IP is already in use");
        }
        if (!cleanup_session(db, nft, accounting, config.nas_ip, *by_ip,
                             by_ip->bytes_in, by_ip->bytes_out,
                             session_duration(*by_ip),
                             kTerminateAdminReset)) {
            throw std::runtime_error(
                "failed to clean session using this IP; retry later");
        }
    }

    Session session;
    session.session_id = session_id;
    session.username = username;
    session.virtual_ip = virtual_ip;
    session.remote_ip = remote_ip;
    session.acct_session_id = acct_session_id;
    session.start_time = start_time;

    insert_session(db, session);

    std::string nft_error;
    if (!nft.apply_session(username, virtual_ip, allow, services, &nft_error)) {
        try {
            delete_session(db, session_id);
        } catch (const std::exception&) {
        }
        throw std::runtime_error("nft apply failed: " + nft_error);
    }
    cache.fingerprints[username] =
        policy_fingerprint(config, username, virtual_ip, allow, services);

    send_start(accounting, session, config.nas_ip);
    log_info("connect user=" + username + " ip=" + format_ipv4(virtual_ip) +
             " session=" + session_id);
}

void handle_disconnect(const IpcFields& fields,
                       Db& db,
                       NftManager& nft,
                       AccountingWorker* accounting,
                       const PolicydConfig& config,
                       PolicyCache& cache) {
    const std::string username = require_field(fields, "username");
    const std::string session_id = optional_field(fields, "session_id");

    if (config.dry_run) {
        const std::string ip_text = optional_field(fields, "virtual_ip");
        if (ip_text.empty()) {
            throw std::runtime_error("dry-run disconnect requires virtual_ip");
        }
        const std::uint32_t virtual_ip = ip_or_throw(ip_text, "virtual_ip");
        std::string error;
        if (!nft.remove_session(username, virtual_ip, &error)) {
            log_warn("nft cleanup failed: " + error);
        }
        log_info("dry-run disconnect user=" + username + " ip=" + ip_text);
        return;
    }

    std::optional<Session> session;
    const auto start_time =
        parse_start_time(optional_field(fields, "start_time"));
    std::string match;

    if (!session_id.empty()) {
        match = "session_id";
        session = find_session_by_id(db, session_id);
        if (!session) {
            log_info("disconnect ignored user=" + username + " session=" +
                     session_id + " (session_id not found)");
            return;
        }
    } else if (start_time) {
        match = "start_time";
        session = find_session_by_username_and_start(db, username, *start_time);
        if (!session) {
            log_info("disconnect ignored user=" + username + " start_time=" +
                     std::to_string(*start_time) +
                     " (session already gone)");
            return;
        }
    } else {
        match = "legacy";
        const std::string ip_text = optional_field(fields, "virtual_ip");
        if (!ip_text.empty()) {
            try {
                session =
                    find_session_by_ip(db, ip_or_throw(ip_text, "virtual_ip"));
            } catch (const std::exception&) {
            }
        }
        if (!session) {
            session = find_session_by_username(db, username);
        }
        if (!session) {
            log_info("disconnect ignored user=" + username +
                     " (not found, legacy match)");
            return;
        }
    }

    const std::uint64_t bytes_in =
        parse_u64_field(fields, "bytes_in", session->bytes_in);
    const std::uint64_t bytes_out =
        parse_u64_field(fields, "bytes_out", session->bytes_out);
    const std::uint64_t requested_time =
        parse_u64_field(fields, "session_time", session_duration(*session));
    const std::uint32_t duration =
        requested_time > 0xFFFFFFFFu
            ? 0xFFFFFFFFu
            : static_cast<std::uint32_t>(requested_time);

    const bool cleaned =
        cleanup_session(db, nft, accounting, config.nas_ip, *session, bytes_in,
                        bytes_out, duration, kTerminateUserRequest);
    if (cleaned) {
        cache.fingerprints.erase(username);
    } else {
        log_warn("disconnect cleanup deferred user=" + username);
    }
    log_info("disconnect user=" + username + " ip=" +
             format_ipv4(session->virtual_ip) + " session=" + session->session_id +
             " match=" + match);
}

bool management_command(const std::string& socket_path,
                        const std::string& command,
                        std::string* error) {
    if (socket_path.empty() ||
        socket_path.size() + 1 >= sizeof(sockaddr_un::sun_path)) {
        if (error) {
            *error = "management socket path is invalid";
        }
        return false;
    }

    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        if (error) {
            *error = std::string("management socket failed: ") +
                     std::strerror(errno);
        }
        return false;
    }

    timeval timeout{};
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, socket_path.c_str(),
                 sizeof(address.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) != 0) {
        const std::string message = std::strerror(errno);
        ::close(fd);
        if (error) {
            *error = "management connect failed: " + message;
        }
        return false;
    }

    const std::string payload = command + "\n";
    std::size_t offset = 0;
    while (offset < payload.size()) {
        const ssize_t written =
            ::send(fd, payload.data() + offset, payload.size() - offset,
                   MSG_NOSIGNAL);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            const std::string message = std::strerror(errno);
            ::close(fd);
            if (error) {
                *error = "management write failed: " + message;
            }
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }

    std::string line;
    char ch = 0;
    while (true) {
        const ssize_t received = ::recv(fd, &ch, 1, 0);
        if (received == 0) {
            if (error) {
                *error = "management connection closed";
            }
            ::close(fd);
            return false;
        }
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (error) {
                *error = std::string("management read failed: ") +
                         std::strerror(errno);
            }
            ::close(fd);
            return false;
        }
        if (ch == '\n') {
            if (line.rfind("SUCCESS:", 0) == 0) {
                ::close(fd);
                return true;
            }
            if (line.rfind("ERROR:", 0) == 0) {
                if (error) {
                    *error = line;
                }
                ::close(fd);
                return false;
            }
            if (line.rfind(">PASSWORD:", 0) == 0) {
                if (error) {
                    *error = "management password is required";
                }
                ::close(fd);
                return false;
            }
            line.clear();
            continue;
        }
        line.push_back(ch);
        if (line.size() > 4096) {
            if (error) {
                *error = "management response is too long";
            }
            ::close(fd);
            return false;
        }
    }
}

void handle_kick(const IpcFields& fields, const PolicydConfig& config) {
    const std::string username = require_field(fields, "username");
    if (!validate_username(username)) {
        throw std::runtime_error("invalid username");
    }

    std::string last_error;
    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto snapshot = parse_openvpn_status(config.status_file);
        if (!snapshot.valid) {
            throw std::runtime_error("status file is invalid");
        }

        std::vector<std::string> client_ids;
        for (const auto& entry : snapshot.clients) {
            if (entry.second.username == username) {
                client_ids.push_back(entry.second.client_id);
            }
        }
        if (client_ids.empty()) {
            log_info("kick skipped user=" + username + " (offline)");
            return;
        }

        bool failed = false;
        for (const auto& client_id : client_ids) {
            const bool valid_id =
                !client_id.empty() &&
                std::all_of(client_id.begin(), client_id.end(),
                            [](unsigned char ch) {
                                return std::isdigit(ch) != 0;
                            });
            if (!valid_id) {
                last_error = "missing or invalid client id";
                failed = true;
                continue;
            }
            std::string error;
            if (!management_command(config.management_socket,
                                    "client-kill " + client_id, &error)) {
                last_error = error;
                failed = true;
            }
        }
        if (!failed) {
            log_info("kick user=" + username);
            return;
        }
        log_warn("kick retry for " + username + ": " + last_error);
    }
    throw std::runtime_error("kick failed: " + last_error);
}

void handle_refresh(const IpcFields& fields,
                    Db& db,
                    NftManager& nft,
                    const PolicydConfig& config,
                    PolicyCache& cache,
                    RuntimeStats& stats) {
    if (config.dry_run) {
        log_info("refresh skipped in dry-run");
        return;
    }

    ++stats.refresh_total;
    RefreshTimer timer{stats, std::chrono::steady_clock::now()};

    const std::string username = optional_field(fields, "username");
    if (!username.empty() && !validate_username(username)) {
        throw std::runtime_error("invalid username");
    }
    if (!status_snapshot_fresh(config)) {
        throw std::runtime_error("status snapshot is stale");
    }
    const auto snapshot = parse_openvpn_status(config.status_file);
    if (!snapshot.valid) {
        throw std::runtime_error("status file is invalid");
    }

    const bool full_refresh = username.empty();
    const std::uint64_t policy_version = read_policy_version(db);
    if (full_refresh && cache.last_full_version == policy_version) {
        log_info("refresh skipped unchanged policy_version=" +
                 std::to_string(policy_version));
        timer.ok = true;
        return;
    }

    const auto validation = load_validation_config(db);
    const auto sessions = list_sessions(db);
    std::vector<NftSessionUpdate> updates;
    std::map<std::string, std::string> pending_fingerprints;
    std::size_t skipped = 0;
    std::string last_error;

    for (const auto& session : sessions) {
        if (!username.empty() && session.username != username) {
            continue;
        }
        const std::string ip = format_ipv4(session.virtual_ip);
        const bool online =
            snapshot.clients.find(ip) != snapshot.clients.end();
        if (!online && session_age(session) >=
                           static_cast<std::time_t>(config.reconcile_grace)) {
            log_info("refresh skipped offline session user=" +
                     session.username);
            continue;
        }

        std::string policy_error;
        try {
            const auto data = load_policy(db, session.username);
            const auto policy = compute_effective_policy(data, validation);
            const std::string fingerprint = policy_fingerprint(
                config, session.username, session.virtual_ip,
                policy.push_routes, policy.services);
            const auto cached = cache.fingerprints.find(session.username);
            if (cached != cache.fingerprints.end() &&
                cached->second == fingerprint) {
                ++skipped;
                continue;
            }

            NftSessionUpdate update;
            update.username = session.username;
            update.virtual_ip = session.virtual_ip;
            update.allow = policy.push_routes;
            update.services = policy.services;
            updates.push_back(update);
            pending_fingerprints[session.username] = fingerprint;
        } catch (const DbError& exception) {
            last_error = exception.what();
            log_error("refresh failed to load policy for " + session.username +
                      ": " + exception.what());
        } catch (const std::exception& exception) {
            policy_error = exception.what();
            NftSessionUpdate update;
            update.username = session.username;
            update.virtual_ip = session.virtual_ip;
            update.remove = true;
            updates.push_back(update);
            pending_fingerprints.erase(session.username);
            cache.fingerprints.erase(session.username);
            log_warn("refresh removing invalid policy user=" +
                     session.username + ": " + policy_error);
        }
    }

    if (updates.empty()) {
        log_info("refresh complete user=" +
                 (full_refresh ? std::string("*") : username) +
                 " applied=0 removed=0 skipped=" + std::to_string(skipped) +
                 " nft_calls=0");
        if (full_refresh && last_error.empty()) {
            cache.last_full_version = policy_version;
        }
        if (!last_error.empty()) {
            throw std::runtime_error("refresh partially failed: " +
                                     last_error);
        }
        timer.ok = true;
        return;
    }

    NftBatchStats batch_stats;
    std::string batch_error;
    if (nft.apply_updates(updates, &batch_stats, &batch_error)) {
        stats.refresh_nft_calls_total += batch_stats.nft_calls;
        for (const auto& update : updates) {
            if (update.remove) {
                cache.fingerprints.erase(update.username);
            } else {
                const auto found =
                    pending_fingerprints.find(update.username);
                if (found != pending_fingerprints.end()) {
                    cache.fingerprints[update.username] = found->second;
                }
            }
        }
        if (full_refresh && last_error.empty()) {
            cache.last_full_version = policy_version;
        }
        log_info("refresh complete user=" +
                 (full_refresh ? std::string("*") : username) +
                 " applied=" + std::to_string(batch_stats.applied) +
                 " removed=" + std::to_string(batch_stats.removed) +
                 " skipped=" + std::to_string(skipped) +
                 " nft_calls=" + std::to_string(batch_stats.nft_calls));
        if (!last_error.empty()) {
            throw std::runtime_error("refresh partially failed: " +
                                     last_error);
        }
        timer.ok = true;
        return;
    }

    ++stats.refresh_fallback_total;
    log_warn("refresh batch failed: " + batch_error +
             "; falling back to per-session apply");
    std::size_t applied = 0;
    std::size_t removed = 0;
    std::size_t failed = 0;
    std::string fallback_error;

    for (const auto& update : updates) {
        std::string error;
        const bool ok =
            update.remove
                ? nft.remove_session(update.username, update.virtual_ip, &error)
                : nft.apply_session(update.username, update.virtual_ip,
                                    update.allow, update.services, &error);
        if (!ok) {
            ++failed;
            fallback_error = error;
            log_error("refresh fallback failed for " + update.username +
                      ": " + error);
            continue;
        }
        if (update.remove) {
            ++removed;
            cache.fingerprints.erase(update.username);
        } else {
            ++applied;
            const auto found = pending_fingerprints.find(update.username);
            if (found != pending_fingerprints.end()) {
                cache.fingerprints[update.username] = found->second;
            }
        }
    }

    stats.refresh_nft_calls_total += applied + removed;
    log_info("refresh fallback complete user=" +
             (full_refresh ? std::string("*") : username) +
             " applied=" + std::to_string(applied) +
             " removed=" + std::to_string(removed) +
             " skipped=" + std::to_string(skipped) +
             " failed=" + std::to_string(failed));
    if (failed == 0 && last_error.empty()) {
        if (full_refresh) {
            cache.last_full_version = policy_version;
        }
        timer.ok = true;
        return;
    }
    if (fallback_error.empty()) {
        fallback_error = last_error;
    }
    throw std::runtime_error("refresh partially failed: " + fallback_error);
}

void reconcile(Db& db,
               NftManager& nft,
               AccountingWorker* accounting,
               const PolicydConfig& config) {
    if (config.dry_run) {
        return;
    }
    std::string base_error;
    if (!nft.ensure_base(&base_error)) {
        log_warn("nftables base check failed: " + base_error);
    }
    if (!status_snapshot_fresh(config)) {
        log_warn("reconcile skipped: status snapshot is stale: " +
                 config.status_file);
        return;
    }
    const auto snapshot = parse_openvpn_status(config.status_file);
    if (!snapshot.valid) {
        log_warn("reconcile skipped: status snapshot is invalid: " +
                 config.status_file);
        return;
    }

    for (const auto& session : list_sessions(db)) {
        const std::string ip = format_ipv4(session.virtual_ip);
        if (snapshot.clients.find(ip) != snapshot.clients.end()) {
            continue;
        }
        const std::time_t age = session_age(session);
        if (age < static_cast<std::time_t>(config.reconcile_grace)) {
            continue;
        }
        log_info("reconcile cleanup user=" + session.username + " ip=" + ip +
                 " age=" + std::to_string(age));
        if (!cleanup_session(db, nft, accounting, config.nas_ip, session,
                             session.bytes_in, session.bytes_out,
                             session_duration(session),
                             kTerminateLostCarrier)) {
            log_error("reconcile cleanup deferred for " + session.username);
        }
    }

    const auto remaining = list_sessions(db);
    std::set<std::string> keep_ips;
    std::set<std::string> keep_chains;
    for (const auto& session : remaining) {
        keep_ips.insert(format_ipv4(session.virtual_ip));
        const std::string hash = nft_chain_hash(session.username);
        keep_chains.insert("uf_" + hash);
        keep_chains.insert("ui_" + hash);
    }
    for (const auto& entry : snapshot.clients) {
        keep_ips.insert(entry.first);
    }

    NftState state;
    std::string nft_error;
    if (!nft.read_state(&state, &nft_error)) {
        log_warn("reconcile nft state read failed: " + nft_error);
        return;
    }

    const auto validation = load_validation_config(db);
    for (const auto& session : remaining) {
        const std::string ip = format_ipv4(session.virtual_ip);
        const bool online =
            snapshot.clients.find(ip) != snapshot.clients.end();
        const bool within_grace =
            session_age(session) <
            static_cast<std::time_t>(config.reconcile_grace);
        if (!online && !within_grace) {
            continue;
        }

        const std::string hash = nft_chain_hash(session.username);
        const std::string forward_chain = "uf_" + hash;
        const std::string input_chain = "ui_" + hash;
        const auto forward = state.user_fwd.find(ip);
        const auto input = state.user_in.find(ip);
        if (forward != state.user_fwd.end() &&
            forward->second == forward_chain &&
            input != state.user_in.end() &&
            input->second == input_chain) {
            continue;
        }

        std::string error;
        const auto result =
            reapply_session(db, nft, session, validation, &error);
        if (result == ReapplyResult::failed) {
            log_error("reconcile repair failed for " + session.username +
                      ": " + error);
        } else {
            log_info("reconcile repaired user=" + session.username + " ip=" +
                     ip);
        }
    }

    std::size_t removed_elements = 0;
    std::size_t removed_chains = 0;
    if (!nft.cleanup_orphans(keep_ips, keep_chains, &removed_elements,
                             &removed_chains, &nft_error)) {
        log_warn("reconcile orphan cleanup failed: " + nft_error);
    } else if (removed_elements != 0 || removed_chains != 0) {
        log_info("reconcile orphan cleanup elements=" +
                 std::to_string(removed_elements) + " chains=" +
                 std::to_string(removed_chains));
    }
}

void interim_update(Db& db,
                    AccountingWorker* accounting,
                    const PolicydConfig& config) {
    if (config.dry_run || !accounting) {
        return;
    }
    if (!status_snapshot_fresh(config)) {
        return;
    }
    const auto snapshot = parse_openvpn_status(config.status_file);
    if (!snapshot.valid) {
        return;
    }

    for (const auto& session : list_sessions(db)) {
        const std::string ip = format_ipv4(session.virtual_ip);
        const auto found = snapshot.clients.find(ip);
        if (found == snapshot.clients.end()) {
            continue;
        }
        update_session_stats(db, session.session_id,
                             found->second.bytes_received,
                             found->second.bytes_sent);
        send_interim(accounting, session, config.nas_ip,
                     found->second.bytes_received, found->second.bytes_sent,
                     session_duration(session));
    }
}

int create_server_socket(const std::string& path, mode_t mode) {
    ::unlink(path.c_str());
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        throw std::runtime_error(std::string("socket failed: ") +
                                 std::strerror(errno));
    }

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path.size() + 1 >= sizeof(address.sun_path)) {
        ::close(fd);
        throw std::runtime_error("socket path is too long");
    }
    std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        const std::string error = std::strerror(errno);
        ::close(fd);
        throw std::runtime_error("bind failed: " + error);
    }
    ::chmod(path.c_str(), mode);
    if (::listen(fd, 16) != 0) {
        const std::string error = std::strerror(errno);
        ::close(fd);
        throw std::runtime_error("listen failed: " + error);
    }
    return fd;
}

void handle_client(int fd,
                   Db& db,
                   NftManager& nft,
                   AccountingWorker* accounting,
                   const PolicydConfig& config,
                   PolicyCache& cache,
                   RuntimeStats& stats) {
    ucred credentials{};
    socklen_t length = sizeof(credentials);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        credentials.uid != config.allowed_uid) {
        ipc_write_response(fd, false, "unauthorized peer");
        return;
    }

    std::string command;
    IpcFields fields;
    std::string error;
    if (!ipc_read_block(fd, &command, &fields, &error)) {
        ipc_write_response(fd, false, error);
        return;
    }

    try {
        if (command == "PING") {
            ipc_write_response(fd, true, "");
        } else if (command == "STATS") {
            ipc_write_response(fd, true, runtime_stats_line(stats));
        } else if (command == "CONNECT") {
            handle_connect(fields, db, nft, accounting, config, cache);
            ipc_write_response(fd, true, "");
        } else if (command == "DISCONNECT") {
            handle_disconnect(fields, db, nft, accounting, config, cache);
            ipc_write_response(fd, true, "");
        } else if (command == "REFRESH") {
            handle_refresh(fields, db, nft, config, cache, stats);
            ipc_write_response(fd, true, "");
        } else if (command == "KICK") {
            handle_kick(fields, config);
            ipc_write_response(fd, true, "");
        } else {
            ipc_write_response(fd, false, "unknown command");
        }
    } catch (const std::exception& exception) {
        ipc_write_response(fd, false, exception.what());
    } catch (...) {
        ipc_write_response(fd, false, "internal error");
    }
}

} // namespace

int main(int argc, char** argv) {
    struct sigaction ignore_action {};
    ignore_action.sa_handler = SIG_IGN;
    sigemptyset(&ignore_action.sa_mask);
    sigaction(SIGPIPE, &ignore_action, nullptr);

    std::string config_path = "/etc/vpn-policy/policyd.conf";
    bool check_only = false;
    bool require_db = false;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (argument == "--check") {
            check_only = true;
        } else if (argument == "--require-db") {
            require_db = true;
        } else {
            std::cerr << "usage: vpn-policyd [--config PATH] "
                         "[--check [--require-db]]\n";
            return 2;
        }
    }

    try {
        const PolicydConfig config = load_config(config_path);
        if (check_only) {
            return run_check(config, require_db);
        }

        vpn::LogConfig log_config;
        log_config.file = config.log_file;
        log_config.level = config.log_level;
        log_config.max_size = config.log_max_size;
        log_config.max_files = config.log_max_files;
        log_config.console = config.log_console;
        try {
            vpn::init_logging(log_config);
        } catch (const std::exception& exception) {
            std::cerr << "vpn-policyd: logging initialization failed: "
                      << exception.what() << "\n";
        }

        struct sigaction action {};
        action.sa_handler = stop_handler;
        sigemptyset(&action.sa_mask);
        sigaction(SIGTERM, &action, nullptr);
        sigaction(SIGINT, &action, nullptr);

        Db db(config.db);
        bool db_ready = false;
        int backoff = 1;
        while (running && !db_ready) {
            try {
                db.connect();
                db_ready = true;
            } catch (const std::exception& exception) {
                log_error(std::string("database connection failed: ") +
                          exception.what() + "; retrying in " +
                          std::to_string(backoff) + "s");
                if (!sleep_interruptible(backoff)) {
                    return 0;
                }
                backoff = std::min(backoff * 2, 30);
            }
        }
        if (!db_ready) {
            return 0;
        }

        std::unique_ptr<AccountingWorker> accounting;
        if (config.accounting_enabled && !config.dry_run) {
            try {
                accounting = std::make_unique<AccountingWorker>(config.radius);
                accounting->start();
            } catch (const std::exception& exception) {
                accounting.reset();
                log_warn(std::string("accounting disabled: ") +
                         exception.what());
            }
        }

        NftManager nft(config.nft_bin, config.nft_table, config.tun_iface,
                       config.work_dir, config.dry_run);
        std::string error;
        if (!nft.ensure_base(&error)) {
            log_error("failed to initialize nftables: " + error +
                      "; will retry periodically");
        }

        try {
            recover_sessions(db, nft, accounting.get(), config);
        } catch (const std::exception& exception) {
            log_error(std::string("session recovery failed: ") +
                      exception.what());
        }

        const int server_fd = create_server_socket(config.socket_path, 0660);
        vpn::log_info("listening on " + config.socket_path);

        PolicyCache policy_cache;
        RuntimeStats runtime_stats;

        auto next_reconcile = std::chrono::steady_clock::now() +
                              std::chrono::seconds(config.reconcile_interval);
        auto next_interim = std::chrono::steady_clock::now() +
                            std::chrono::seconds(config.interim_interval);

        while (running) {
            const auto now = std::chrono::steady_clock::now();
            auto timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
                               next_reconcile - now)
                               .count();
            timeout = std::min<long long>(timeout, 1000);
            if (timeout < 0) {
                timeout = 0;
            }

            pollfd poll_fd{};
            poll_fd.fd = server_fd;
            poll_fd.events = POLLIN;
            const int ready = ::poll(&poll_fd, 1, static_cast<int>(timeout));
            if (ready > 0 && (poll_fd.revents & POLLIN)) {
                const int client_fd = ::accept(server_fd, nullptr, nullptr);
                if (client_fd >= 0) {
                    try {
                        handle_client(client_fd, db, nft, accounting.get(),
                                      config, policy_cache, runtime_stats);
                    } catch (const std::exception& exception) {
                        log_error(std::string("client handling failed: ") +
                                  exception.what());
                    } catch (...) {
                        log_error("client handling failed: unknown exception");
                    }
                    ::close(client_fd);
                }
            }

            const auto after = std::chrono::steady_clock::now();
            if (after >= next_reconcile) {
                ++runtime_stats.reconcile_total;
                const auto reconcile_started = std::chrono::steady_clock::now();
                try {
                    reconcile(db, nft, accounting.get(), config);
                } catch (const std::exception& exception) {
                    ++runtime_stats.reconcile_errors;
                    log_error(std::string("reconcile failed: ") + exception.what());
                }
                const auto reconcile_elapsed =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - reconcile_started)
                        .count();
                runtime_stats.last_reconcile_duration_ms =
                    reconcile_elapsed > 0
                        ? static_cast<std::uint64_t>(reconcile_elapsed)
                        : 0;
                runtime_stats.last_reconcile_time =
                    static_cast<std::uint64_t>(std::time(nullptr));
                next_reconcile = after + std::chrono::seconds(config.reconcile_interval);
            }
            if (after >= next_interim) {
                try {
                    interim_update(db, accounting.get(), config);
                } catch (const std::exception& exception) {
                    log_error(std::string("interim update failed: ") +
                             exception.what());
                }
                next_interim = after + std::chrono::seconds(config.interim_interval);
            }
        }

        ::close(server_fd);
        ::unlink(config.socket_path.c_str());
        if (accounting) {
            accounting->stop();
        }
        return 0;
    } catch (const std::exception& exception) {
        vpn::log_error(std::string("fatal: ") + exception.what());
        return 1;
    }
}