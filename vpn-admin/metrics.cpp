#include "metrics.h"

#include "vpn/ipc.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace vpn::admin {
namespace {

std::uint64_t parse_u64(const std::string& value) {
    if (value.empty()) {
        return 0;
    }
    try {
        return static_cast<std::uint64_t>(std::stoull(value));
    } catch (const std::exception&) {
        return 0;
    }
}

bool unix_socket_alive(const std::string& path) {
    if (path.empty() || path.size() + 1 >= sizeof(sockaddr_un::sun_path)) {
        return false;
    }
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
    const bool ok =
        ::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
    ::close(fd);
    return ok;
}

std::string escape_label(const std::string& value) {
    std::string output;
    output.reserve(value.size());
    for (const char ch : value) {
        if (ch == '\\' || ch == '"') {
            output.push_back('\\');
            output.push_back(ch);
        } else if (ch == '\n') {
            output += "\\n";
        } else {
            output.push_back(ch);
        }
    }
    return output;
}

void add_help(std::ostringstream& out,
              const char* name,
              const char* type,
              const char* help) {
    out << "# HELP " << name << ' ' << help << '\n';
    out << "# TYPE " << name << ' ' << type << '\n';
}

void parse_policyd_stats(const std::string& line, PolicydStats* stats) {
    std::size_t offset = 0;
    while (offset <= line.size()) {
        const auto end = line.find(';', offset);
        const std::string part =
            line.substr(offset, end == std::string::npos ? std::string::npos
                                                         : end - offset);
        const auto equal = part.find('=');
        if (equal != std::string::npos) {
            const std::string key = part.substr(0, equal);
            const std::uint64_t value = parse_u64(part.substr(equal + 1));
            if (key == "refresh_total") {
                stats->refresh_total = value;
            } else if (key == "refresh_errors") {
                stats->refresh_errors = value;
            } else if (key == "refresh_fallback_total") {
                stats->refresh_fallback_total = value;
            } else if (key == "refresh_nft_calls_total") {
                stats->refresh_nft_calls_total = value;
            } else if (key == "last_refresh_duration_ms") {
                stats->last_refresh_duration_ms = value;
            } else if (key == "last_refresh_time") {
                stats->last_refresh_time = value;
            } else if (key == "reconcile_total") {
                stats->reconcile_total = value;
            } else if (key == "reconcile_errors") {
                stats->reconcile_errors = value;
            } else if (key == "last_reconcile_duration_ms") {
                stats->last_reconcile_duration_ms = value;
            } else if (key == "last_reconcile_time") {
                stats->last_reconcile_time = value;
            }
        }
        if (end == std::string::npos) {
            break;
        }
        offset = end + 1;
    }
    stats->available = true;
}

} // namespace

MetricsCollector::MetricsCollector(const AdminConfig& config, DbPool& pool)
    : config_(config), pool_(pool) {}

MetricsSnapshot MetricsCollector::collect() {
    MetricsSnapshot snapshot;
    snapshot.collected_at = std::time(nullptr);
    const auto status = service::parse_openvpn_status(config_.status_file);

    try {
        auto lease = pool_.acquire();
        lease.db().query("SELECT 1");
        snapshot.database_up = true;

        snapshot.dashboard =
            service::dashboard_summary(lease.db(), status);
        snapshot.sessions = service::list_sessions(lease.db(), status);

        const auto rows = lease.db().query(
            "SELECT (SELECT COUNT(*) FROM vpn_sessions), "
            "(SELECT COUNT(*) FROM vpn_session_history)");
        if (!rows.empty() && rows[0].size() >= 2) {
            snapshot.radacct_open = parse_u64(rows[0][0]);
            snapshot.radacct_closed = parse_u64(rows[0][1]);
        }

        const auto auth_rows = lease.db().query(
            "SELECT IFNULL(UNIX_TIMESTAMP(MAX(created_at)), 0) "
            "FROM vpn_auth_log WHERE success = 1");
        if (!auth_rows.empty() && !auth_rows[0].empty()) {
            snapshot.auth_last_success = parse_u64(auth_rows[0][0]);
        }
    } catch (const std::exception&) {
        snapshot.database_up = false;
        snapshot.dashboard = service::DashboardSummary{};
        snapshot.sessions.clear();
    }

    if (!snapshot.database_up) {
        snapshot.dashboard.active_sessions = status.clients.size();
        for (const auto& entry : status.clients) {
            service::SessionInfo session;
            session.username = entry.second.username;
            session.virtual_ip = entry.second.virtual_ip;
            session.bytes_in = entry.second.bytes_received;
            session.bytes_out = entry.second.bytes_sent;
            session.online = true;
            snapshot.sessions.push_back(session);
        }
    }

    snapshot.policyd_up = unix_socket_alive(config_.policyd_socket);
    if (snapshot.policyd_up) {
        std::string response;
        std::string error;
        if (ipc_request(config_.policyd_socket, "STATS", {}, &response, &error,
                        1)) {
            parse_policyd_stats(response, &snapshot.policyd);
        }
    }
    return snapshot;
}

MetricsSnapshot MetricsCollector::get() {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::time_t now = std::time(nullptr);
    if (has_cache_ && now - cache_.collected_at <
                          static_cast<std::time_t>(config_.metrics_cache_seconds)) {
        return cache_;
    }
    cache_ = collect();
    has_cache_ = true;
    return cache_;
}

std::string MetricsCollector::prometheus() {
    const auto snapshot = get();
    const auto& summary = snapshot.dashboard;

    std::ostringstream out;
    add_help(out, "vpn_active_sessions", "gauge",
             "Current active VPN sessions");
    out << "vpn_active_sessions " << summary.active_sessions << "\n";

    add_help(out, "vpn_users", "gauge", "VPN users by status");
    out << "vpn_users{status=\"enabled\"} " << summary.users_enabled << "\n";
    out << "vpn_users{status=\"disabled\"} "
        << (summary.users_total - summary.users_enabled) << "\n";

    add_help(out, "vpn_groups", "gauge", "VPN groups");
    out << "vpn_groups " << summary.groups_total << "\n";

    add_help(out, "vpn_auth_total", "counter",
             "RADIUS authentication results");
    out << "vpn_auth_total{result=\"accept\"} " << summary.auth_accept_total
        << "\n";
    out << "vpn_auth_total{result=\"reject\"} " << summary.auth_reject_total
        << "\n";
    add_help(out, "vpn_auth_last_success_timestamp", "gauge",
             "Last successful VPN authentication timestamp");
    out << "vpn_auth_last_success_timestamp " << snapshot.auth_last_success
        << "\n";

    add_help(out, "vpn_radacct_sessions", "gauge",
             "VPN sessions (open = online, closed = archived history)");
    out << "vpn_radacct_sessions{state=\"open\"} " << snapshot.radacct_open
        << "\n";
    out << "vpn_radacct_sessions{state=\"closed\"} "
        << snapshot.radacct_closed << "\n";

    add_help(out, "vpn_policy_version", "gauge", "Current policy version");
    out << "vpn_policy_version " << summary.policy_version << "\n";

    add_help(out, "vpn_audit_entries_total", "counter",
             "Audit log entries");
    out << "vpn_audit_entries_total " << summary.audit_entries << "\n";

    add_help(out, "vpn_session_rx_bytes", "gauge",
             "VPN session received bytes");
    add_help(out, "vpn_session_tx_bytes", "gauge",
             "VPN session sent bytes");
    add_help(out, "vpn_session_age_seconds", "gauge",
             "VPN session age in seconds");
    add_help(out, "vpn_session_online", "gauge",
             "VPN session online state");
    for (const auto& session : snapshot.sessions) {
        const std::string labels =
            "user=\"" + escape_label(session.username) + "\",ip=\"" +
            escape_label(session.virtual_ip) + "\"";
        out << "vpn_session_rx_bytes{" << labels << "} " << session.bytes_in
            << "\n";
        out << "vpn_session_tx_bytes{" << labels << "} " << session.bytes_out
            << "\n";
        out << "vpn_session_age_seconds{" << labels << "} "
            << session.duration_seconds << "\n";
        out << "vpn_session_online{" << labels << "} "
            << (session.online ? 1 : 0) << "\n";
    }

    add_help(out, "vpn_db_up", "gauge", "Database availability");
    out << "vpn_db_up " << (snapshot.database_up ? 1 : 0) << "\n";
    add_help(out, "vpn_policyd_up", "gauge",
             "vpn-policyd socket availability");
    out << "vpn_policyd_up " << (snapshot.policyd_up ? 1 : 0) << "\n";

    add_help(out, "vpn_policyd_stats_available", "gauge",
             "vpn-policyd runtime statistics availability");
    out << "vpn_policyd_stats_available "
        << (snapshot.policyd.available ? 1 : 0) << "\n";
    add_help(out, "vpn_policyd_refresh_total", "counter",
             "vpn-policyd refresh requests");
    out << "vpn_policyd_refresh_total " << snapshot.policyd.refresh_total
        << "\n";
    add_help(out, "vpn_policyd_refresh_errors_total", "counter",
             "vpn-policyd refresh errors");
    out << "vpn_policyd_refresh_errors_total "
        << snapshot.policyd.refresh_errors << "\n";
    add_help(out, "vpn_policyd_refresh_fallback_total", "counter",
             "vpn-policyd refresh batch fallbacks");
    out << "vpn_policyd_refresh_fallback_total "
        << snapshot.policyd.refresh_fallback_total << "\n";
    add_help(out, "vpn_policyd_nft_calls_total", "counter",
             "vpn-policyd nft command calls");
    out << "vpn_policyd_nft_calls_total "
        << snapshot.policyd.refresh_nft_calls_total << "\n";
    add_help(out, "vpn_policyd_refresh_last_duration_seconds", "gauge",
             "Last vpn-policyd refresh duration in seconds");
    out << "vpn_policyd_refresh_last_duration_seconds "
        << static_cast<double>(snapshot.policyd.last_refresh_duration_ms) /
               1000.0
        << "\n";
    add_help(out, "vpn_policyd_refresh_last_timestamp", "gauge",
             "Last vpn-policyd refresh timestamp");
    out << "vpn_policyd_refresh_last_timestamp "
        << snapshot.policyd.last_refresh_time << "\n";
    add_help(out, "vpn_policyd_reconcile_total", "counter",
             "vpn-policyd reconcile runs");
    out << "vpn_policyd_reconcile_total " << snapshot.policyd.reconcile_total
        << "\n";
    add_help(out, "vpn_policyd_reconcile_errors_total", "counter",
             "vpn-policyd reconcile errors");
    out << "vpn_policyd_reconcile_errors_total "
        << snapshot.policyd.reconcile_errors << "\n";
    add_help(out, "vpn_policyd_reconcile_last_duration_seconds", "gauge",
             "Last vpn-policyd reconcile duration in seconds");
    out << "vpn_policyd_reconcile_last_duration_seconds "
        << static_cast<double>(snapshot.policyd.last_reconcile_duration_ms) /
               1000.0
        << "\n";
    add_help(out, "vpn_policyd_reconcile_last_timestamp", "gauge",
             "Last vpn-policyd reconcile timestamp");
    out << "vpn_policyd_reconcile_last_timestamp "
        << snapshot.policyd.last_reconcile_time << "\n";

    add_help(out, "vpn_admin_up", "gauge", "vpn-admin availability");
    out << "vpn_admin_up 1\n";

    return out.str();
}

nlohmann::json MetricsCollector::json() {
    const auto snapshot = get();
    const auto& summary = snapshot.dashboard;

    nlohmann::json out;
    out["dashboard"] = {
        {"users",
         {{"total", summary.users_total},
          {"enabled", summary.users_enabled},
          {"disabled", summary.users_total - summary.users_enabled}}},
        {"groups", summary.groups_total},
        {"active_sessions", summary.active_sessions},
        {"audit_entries", summary.audit_entries},
        {"policy_version", summary.policy_version},
        {"auth",
         {{"accept", summary.auth_accept_total},
          {"reject", summary.auth_reject_total}}}};
    out["database_up"] = snapshot.database_up;
    out["policyd_up"] = snapshot.policyd_up;
    out["policyd"] = {
        {"stats_available", snapshot.policyd.available},
        {"refresh_total", snapshot.policyd.refresh_total},
        {"refresh_errors", snapshot.policyd.refresh_errors},
        {"refresh_fallback_total", snapshot.policyd.refresh_fallback_total},
        {"refresh_nft_calls_total", snapshot.policyd.refresh_nft_calls_total},
        {"last_refresh_duration_ms",
         snapshot.policyd.last_refresh_duration_ms},
        {"last_refresh_time", snapshot.policyd.last_refresh_time},
        {"reconcile_total", snapshot.policyd.reconcile_total},
        {"reconcile_errors", snapshot.policyd.reconcile_errors},
        {"last_reconcile_duration_ms",
         snapshot.policyd.last_reconcile_duration_ms},
        {"last_reconcile_time", snapshot.policyd.last_reconcile_time}};
    out["radacct"] = {{"open", snapshot.radacct_open},
                      {"closed", snapshot.radacct_closed}};
    out["auth_last_success"] = snapshot.auth_last_success;

    nlohmann::json sessions = nlohmann::json::array();
    for (const auto& session : snapshot.sessions) {
        sessions.push_back(
            {{"session_id", session.session_id},
             {"username", session.username},
             {"virtual_ip", session.virtual_ip},
             {"remote_ip", session.remote_ip},
             {"start_time", session.start_time},
             {"duration_seconds", session.duration_seconds},
             {"bytes_in", session.bytes_in},
             {"bytes_out", session.bytes_out},
             {"online", session.online}});
    }
    out["sessions"] = sessions;
    return out;
}

} // namespace vpn::admin