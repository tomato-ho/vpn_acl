#pragma once

#include "vpn/db.h"
#include "vpn/service/types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vpn::service {

struct SessionHistoryQuery {
    std::string range{"today"};
    std::string from;
    std::string to;
    std::string username;
    std::uint32_t page{1};
    std::uint32_t page_size{50};
    bool include_deleted{true};
};

struct HistorySession {
    std::string session_id;
    std::string username;
    std::string virtual_ip;
    std::string remote_ip;
    std::string start_time;
    std::string stop_time;
    std::uint64_t duration_seconds{0};
    std::uint64_t bytes_in{0};
    std::uint64_t bytes_out{0};
    std::string terminate_cause;
    std::string state;
    bool user_exists{true};
};

struct SessionHistoryStats {
    std::uint64_t unique_users{0};
    std::uint64_t session_count{0};
    std::uint64_t online_sessions{0};
    std::uint64_t total_seconds{0};
    std::uint64_t bytes_in{0};
    std::uint64_t bytes_out{0};
};

struct AuthFailure {
    std::uint64_t id{0};
    std::string username;
    std::string reply;
    std::string auth_time;
    bool user_exists{true};
};

PagedResult<HistorySession> query_session_history(
    Db& db, const SessionHistoryQuery& query);
SessionHistoryStats query_session_history_stats(
    Db& db, const SessionHistoryQuery& query);
PagedResult<AuthFailure> query_auth_failures(
    Db& db, const SessionHistoryQuery& query);

std::vector<HistorySession> export_session_history(
    Db& db, const SessionHistoryQuery& query, std::size_t max_rows);
std::vector<AuthFailure> export_auth_failures(
    Db& db, const SessionHistoryQuery& query, std::size_t max_rows);

} // namespace vpn::service