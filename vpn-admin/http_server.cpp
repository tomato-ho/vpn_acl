#include "http_server.h"

#include "vpn/cidr.h"
#include "vpn/ipc.h"
#include "vpn/password.h"
#include "vpn/policy_store.h"
#include "vpn/service/admin_read.h"
#include "vpn/service/transaction.h"
#include "vpn/service/errors.h"
#include "vpn/service/group_write.h"
#include "vpn/service/metrics_read.h"
#include "vpn/service/service_write.h"
#include "vpn/service/session_history.h"
#include "vpn/service/settings_write.h"
#include "vpn/service/user_write.h"
#include "vpn/util.h"

#include <nlohmann/json.hpp>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace vpn::admin {
namespace {

using json = nlohmann::json;

constexpr const char* kCookieName = "vpn_admin_session";

std::string cookie_value(const httplib::Request& req) {
    const std::string header = req.get_header_value("Cookie");
    std::size_t start = 0;
    while (start < header.size()) {
        std::size_t end = header.find(';', start);
        if (end == std::string::npos) {
            end = header.size();
        }
        const std::string part =
            vpn::trim(header.substr(start, end - start));
        const auto equal = part.find('=');
        if (equal != std::string::npos &&
            part.substr(0, equal) == kCookieName) {
            return part.substr(equal + 1);
        }
        start = end + 1;
    }
    return {};
}

void set_session_cookie(httplib::Response& res,
                        const std::string& token,
                        unsigned int ttl,
                        bool secure) {
    std::string cookie = std::string(kCookieName) + "=" + token +
                         "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" +
                         std::to_string(ttl);
    if (secure) {
        cookie += "; Secure";
    }
    res.set_header("Set-Cookie", cookie);
}

void clear_session_cookie(httplib::Response& res, bool secure) {
    std::string cookie = std::string(kCookieName) +
                         "=; Path=/; HttpOnly; SameSite=Strict; "
                         "Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
    if (secure) {
        cookie += "; Secure";
    }
    res.set_header("Set-Cookie", cookie);
}

void send_json(httplib::Response& res, int status, const json& value) {
    res.status = status;
    res.set_header("Cache-Control", "no-store");
    res.set_content(value.dump(), "application/json; charset=utf-8");
}

void send_error(httplib::Response& res,
                int status,
                const std::string& code,
                const std::string& message) {
    send_json(res, status, json{{"error", {{"code", code}, {"message", message}}}});
}

std::optional<Session> require_session(const httplib::Request& req,
                                       httplib::Response& res,
                                       SessionStore& sessions,
                                       bool require_csrf) {
    const std::string token = cookie_value(req);
    const auto session = sessions.find(token);
    if (!session) {
        send_error(res, 401, "unauthorized", "login required");
        return std::nullopt;
    }
    if (require_csrf && req.method != "GET" && req.method != "HEAD" &&
        req.method != "OPTIONS") {
        const std::string token_header =
            req.get_header_value("X-CSRF-Token");
        if (token_header != session->csrf) {
            send_error(res, 403, "csrf", "invalid csrf token");
            return std::nullopt;
        }
    }
    return session;
}

std::string client_ip(const httplib::Request& req, bool trust_proxy) {
    if (!trust_proxy ||
        (req.remote_addr != "127.0.0.1" && req.remote_addr != "::1")) {
        return req.remote_addr;
    }
    const std::string real_ip = req.get_header_value("X-Real-IP");
    if (!real_ip.empty()) {
        return real_ip;
    }
    const std::string forwarded = req.get_header_value("X-Forwarded-For");
    if (!forwarded.empty()) {
        const auto comma = forwarded.find(',');
        return vpn::trim(comma == std::string::npos
                             ? forwarded
                             : forwarded.substr(0, comma));
    }
    return req.remote_addr;
}

unsigned int query_u32(const httplib::Request& req,
                       const char* name,
                       unsigned int fallback,
                       unsigned int minimum,
                       unsigned int maximum) {
    if (!req.has_param(name)) {
        return fallback;
    }
    const std::string value = req.get_param_value(name);
    try {
        std::size_t consumed = 0;
        const unsigned long parsed = std::stoul(value, &consumed, 10);
        if (consumed != value.size()) {
            return fallback;
        }
        if (parsed < minimum) {
            return minimum;
        }
        if (parsed > maximum) {
            return maximum;
        }
        return static_cast<unsigned int>(parsed);
    } catch (const std::exception&) {
        return fallback;
    }
}

service::SessionHistoryQuery parse_history_query(
    const httplib::Request& req, bool default_include_deleted) {
    service::SessionHistoryQuery query;
    query.range = req.has_param("range")
                      ? req.get_param_value("range")
                      : "today";
    query.from = req.has_param("from") ? req.get_param_value("from") : "";
    query.to = req.has_param("to") ? req.get_param_value("to") : "";
    query.username =
        req.has_param("username") ? req.get_param_value("username") : "";
    query.page = query_u32(req, "page", 1, 1, 1000000);
    query.page_size = query_u32(req, "page_size", 50, 1, 200);
    query.include_deleted = default_include_deleted;
    if (req.has_param("include_deleted")) {
        query.include_deleted =
            req.get_param_value("include_deleted") != "0";
    }
    return query;
}

json history_session_json(const service::HistorySession& session) {
    return json{{"username", session.username},
                {"virtual_ip", session.virtual_ip},
                {"remote_ip", session.remote_ip},
                {"start_time", session.start_time},
                {"stop_time", session.stop_time},
                {"duration_seconds", session.duration_seconds},
                {"bytes_in", session.bytes_in},
                {"bytes_out", session.bytes_out},
                {"terminate_cause", session.terminate_cause},
                {"state", session.state},
                {"user_exists", session.user_exists}};
}

json history_stats_json(const service::SessionHistoryStats& stats) {
    return json{{"unique_users", stats.unique_users},
                {"session_count", stats.session_count},
                {"online_sessions", stats.online_sessions},
                {"total_seconds", stats.total_seconds},
                {"bytes_in", stats.bytes_in},
                {"bytes_out", stats.bytes_out}};
}

json auth_failure_json(const service::AuthFailure& failure) {
    return json{{"id", failure.id},
                {"username", failure.username},
                {"reply", failure.reply},
                {"auth_time", failure.auth_time},
                {"user_exists", failure.user_exists}};
}

std::string csv_escape(const std::string& value) {
    std::string output = "\"";
    if (!value.empty() &&
        (value[0] == '=' || value[0] == '+' || value[0] == '-' ||
         value[0] == '@' || value[0] == '\t' || value[0] == '\r')) {
        output.push_back('\'');
    }
    for (const char ch : value) {
        if (ch == '"') {
            output += "\"\"";
        } else if (ch == '\r' || ch == '\n') {
            output += ' ';
        } else {
            output.push_back(ch);
        }
    }
    output += '"';
    return output;
}

std::string session_csv(const std::vector<service::HistorySession>& rows) {
    std::ostringstream out;
    out << "username,virtual_ip,remote_ip,start_time,stop_time,"
           "duration_seconds,bytes_in,bytes_out,terminate_cause,state,"
           "user_exists\n";
    for (const auto& row : rows) {
        out << csv_escape(row.username) << ',' << csv_escape(row.virtual_ip)
            << ',' << csv_escape(row.remote_ip) << ','
            << csv_escape(row.start_time) << ',' << csv_escape(row.stop_time)
            << ',' << row.duration_seconds << ',' << row.bytes_in << ','
            << row.bytes_out << ',' << csv_escape(row.terminate_cause) << ','
            << csv_escape(row.state) << ','
            << (row.user_exists ? "true" : "false") << '\n';
    }
    return out.str();
}

std::string auth_csv(const std::vector<service::AuthFailure>& rows) {
    std::ostringstream out;
    out << "auth_time,username,reply,user_exists\n";
    for (const auto& row : rows) {
        out << csv_escape(row.auth_time) << ',' << csv_escape(row.username)
            << ',' << csv_escape(row.reply) << ','
            << (row.user_exists ? "true" : "false") << '\n';
    }
    return out.str();
}

void send_csv(httplib::Response& res,
              const std::string& content,
              const std::string& filename) {
    res.set_header("Content-Disposition",
                   "attachment; filename=\"" + filename + "\"");
    res.set_header("Cache-Control", "no-store");
    res.set_content(content, "text/csv; charset=utf-8");
}

json user_json(const service::UserSummary& user) {
    return json{{"username", user.username},
                {"display_name", user.display_name},
                {"group", user.group_name},
                {"fixed_ip", user.fixed_ip},
                {"enabled", user.enabled},
                {"must_change_password", user.must_change_password},
                {"created_at", user.created_at},
                {"updated_at", user.updated_at}};
}

json rule_json(const service::UserRule& rule) {
    return json{{"id", rule.id},
                {"rule_type", rule.rule_type},
                {"cidr", rule.cidr},
                {"enabled", rule.enabled},
                {"created_at", rule.created_at}};
}

json cidr_list_json(const std::vector<Cidr>& cidrs) {
    json items = json::array();
    for (const auto& cidr : cidrs) {
        items.push_back(cidr.to_string());
    }
    return items;
}

json service_list_json(const std::vector<Service>& services) {
    json items = json::array();
    for (const auto& service : services) {
        items.push_back(service.to_string());
    }
    return items;
}

json service_row_json(const service::ServiceRow& row) {
    return json{{"id", row.id},
                {"scope_type", row.scope_type},
                {"scope_id", row.scope_id},
                {"service", row.service},
                {"enabled", row.enabled},
                {"created_at", row.created_at}};
}

json settings_json(const service::SettingsMap& settings) {
    json out = json::object();
    for (const auto& entry : settings) {
        out[entry.first] = entry.second;
    }
    return out;
}

json user_detail_json(const service::UserDetail& detail) {
    json out = user_json(detail.user);
    json rules = json::array();
    for (const auto& rule : detail.rules) {
        rules.push_back(rule_json(rule));
    }
    out["rules"] = rules;
    if (detail.policy_error.empty()) {
        out["policy"] = json{
            {"fixed_ip", format_ipv4(detail.policy.fixed_ip)},
            {"group", detail.policy.group_name},
            {"allow", cidr_list_json(detail.policy.allow)},
            {"deny", cidr_list_json(detail.policy.deny)},
            {"push_routes", cidr_list_json(detail.policy.push_routes)},
            {"services", service_list_json(detail.policy.services)}};
    } else {
        out["policy_error"] = detail.policy_error;
    }
    return out;
}

struct PolicydOutcome {
    bool ok{false};
    std::string error;
};

PolicydOutcome call_policyd(const AdminConfig& config,
                            const std::string& command,
                            const std::string& username) {
    IpcFields fields;
    if (!username.empty()) {
        fields["username"] = username;
    }
    std::string response;
    std::string error;
    PolicydOutcome outcome;
    outcome.ok = ipc_request(config.policyd_socket, command, fields, &response,
                             &error, 30);
    outcome.error = error;
    if (!outcome.ok) {
        std::cerr << "vpn-admin: policyd " << command << " failed";
        if (!username.empty()) {
            std::cerr << " for " << username;
        }
        std::cerr << ": " << error << "\n";
    }
    return outcome;
}

void set_policy_header(httplib::Response& res,
                       const char* name,
                       const PolicydOutcome& outcome) {
    res.set_header(name, outcome.ok ? "applied" : "failed");
}

bool parse_body(const httplib::Request& req,
                httplib::Response& res,
                json* body) {
    *body = json::parse(req.body, nullptr, false);
    if (body->is_discarded() || !body->is_object()) {
        send_error(res, 400, "bad_request", "invalid JSON body");
        return false;
    }
    return true;
}

json group_json(const service::GroupSummary& group) {
    return json{{"id", group.id},
                {"name", group.name},
                {"ip_start", group.ip_start},
                {"ip_end", group.ip_end},
                {"description", group.description},
                {"user_count", group.user_count},
                {"rule_count", group.rule_count}};
}

json group_rule_json(const service::GroupRule& rule) {
    return json{{"id", rule.id},
                {"rule_type", rule.rule_type},
                {"cidr", rule.cidr},
                {"enabled", rule.enabled},
                {"created_at", rule.created_at}};
}

json group_detail_json(const service::GroupDetail& detail) {
    json out = group_json(detail.group);
    json rules = json::array();
    for (const auto& rule : detail.rules) {
        rules.push_back(group_rule_json(rule));
    }
    out["rules"] = rules;
    return out;
}

json session_json(const service::SessionInfo& session) {
    return json{{"session_id", session.session_id},
                {"username", session.username},
                {"virtual_ip", session.virtual_ip},
                {"remote_ip", session.remote_ip},
                {"start_time", session.start_time},
                {"duration_seconds", session.duration_seconds},
                {"bytes_in", session.bytes_in},
                {"bytes_out", session.bytes_out},
                {"online", session.online}};
}

json audit_json(const service::AuditEntry& entry) {
    return json{{"id", entry.id},
                {"operator", entry.operator_name},
                {"action", entry.action},
                {"target", entry.target},
                {"before", entry.before_json},
                {"after", entry.after_json},
                {"created_at", entry.created_at}};
}

json dashboard_json(const service::DashboardSummary& summary) {
    return json{{"users",
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
}

json me_json(const Session& session) {
    return json{{"username", session.username},
                {"csrf_token", session.csrf},
                {"expires_at", session.expires_at}};
}

bool db_alive(DbPool& pool) {
    try {
        auto lease = pool.acquire();
        lease.db().query("SELECT 1");
        return true;
    } catch (const std::exception& error) {
        // 限流：最多每 30 秒打一条，避免健康检查刷屏。
        static std::mutex mutex;
        static std::chrono::steady_clock::time_point last{};
        std::lock_guard<std::mutex> lock(mutex);
        const auto now = std::chrono::steady_clock::now();
        if (last.time_since_epoch().count() == 0 ||
            now - last >= std::chrono::seconds(30)) {
            last = now;
            std::cerr << "vpn-admin: readyz database check failed: "
                      << error.what() << "\n";
        }
        return false;
    }
}

template <typename Fn>
void handle(httplib::Response& res, Fn&& fn) {
    try {
        fn();
    } catch (const DbError& error) {
        std::cerr << "vpn-admin: database unavailable: " << error.what()
                  << "\n";
        send_error(res, 503, "unavailable", "database unavailable");
    } catch (const service::ServiceError& error) {
        int status = 500;
        const char* code = "internal";
        switch (error.code()) {
        case service::ErrorCode::validation:
            status = 400;
            code = "validation";
            break;
        case service::ErrorCode::not_found:
            status = 404;
            code = "not_found";
            break;
        case service::ErrorCode::conflict:
            status = 409;
            code = "conflict";
            break;
        case service::ErrorCode::unavailable:
            status = 503;
            code = "unavailable";
            break;
        case service::ErrorCode::internal:
            status = 500;
            break;
        }
        send_error(res, status, code, error.what());
    } catch (const std::exception& error) {
        std::cerr << "vpn-admin: " << error.what() << "\n";
        send_error(res, 500, "internal", "internal server error");
    }
}

} // namespace

HttpServer::HttpServer(const AdminConfig& config,
                       DbPool& pool,
                       SessionStore& sessions,
                       LoginLimiter& limiter,
                       MetricsCollector& metrics)
    : config_(config),
      pool_(pool),
      sessions_(sessions),
      limiter_(limiter),
      metrics_(metrics) {}

std::string HttpServer::admin_metrics() {
    std::ostringstream out;
    out << "# HELP vpn_admin_login_failures_total "
           "Failed admin login attempts\n";
    out << "# TYPE vpn_admin_login_failures_total counter\n";
    out << "vpn_admin_login_failures_total " << login_failures_.load()
        << "\n";
    out << "# HELP vpn_admin_http_requests_total "
           "Admin HTTP requests by method and status\n";
    out << "# TYPE vpn_admin_http_requests_total counter\n";

    std::lock_guard<std::mutex> lock(counter_mutex_);
    for (const auto& entry : request_counts_) {
        const auto separator = entry.first.find('|');
        const std::string method =
            separator == std::string::npos
                ? entry.first
                : entry.first.substr(0, separator);
        const std::string status =
            separator == std::string::npos
                ? "0"
                : entry.first.substr(separator + 1);
        out << "vpn_admin_http_requests_total{method=\"" << method
            << "\",status=\"" << status << "\"} " << entry.second << "\n";
    }
    return out.str();
}

void HttpServer::stop() {
    server_.stop();
}

bool HttpServer::run() {
    setup_routes();
    return server_.listen(config_.bind.c_str(),
                          static_cast<int>(config_.port));
}

void HttpServer::setup_routes() {
    server_.set_payload_max_length(1024 * 1024);
    server_.set_read_timeout(10, 0);
    server_.set_write_timeout(10, 0);
    server_.set_logger([this](const httplib::Request& req,
                             const httplib::Response& res) {
        const std::string key =
            req.method + "|" + std::to_string(res.status);
        std::lock_guard<std::mutex> lock(counter_mutex_);
        ++request_counts_[key];
    });

    server_.Post("/api/login", [this](const httplib::Request& req,
                                      httplib::Response& res) {
        handle(res, [&]() {
            const auto body = json::parse(req.body, nullptr, false);
            if (body.is_discarded() || !body.is_object() ||
                !body.contains("username") || !body["username"].is_string() ||
                !body.contains("password") || !body["password"].is_string()) {
                send_error(res, 400, "bad_request",
                           "username and password are required");
                return;
            }
            const std::string username =
                body["username"].get<std::string>();
            const std::string password =
                body["password"].get<std::string>();
            if (username.empty() || username.size() > 64 || password.empty() ||
                password.size() > 256) {
                send_error(res, 400, "bad_request", "invalid credentials");
                return;
            }

            const std::string key =
                client_ip(req, config_.trust_proxy) + "|" + username;
            if (limiter_.locked(key)) {
                send_error(res, 429, "rate_limited",
                           "too many login attempts, try later");
                return;
            }

            auto lease = pool_.acquire();
            const auto rows = lease.db().query(
                "SELECT password_hash, enabled FROM vpn_admins WHERE username='" +
                lease.db().quote(username) + "'");

            bool valid = false;
            if (!rows.empty() && rows[0].size() >= 2 &&
                vpn::parse_bool(rows[0][1], false)) {
                valid = vpn::verify_admin_password(password, rows[0][0]);
            }

            if (!valid) {
                limiter_.failure(key);
                ++login_failures_;
                send_error(res, 401, "invalid_credentials",
                           "invalid username or password");
                return;
            }

            limiter_.success(key);
            const auto created = sessions_.create(username);
            set_session_cookie(res, created.token, config_.session_ttl,
                               config_.cookie_secure);
            send_json(res, 200, me_json(created.session));
        });
    });

    server_.Post("/api/logout", [this](const httplib::Request& req,
                                       httplib::Response& res) {
        handle(res, [&]() {
            if (!require_session(req, res, sessions_, false)) {
                return;
            }
            sessions_.erase(cookie_value(req));
            clear_session_cookie(res, config_.cookie_secure);
            res.status = 204;
        });
    });

    server_.Get("/api/me", [this](const httplib::Request& req,
                                  httplib::Response& res) {
        handle(res, [&]() {
            const auto session = require_session(req, res, sessions_, false);
            if (!session) {
                return;
            }
            send_json(res, 200, me_json(*session));
        });
    });

    server_.Post("/api/me/password",
                 [this](const httplib::Request& req,
                        httplib::Response& res) {
                     handle(res, [&]() {
                         const auto session =
                             require_session(req, res, sessions_, true);
                         if (!session) {
                             return;
                         }
                         json body;
                         if (!parse_body(req, res, &body)) {
                             return;
                         }
                         if (!body.contains("current_password") ||
                             !body["current_password"].is_string() ||
                             !body.contains("new_password") ||
                             !body["new_password"].is_string()) {
                             send_error(res, 400, "bad_request",
                                        "current_password and new_password are required");
                             return;
                         }
                         const std::string current_password =
                             body["current_password"].get<std::string>();
                         const std::string new_password =
                             body["new_password"].get<std::string>();
                         if (new_password.size() < 8 ||
                             new_password.size() > 256) {
                             send_error(res, 400, "validation",
                                        "password must be 8-256 bytes");
                             return;
                         }

                         auto lease = pool_.acquire();
                         const auto rows = lease.db().query(
                             "SELECT password_hash FROM vpn_admins "
                             "WHERE username = '" +
                             lease.db().quote(session->username) + "'");
                         if (rows.empty() || rows[0].empty() ||
                             !verify_admin_password(current_password,
                                                    rows[0][0])) {
                             send_error(res, 400, "invalid_credentials",
                                        "current password is incorrect");
                             return;
                         }

                         const std::string hash =
                             pbkdf2_sha256_admin(new_password);
                         service::Transaction tx(lease.db());
                         lease.db().execute(
                             "UPDATE vpn_admins SET password_hash = '" +
                             lease.db().quote(hash) + "' WHERE username = '" +
                             lease.db().quote(session->username) + "'");
                         write_audit_as(
                             lease.db(), session->username,
                             "admin-password-change", session->username, "",
                             json{{"password_changed", true}}.dump());
                         tx.commit();

                         sessions_.erase_user(session->username);
                         const auto created =
                             sessions_.create(session->username);
                         set_session_cookie(res, created.token,
                                            config_.session_ttl,
                                            config_.cookie_secure);
                         send_json(res, 200, me_json(created.session));
                     });
                 });

    server_.Get("/api/dashboard", [this](const httplib::Request& req,
                                         httplib::Response& res) {
        handle(res, [&]() {
            if (!require_session(req, res, sessions_, false)) {
                return;
            }
            auto lease = pool_.acquire();
            const auto status =
                service::parse_openvpn_status(config_.status_file);
            send_json(res, 200,
                      dashboard_json(
                          service::dashboard_summary(lease.db(), status)));
        });
    });

    server_.Get("/api/users", [this](const httplib::Request& req,
                                     httplib::Response& res) {
        handle(res, [&]() {
            if (!require_session(req, res, sessions_, false)) {
                return;
            }
            service::UserQuery query;
            query.query = req.has_param("query")
                              ? req.get_param_value("query")
                              : "";
            query.group = req.has_param("group")
                              ? req.get_param_value("group")
                              : "";
            query.page.page = query_u32(req, "page", 1, 1, 1000000);
            query.page.page_size = query_u32(req, "page_size", 50, 1, 200);

            auto lease = pool_.acquire();
            const auto result = service::list_users(lease.db(), query);
            json items = json::array();
            for (const auto& user : result.items) {
                items.push_back(user_json(user));
            }
            send_json(res, 200,
                      json{{"items", items},
                           {"total", result.total},
                           {"page", result.page},
                           {"page_size", result.page_size}});
        });
    });

    server_.Post("/api/users", [this](const httplib::Request& req,
                                      httplib::Response& res) {
        handle(res, [&]() {
            const auto session = require_session(req, res, sessions_, true);
            if (!session) {
                return;
            }
            json body;
            if (!parse_body(req, res, &body)) {
                return;
            }
            if (!body.contains("username") || !body["username"].is_string() ||
                !body.contains("group") || !body["group"].is_string() ||
                !body.contains("fixed_ip") || !body["fixed_ip"].is_string() ||
                !body.contains("password") || !body["password"].is_string()) {
                send_error(res, 400, "bad_request",
                           "username, group, fixed_ip and password are required");
                return;
            }

            service::CreateUserInput input;
            input.username = body["username"].get<std::string>();
            input.group = body["group"].get<std::string>();
            input.fixed_ip = body["fixed_ip"].get<std::string>();
            input.password = body["password"].get<std::string>();
            if (body.contains("display_name")) {
                if (!body["display_name"].is_string()) {
                    send_error(res, 400, "bad_request",
                               "display_name must be a string");
                    return;
                }
                input.display_name = body["display_name"].get<std::string>();
            }
            if (body.contains("must_change_password")) {
                if (!body["must_change_password"].is_boolean()) {
                    send_error(res, 400, "bad_request",
                               "must_change_password must be boolean");
                    return;
                }
                input.must_change_password =
                    body["must_change_password"].get<bool>();
            }

            auto lease = pool_.acquire();
            const auto user =
                service::create_user(lease.db(), input, session->username);
            const auto detail =
                service::get_user_detail(lease.db(), user.username);
            send_json(res, 201, detail ? user_detail_json(*detail)
                                       : user_json(user));
        });
    });

    server_.Patch(R"(/api/users/([^/]+))",
                  [this](const httplib::Request& req,
                         httplib::Response& res) {
                      handle(res, [&]() {
                          const auto session =
                              require_session(req, res, sessions_, true);
                          if (!session) {
                              return;
                          }
                          json body;
                          if (!parse_body(req, res, &body)) {
                              return;
                          }

                          service::UpdateUserInput input;
                          if (body.contains("display_name")) {
                              if (!body["display_name"].is_string()) {
                                  send_error(res, 400, "bad_request",
                                             "display_name must be a string");
                                  return;
                              }
                              input.display_name =
                                  body["display_name"].get<std::string>();
                          }
                          if (body.contains("group")) {
                              if (!body["group"].is_string()) {
                                  send_error(res, 400, "bad_request",
                                             "group must be a string");
                                  return;
                              }
                              input.group = body["group"].get<std::string>();
                          }
                          if (body.contains("fixed_ip")) {
                              if (!body["fixed_ip"].is_string()) {
                                  send_error(res, 400, "bad_request",
                                             "fixed_ip must be a string");
                                  return;
                              }
                              input.fixed_ip =
                                  body["fixed_ip"].get<std::string>();
                          }
                          if (body.contains("enabled")) {
                              if (!body["enabled"].is_boolean()) {
                                  send_error(res, 400, "bad_request",
                                             "enabled must be boolean");
                                  return;
                              }
                              input.enabled = body["enabled"].get<bool>();
                          }
                          if (body.contains("must_change_password")) {
                              if (!body["must_change_password"].is_boolean()) {
                                  send_error(res, 400, "bad_request",
                                             "must_change_password must be boolean");
                                  return;
                              }
                              input.must_change_password =
                                  body["must_change_password"].get<bool>();
                          }

                          const std::string username = req.matches[1].str();
                          auto lease = pool_.acquire();
                          const auto before =
                              service::get_user(lease.db(), username);
                          const auto user = service::update_user(
                              lease.db(), username, input,
                              session->username);

                          if (before && before->enabled &&
                              (!user.enabled ||
                               user.fixed_ip != before->fixed_ip ||
                               user.group_name != before->group_name)) {
                              const auto outcome =
                                  call_policyd(config_, "KICK", username);
                              set_policy_header(res, "X-Policy-Kick", outcome);
                              if (!outcome.ok) {
                                  const auto fallback =
                                      call_policyd(config_, "REFRESH", username);
                                  set_policy_header(res, "X-Policy-Refresh",
                                                    fallback);
                              }
                          }

                          const auto detail =
                              service::get_user_detail(lease.db(), username);
                          send_json(res, 200, detail ? user_detail_json(*detail)
                                                     : user_json(user));
                      });
                  });

    server_.Delete(R"(/api/users/([^/]+))",
                   [this](const httplib::Request& req,
                          httplib::Response& res) {
                       handle(res, [&]() {
                           const auto session =
                               require_session(req, res, sessions_, true);
                           if (!session) {
                               return;
                           }
                           const std::string username = req.matches[1].str();
                           auto lease = pool_.acquire();
                           service::delete_user(lease.db(), username,
                                                session->username);
                           res.status = 204;
                       });
                   });

    server_.Post(R"(/api/users/([^/]+)/password)",
                 [this](const httplib::Request& req,
                        httplib::Response& res) {
                     handle(res, [&]() {
                         const auto session =
                             require_session(req, res, sessions_, true);
                         if (!session) {
                             return;
                         }
                         json body;
                         if (!parse_body(req, res, &body)) {
                             return;
                         }
                         if (!body.contains("password") ||
                             !body["password"].is_string()) {
                             send_error(res, 400, "bad_request",
                                        "password is required");
                             return;
                         }
                         service::PasswordResetInput input;
                         input.password =
                             body["password"].get<std::string>();
                         if (body.contains("must_change_password")) {
                             if (!body["must_change_password"].is_boolean()) {
                                 send_error(res, 400, "bad_request",
                                            "must_change_password must be boolean");
                                 return;
                             }
                             input.must_change_password =
                                 body["must_change_password"].get<bool>();
                         }
                         const std::string username = req.matches[1].str();
                         auto lease = pool_.acquire();
                         service::reset_user_password(
                             lease.db(), username, input, session->username);
                         res.status = 204;
                     });
                 });

    server_.Get(R"(/api/users/([^/]+))",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        const std::string username = req.matches[1].str();
                        auto lease = pool_.acquire();
                        const auto detail =
                            service::get_user_detail(lease.db(), username);
                        if (!detail) {
                            send_error(res, 404, "not_found",
                                       "user not found");
                            return;
                        }
                        send_json(res, 200, user_detail_json(*detail));
                    });
                });

    server_.Get(R"(/api/users/([^/]+)/rules)",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        const std::string username = req.matches[1].str();
                        auto lease = pool_.acquire();
                        json items = json::array();
                        for (const auto& rule :
                             service::list_user_rules(lease.db(), username)) {
                            items.push_back(rule_json(rule));
                        }
                        send_json(res, 200, json{{"items", items}});
                    });
                });

    server_.Post(R"(/api/users/([^/]+)/rules)",
                 [this](const httplib::Request& req,
                        httplib::Response& res) {
                     handle(res, [&]() {
                         const auto session =
                             require_session(req, res, sessions_, true);
                         if (!session) {
                             return;
                         }
                         json body;
                         if (!parse_body(req, res, &body)) {
                             return;
                         }
                         if (!body.contains("rule_type") ||
                             !body["rule_type"].is_string() ||
                             !body.contains("cidr") ||
                             !body["cidr"].is_string()) {
                             send_error(res, 400, "bad_request",
                                        "rule_type and cidr are required");
                             return;
                         }
                         service::UserRuleInput input;
                         input.rule_type =
                             body["rule_type"].get<std::string>();
                         input.cidr = body["cidr"].get<std::string>();
                         if (body.contains("enabled")) {
                             if (!body["enabled"].is_boolean()) {
                                 send_error(res, 400, "bad_request",
                                            "enabled must be boolean");
                                 return;
                             }
                             input.enabled = body["enabled"].get<bool>();
                         }
                         const std::string username = req.matches[1].str();
                         auto lease = pool_.acquire();
                         const auto rule = service::add_user_rule(
                             lease.db(), username, input, session->username);
                         const auto outcome =
                             call_policyd(config_, "REFRESH", username);
                         set_policy_header(res, "X-Policy-Refresh", outcome);
                         send_json(res, 201, rule_json(rule));
                     });
                 });

    server_.Delete(R"(/api/users/([^/]+)/rules/([0-9]+))",
                   [this](const httplib::Request& req,
                          httplib::Response& res) {
                       handle(res, [&]() {
                           const auto session =
                               require_session(req, res, sessions_, true);
                           if (!session) {
                               return;
                           }
                           const std::string username = req.matches[1].str();
                           std::uint32_t rule_id = 0;
                           try {
                               rule_id = static_cast<std::uint32_t>(
                                   std::stoul(req.matches[2].str()));
                           } catch (const std::exception&) {
                               send_error(res, 400, "bad_request",
                                          "invalid rule id");
                               return;
                           }
                           auto lease = pool_.acquire();
                           service::delete_user_rule(
                               lease.db(), username, rule_id,
                               session->username);
                           const auto outcome =
                               call_policyd(config_, "REFRESH", username);
                           set_policy_header(res, "X-Policy-Refresh", outcome);
                           res.status = 204;
                       });
                   });

    server_.Patch(R"(/api/users/([^/]+)/rules/([0-9]+))",
                  [this](const httplib::Request& req,
                         httplib::Response& res) {
                      handle(res, [&]() {
                          const auto session =
                              require_session(req, res, sessions_, true);
                          if (!session) {
                              return;
                          }
                          json body;
                          if (!parse_body(req, res, &body)) {
                              return;
                          }
                          if (!body.contains("enabled") ||
                              !body["enabled"].is_boolean()) {
                              send_error(res, 400, "bad_request",
                                         "enabled is required");
                              return;
                          }
                          const std::string username = req.matches[1].str();
                          std::uint32_t rule_id = 0;
                          try {
                              rule_id = static_cast<std::uint32_t>(
                                  std::stoul(req.matches[2].str()));
                          } catch (const std::exception&) {
                              send_error(res, 400, "bad_request",
                                         "invalid rule id");
                              return;
                          }
                          auto lease = pool_.acquire();
                          const auto rule = service::update_user_rule(
                              lease.db(), username, rule_id,
                              body["enabled"].get<bool>(),
                              session->username);
                          const auto outcome =
                              call_policyd(config_, "REFRESH", username);
                          set_policy_header(res, "X-Policy-Refresh", outcome);
                          send_json(res, 200, rule_json(rule));
                      });
                  });

    server_.Get("/api/groups", [this](const httplib::Request& req,
                                      httplib::Response& res) {
        handle(res, [&]() {
            if (!require_session(req, res, sessions_, false)) {
                return;
            }
            auto lease = pool_.acquire();
            json items = json::array();
            for (const auto& group : service::list_groups(lease.db())) {
                items.push_back(group_json(group));
            }
            send_json(res, 200, json{{"items", items}});
        });
    });

    server_.Post("/api/groups", [this](const httplib::Request& req,
                                       httplib::Response& res) {
        handle(res, [&]() {
            const auto session = require_session(req, res, sessions_, true);
            if (!session) {
                return;
            }
            json body;
            if (!parse_body(req, res, &body)) {
                return;
            }
            if (!body.contains("name") || !body["name"].is_string() ||
                !body.contains("ip_start") || !body["ip_start"].is_string() ||
                !body.contains("ip_end") || !body["ip_end"].is_string()) {
                send_error(res, 400, "bad_request",
                           "name, ip_start and ip_end are required");
                return;
            }
            service::CreateGroupInput input;
            input.name = body["name"].get<std::string>();
            input.ip_start = body["ip_start"].get<std::string>();
            input.ip_end = body["ip_end"].get<std::string>();
            if (body.contains("description")) {
                if (!body["description"].is_string()) {
                    send_error(res, 400, "bad_request",
                               "description must be a string");
                    return;
                }
                input.description = body["description"].get<std::string>();
            }
            auto lease = pool_.acquire();
            const auto group =
                service::create_group(lease.db(), input, session->username);
            send_json(res, 201, group_json(group));
        });
    });

    server_.Patch(R"(/api/groups/([0-9]+))",
                  [this](const httplib::Request& req,
                         httplib::Response& res) {
                      handle(res, [&]() {
                          const auto session =
                              require_session(req, res, sessions_, true);
                          if (!session) {
                              return;
                          }
                          std::uint32_t group_id = 0;
                          try {
                              group_id = static_cast<std::uint32_t>(
                                  std::stoul(req.matches[1].str()));
                          } catch (const std::exception&) {
                              send_error(res, 400, "bad_request",
                                         "invalid group id");
                              return;
                          }
                          json body;
                          if (!parse_body(req, res, &body)) {
                              return;
                          }
                          service::UpdateGroupInput input;
                          if (body.contains("name")) {
                              if (!body["name"].is_string()) {
                                  send_error(res, 400, "bad_request",
                                             "name must be a string");
                                  return;
                              }
                              input.name = body["name"].get<std::string>();
                          }
                          if (body.contains("ip_start")) {
                              if (!body["ip_start"].is_string()) {
                                  send_error(res, 400, "bad_request",
                                             "ip_start must be a string");
                                  return;
                              }
                              input.ip_start =
                                  body["ip_start"].get<std::string>();
                          }
                          if (body.contains("ip_end")) {
                              if (!body["ip_end"].is_string()) {
                                  send_error(res, 400, "bad_request",
                                             "ip_end must be a string");
                                  return;
                              }
                              input.ip_end =
                                  body["ip_end"].get<std::string>();
                          }
                          if (body.contains("description")) {
                              if (!body["description"].is_string()) {
                                  send_error(res, 400, "bad_request",
                                             "description must be a string");
                                  return;
                              }
                              input.description =
                                  body["description"].get<std::string>();
                          }
                          auto lease = pool_.acquire();
                          const auto updated = service::update_group(
                              lease.db(), group_id, input, session->username);
                          const auto outcome =
                              call_policyd(config_, "REFRESH", "");
                          set_policy_header(res, "X-Policy-Refresh", outcome);
                          send_json(res, 200, group_json(updated));
                      });
                  });

    server_.Delete(R"(/api/groups/([0-9]+))",
                   [this](const httplib::Request& req,
                          httplib::Response& res) {
                       handle(res, [&]() {
                           const auto session =
                               require_session(req, res, sessions_, true);
                           if (!session) {
                               return;
                           }
                           std::uint32_t group_id = 0;
                           try {
                               group_id = static_cast<std::uint32_t>(
                                   std::stoul(req.matches[1].str()));
                           } catch (const std::exception&) {
                               send_error(res, 400, "bad_request",
                                          "invalid group id");
                               return;
                           }
                           auto lease = pool_.acquire();
                           service::delete_group(lease.db(), group_id,
                                                 session->username);
                           res.status = 204;
                       });
                   });

    server_.Get(R"(/api/groups/([0-9]+))",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        std::uint32_t group_id = 0;
                        try {
                            group_id = static_cast<std::uint32_t>(
                                std::stoul(req.matches[1].str()));
                        } catch (const std::exception&) {
                            send_error(res, 400, "bad_request",
                                       "invalid group id");
                            return;
                        }
                        auto lease = pool_.acquire();
                        const auto detail =
                            service::get_group_detail(lease.db(), group_id);
                        if (!detail) {
                            send_error(res, 404, "not_found",
                                       "group not found");
                            return;
                        }
                        send_json(res, 200, group_detail_json(*detail));
                    });
                });

    server_.Get(R"(/api/groups/([0-9]+)/rules)",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        std::uint32_t group_id = 0;
                        try {
                            group_id = static_cast<std::uint32_t>(
                                std::stoul(req.matches[1].str()));
                        } catch (const std::exception&) {
                            send_error(res, 400, "bad_request",
                                       "invalid group id");
                            return;
                        }
                        auto lease = pool_.acquire();
                        json items = json::array();
                        for (const auto& rule :
                             service::list_group_rules(lease.db(), group_id)) {
                            items.push_back(group_rule_json(rule));
                        }
                        send_json(res, 200, json{{"items", items}});
                    });
                });

    server_.Post(R"(/api/groups/([0-9]+)/rules)",
                 [this](const httplib::Request& req,
                        httplib::Response& res) {
                     handle(res, [&]() {
                         const auto session =
                             require_session(req, res, sessions_, true);
                         if (!session) {
                             return;
                         }
                         std::uint32_t group_id = 0;
                         try {
                             group_id = static_cast<std::uint32_t>(
                                 std::stoul(req.matches[1].str()));
                         } catch (const std::exception&) {
                             send_error(res, 400, "bad_request",
                                        "invalid group id");
                             return;
                         }
                         json body;
                         if (!parse_body(req, res, &body)) {
                             return;
                         }
                         if (!body.contains("rule_type") ||
                             !body["rule_type"].is_string() ||
                             !body.contains("cidr") ||
                             !body["cidr"].is_string()) {
                             send_error(res, 400, "bad_request",
                                        "rule_type and cidr are required");
                             return;
                         }
                         service::GroupRuleInput input;
                         input.rule_type =
                             body["rule_type"].get<std::string>();
                         input.cidr = body["cidr"].get<std::string>();
                         if (body.contains("enabled")) {
                             if (!body["enabled"].is_boolean()) {
                                 send_error(res, 400, "bad_request",
                                            "enabled must be boolean");
                                 return;
                             }
                             input.enabled = body["enabled"].get<bool>();
                         }
                         auto lease = pool_.acquire();
                         const auto rule = service::add_group_rule(
                             lease.db(), group_id, input, session->username);
                         const auto outcome =
                             call_policyd(config_, "REFRESH", "");
                         set_policy_header(res, "X-Policy-Refresh", outcome);
                         send_json(res, 201, group_rule_json(rule));
                     });
                 });

    server_.Delete(R"(/api/groups/([0-9]+)/rules/([0-9]+))",
                   [this](const httplib::Request& req,
                          httplib::Response& res) {
                       handle(res, [&]() {
                           const auto session =
                               require_session(req, res, sessions_, true);
                           if (!session) {
                               return;
                           }
                           std::uint32_t group_id = 0;
                           std::uint32_t rule_id = 0;
                           try {
                               group_id = static_cast<std::uint32_t>(
                                   std::stoul(req.matches[1].str()));
                               rule_id = static_cast<std::uint32_t>(
                                   std::stoul(req.matches[2].str()));
                           } catch (const std::exception&) {
                               send_error(res, 400, "bad_request",
                                          "invalid group or rule id");
                               return;
                           }
                           auto lease = pool_.acquire();
                           service::delete_group_rule(lease.db(), group_id,
                                                      rule_id,
                                                      session->username);
                           const auto outcome =
                               call_policyd(config_, "REFRESH", "");
                           set_policy_header(res, "X-Policy-Refresh", outcome);
                           res.status = 204;
                       });
                   });

    server_.Patch(R"(/api/groups/([0-9]+)/rules/([0-9]+))",
                  [this](const httplib::Request& req,
                         httplib::Response& res) {
                      handle(res, [&]() {
                          const auto session =
                              require_session(req, res, sessions_, true);
                          if (!session) {
                              return;
                          }
                          json body;
                          if (!parse_body(req, res, &body)) {
                              return;
                          }
                          if (!body.contains("enabled") ||
                              !body["enabled"].is_boolean()) {
                              send_error(res, 400, "bad_request",
                                         "enabled is required");
                              return;
                          }
                          std::uint32_t group_id = 0;
                          std::uint32_t rule_id = 0;
                          try {
                              group_id = static_cast<std::uint32_t>(
                                  std::stoul(req.matches[1].str()));
                              rule_id = static_cast<std::uint32_t>(
                                  std::stoul(req.matches[2].str()));
                          } catch (const std::exception&) {
                              send_error(res, 400, "bad_request",
                                         "invalid group or rule id");
                              return;
                          }
                          auto lease = pool_.acquire();
                          const auto rule = service::update_group_rule(
                              lease.db(), group_id, rule_id,
                              body["enabled"].get<bool>(),
                              session->username);
                          const auto outcome =
                              call_policyd(config_, "REFRESH", "");
                          set_policy_header(res, "X-Policy-Refresh", outcome);
                          send_json(res, 200, group_rule_json(rule));
                      });
                  });

    server_.Get("/api/services", [this](const httplib::Request& req,
                                        httplib::Response& res) {
        handle(res, [&]() {
            if (!require_session(req, res, sessions_, false)) {
                return;
            }
            const std::string scope_type =
                req.has_param("scope_type") ? req.get_param_value("scope_type")
                                            : "";
            const std::string scope_id =
                req.has_param("scope_id") ? req.get_param_value("scope_id")
                                          : "";
            auto lease = pool_.acquire();
            json items = json::array();
            for (const auto& row :
                 service::list_services(lease.db(), scope_type, scope_id)) {
                items.push_back(service_row_json(row));
            }
            send_json(res, 200, json{{"items", items}});
        });
    });

    server_.Post("/api/services", [this](const httplib::Request& req,
                                         httplib::Response& res) {
        handle(res, [&]() {
            const auto session = require_session(req, res, sessions_, true);
            if (!session) {
                return;
            }
            json body;
            if (!parse_body(req, res, &body)) {
                return;
            }
            if (!body.contains("scope_type") ||
                !body["scope_type"].is_string() ||
                !body.contains("service") ||
                !body["service"].is_string()) {
                send_error(res, 400, "bad_request",
                           "scope_type and service are required");
                return;
            }
            service::CreateServiceInput input;
            input.scope_type = body["scope_type"].get<std::string>();
            input.service = body["service"].get<std::string>();
            if (body.contains("scope_id")) {
                if (!body["scope_id"].is_string()) {
                    send_error(res, 400, "bad_request",
                               "scope_id must be a string");
                    return;
                }
                input.scope_id = body["scope_id"].get<std::string>();
            }
            if (body.contains("enabled")) {
                if (!body["enabled"].is_boolean()) {
                    send_error(res, 400, "bad_request",
                               "enabled must be boolean");
                    return;
                }
                input.enabled = body["enabled"].get<bool>();
            }
            auto lease = pool_.acquire();
            const auto row =
                service::add_service(lease.db(), input, session->username);
            const auto outcome = call_policyd(config_, "REFRESH", "");
            set_policy_header(res, "X-Policy-Refresh", outcome);
            send_json(res, 201, service_row_json(row));
        });
    });

    server_.Delete(R"(/api/services/([0-9]+))",
                   [this](const httplib::Request& req,
                          httplib::Response& res) {
                       handle(res, [&]() {
                           const auto session =
                               require_session(req, res, sessions_, true);
                           if (!session) {
                               return;
                           }
                           std::uint32_t service_id = 0;
                           try {
                               service_id = static_cast<std::uint32_t>(
                                   std::stoul(req.matches[1].str()));
                           } catch (const std::exception&) {
                               send_error(res, 400, "bad_request",
                                          "invalid service id");
                               return;
                           }
                           auto lease = pool_.acquire();
                           service::delete_service(lease.db(), service_id,
                                                   session->username);
                           const auto outcome =
                               call_policyd(config_, "REFRESH", "");
                           set_policy_header(res, "X-Policy-Refresh", outcome);
                           res.status = 204;
                       });
                   });

    server_.Patch(R"(/api/services/([0-9]+))",
                  [this](const httplib::Request& req,
                         httplib::Response& res) {
                      handle(res, [&]() {
                          const auto session =
                              require_session(req, res, sessions_, true);
                          if (!session) {
                              return;
                          }
                          json body;
                          if (!parse_body(req, res, &body)) {
                              return;
                          }
                          std::optional<bool> enabled;
                          std::optional<std::string> service;
                          if (body.contains("enabled")) {
                              if (!body["enabled"].is_boolean()) {
                                  send_error(res, 400, "bad_request",
                                             "enabled must be boolean");
                                  return;
                              }
                              enabled = body["enabled"].get<bool>();
                          }
                          if (body.contains("service")) {
                              if (!body["service"].is_string()) {
                                  send_error(res, 400, "bad_request",
                                             "service must be a string");
                                  return;
                              }
                              service = body["service"].get<std::string>();
                          }
                          std::uint32_t service_id = 0;
                          try {
                              service_id = static_cast<std::uint32_t>(
                                  std::stoul(req.matches[1].str()));
                          } catch (const std::exception&) {
                              send_error(res, 400, "bad_request",
                                         "invalid service id");
                              return;
                          }
                          auto lease = pool_.acquire();
                          const auto row = service::update_service(
                              lease.db(), service_id, enabled, service,
                              session->username);
                          const auto outcome =
                              call_policyd(config_, "REFRESH", "");
                          set_policy_header(res, "X-Policy-Refresh", outcome);
                          send_json(res, 200, service_row_json(row));
                      });
                  });

    server_.Get("/api/settings", [this](const httplib::Request& req,
                                        httplib::Response& res) {
        handle(res, [&]() {
            if (!require_session(req, res, sessions_, false)) {
                return;
            }
            auto lease = pool_.acquire();
            send_json(res, 200,
                      settings_json(service::load_settings(lease.db())));
        });
    });

    server_.Patch("/api/settings", [this](const httplib::Request& req,
                                          httplib::Response& res) {
        handle(res, [&]() {
            const auto session = require_session(req, res, sessions_, true);
            if (!session) {
                return;
            }
            json body;
            if (!parse_body(req, res, &body)) {
                return;
            }
            service::UpdateSettingsInput input;
            auto read_string = [&](const char* key,
                                   std::optional<std::string>* target) -> bool {
                if (!body.contains(key)) {
                    return true;
                }
                if (!body[key].is_string()) {
                    send_error(res, 400, "bad_request",
                               std::string(key) + " must be a string");
                    return false;
                }
                *target = body[key].get<std::string>();
                return true;
            };
            if (!read_string("allowed_target_networks",
                             &input.allowed_target_networks) ||
                !read_string("allowed_service_ips",
                             &input.allowed_service_ips) ||
                !read_string("tunnel_network", &input.tunnel_network) ||
                !read_string("max_rules_per_user",
                             &input.max_rules_per_user) ||
                !read_string("max_services_per_user",
                             &input.max_services_per_user)) {
                return;
            }
            auto lease = pool_.acquire();
            const auto settings = service::update_settings(
                lease.db(), input, session->username);
            const auto outcome = call_policyd(config_, "REFRESH", "");
            set_policy_header(res, "X-Policy-Refresh", outcome);
            send_json(res, 200, settings_json(settings));
        });
    });

    server_.Get("/api/sessions", [this](const httplib::Request& req,
                                        httplib::Response& res) {
        handle(res, [&]() {
            if (!require_session(req, res, sessions_, false)) {
                return;
            }
            auto lease = pool_.acquire();
            const auto status =
                service::parse_openvpn_status(config_.status_file);
            json items = json::array();
            for (const auto& session :
                 service::list_sessions(lease.db(), status)) {
                items.push_back(session_json(session));
            }
            send_json(res, 200, json{{"items", items}});
        });
    });

    server_.Post(R"(/api/sessions/([^/]+)/kick)",
                 [this](const httplib::Request& req,
                        httplib::Response& res) {
                     handle(res, [&]() {
                         const auto session =
                             require_session(req, res, sessions_, true);
                         if (!session) {
                             return;
                         }
                         const std::string username = req.matches[1].str();
                         const auto outcome =
                             call_policyd(config_, "KICK", username);
                         set_policy_header(res, "X-Policy-Kick", outcome);
                         if (!outcome.ok) {
                             send_error(res, 503, "unavailable",
                                        outcome.error);
                             return;
                         }
                         send_json(res, 200, json{{"kicked", true}});
                     });
                 });

    server_.Get("/api/sessions/history",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        const auto query = parse_history_query(req, true);
                        auto lease = pool_.acquire();
                        const auto result =
                            service::query_session_history(lease.db(), query);
                        json items = json::array();
                        for (const auto& session : result.items) {
                            items.push_back(history_session_json(session));
                        }
                        send_json(res, 200,
                                  json{{"items", items},
                                       {"total", result.total},
                                       {"page", result.page},
                                       {"page_size", result.page_size}});
                    });
                });

    server_.Get("/api/sessions/history/stats",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        const auto query = parse_history_query(req, true);
                        auto lease = pool_.acquire();
                        send_json(res, 200,
                                  history_stats_json(
                                      service::query_session_history_stats(
                                          lease.db(), query)));
                    });
                });

    server_.Get("/api/sessions/history/export",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        const auto query = parse_history_query(req, true);
                        auto lease = pool_.acquire();
                        const auto rows = service::export_session_history(
                            lease.db(), query, 10000);
                        send_csv(res, session_csv(rows), "vpn-sessions.csv");
                    });
                });

    server_.Get("/api/auth-failures",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        const auto query = parse_history_query(req, true);
                        auto lease = pool_.acquire();
                        const auto result =
                            service::query_auth_failures(lease.db(), query);
                        json items = json::array();
                        for (const auto& failure : result.items) {
                            items.push_back(auth_failure_json(failure));
                        }
                        send_json(res, 200,
                                  json{{"items", items},
                                       {"total", result.total},
                                       {"page", result.page},
                                       {"page_size", result.page_size}});
                    });
                });

    server_.Get("/api/auth-failures/export",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        const auto query = parse_history_query(req, true);
                        auto lease = pool_.acquire();
                        const auto rows = service::export_auth_failures(
                            lease.db(), query, 10000);
                        send_csv(res, auth_csv(rows),
                                 "vpn-auth-failures.csv");
                    });
                });

    server_.Get("/api/audit", [this](const httplib::Request& req,
                                     httplib::Response& res) {
        handle(res, [&]() {
            if (!require_session(req, res, sessions_, false)) {
                return;
            }
            const unsigned int limit = query_u32(req, "limit", 100, 1, 500);
            const unsigned int offset =
                query_u32(req, "offset", 0, 0, 1000000000);
            auto lease = pool_.acquire();
            json items = json::array();
            for (const auto& entry :
                 service::list_audit(lease.db(), limit, offset)) {
                items.push_back(audit_json(entry));
            }
            send_json(res, 200, json{{"items", items}});
        });
    });

    server_.Get("/api/metrics", [this](const httplib::Request& req,
                                       httplib::Response& res) {
        handle(res, [&]() {
            if (!require_session(req, res, sessions_, false)) {
                return;
            }
            send_json(res, 200, metrics_.json());
        });
    });

    server_.Get("/api/metrics/history",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        const std::string range =
                            req.has_param("range")
                                ? req.get_param_value("range")
                                : "24h";
                        const std::string step =
                            req.has_param("step")
                                ? req.get_param_value("step")
                                : "";
                        auto lease = pool_.acquire();
                        const auto history = service::load_metrics_history(
                            lease.db(), range, step);
                        json auth = json::array();
                        for (const auto& point : history.auth) {
                            auth.push_back(
                                {{"bucket", point.bucket},
                                 {"accept", point.accept},
                                 {"reject", point.reject}});
                        }
                        json sessions = json::array();
                        for (const auto& point : history.sessions) {
                            sessions.push_back(
                                {{"bucket", point.bucket},
                                 {"started", point.started},
                                 {"stopped", point.stopped},
                                 {"session_time", point.session_time},
                                 {"bytes_in", point.bytes_in},
                                 {"bytes_out", point.bytes_out}});
                        }
                        send_json(res, 200,
                                  json{{"range", range},
                                       {"step", step},
                                       {"auth", auth},
                                       {"sessions", sessions}});
                    });
                });

    server_.Get("/api/metrics/top-users",
                [this](const httplib::Request& req,
                       httplib::Response& res) {
                    handle(res, [&]() {
                        if (!require_session(req, res, sessions_, false)) {
                            return;
                        }
                        const std::string range =
                            req.has_param("range")
                                ? req.get_param_value("range")
                                : "24h";
                        const unsigned int limit =
                            query_u32(req, "limit", 10, 1, 100);
                        const bool include_deleted =
                            req.has_param("include_deleted") &&
                            req.get_param_value("include_deleted") == "1";
                        auto lease = pool_.acquire();
                        json items = json::array();
                        for (const auto& user : service::load_top_users(
                                 lease.db(), range, limit,
                                 include_deleted)) {
                            items.push_back(
                                {{"username", user.username},
                                 {"sessions", user.sessions},
                                 {"bytes_in", user.bytes_in},
                                 {"bytes_out", user.bytes_out},
                                 {"session_time", user.session_time},
                                 {"user_exists", user.user_exists}});
                        }
                        send_json(res, 200, json{{"items", items}});
                    });
                });

    server_.Get("/healthz", [](const httplib::Request&,
                              httplib::Response& res) {
        send_json(res, 200, json{{"status", "ok"}});
    });

    server_.Get("/readyz", [this](const httplib::Request&,
                                  httplib::Response& res) {
        handle(res, [&]() {
            const bool database_up = db_alive(pool_);
            const bool status_ok =
                ::access(config_.status_file.c_str(), R_OK) == 0;
            std::string policyd_response;
            std::string policyd_error;
            const bool policyd_up = ipc_request(
                config_.policyd_socket, "PING", {}, &policyd_response,
                &policyd_error, 1);
            send_json(res,
                      database_up && status_ok && policyd_up ? 200 : 503,
                      json{{"database", database_up},
                           {"status_file", status_ok},
                           {"policyd", policyd_up}});
        });
    });

    server_.Get("/metrics", [this](const httplib::Request&,
                                   httplib::Response& res) {
        handle(res, [&]() {
            res.set_header("Cache-Control", "no-store");
            res.set_content(metrics_.prometheus() + admin_metrics(),
                            "text/plain; version=0.0.4; charset=utf-8");
        });
    });
}

} // namespace vpn::admin