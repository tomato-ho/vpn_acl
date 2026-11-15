#include "vpn/db.h"

#include <errmsg.h>

#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace vpn {
namespace {

constexpr int kMaxAttempts = 2;
// 连接阶段的重试：容器 DNS / 数据库刚启动时抖动，短退避重试几次，
// 避免一次解析失败就把 503 直接抛给前端。
constexpr int kConnectAttempts = 3;

bool is_disconnect_error(unsigned int code) {
    if (code == CR_SERVER_GONE_ERROR || code == CR_SERVER_LOST ||
        code == CR_CONN_HOST_ERROR || code == CR_CONNECTION_ERROR ||
        code == CR_SERVER_HANDSHAKE_ERR) {
        return true;
    }
#ifdef CR_SERVER_LOST_EXTENDED
    if (code == CR_SERVER_LOST_EXTENDED) {
        return true;
    }
#endif
    return false;
}

[[noreturn]] void fail(MYSQL* connection, const std::string& message) {
    std::string detail = message;
    bool connection_error = false;
    if (connection) {
        detail += ": ";
        detail += mysql_error(connection);
        connection_error = is_disconnect_error(mysql_errno(connection));
    }
    throw DbError(detail, connection_error);
}

} // namespace

Db::Db(const DbConfig& config) : config_(config) {}

Db::~Db() {
    if (conn_) {
        mysql_close(conn_);
    }
}

void Db::drop_connection() {
    if (conn_) {
        mysql_close(conn_);
        conn_ = nullptr;
    }
}

void Db::ensure_connected() {
    if (!conn_) {
        if (in_transaction_) {
            throw DbError("database connection lost during transaction", true);
        }
        connect();
        return;
    }
    if (mysql_ping(conn_) == 0) {
        return;
    }
    if (in_transaction_) {
        drop_connection();
        throw DbError("database connection lost during transaction", true);
    }
    drop_connection();
    connect();
}

void Db::connect() {
    if (in_transaction_) {
        throw DbError("cannot reconnect during transaction", true);
    }

    std::string last_error = "unknown error";
    unsigned int last_code = CR_CONNECTION_ERROR;
    for (int attempt = 1; attempt <= kConnectAttempts; ++attempt) {
        drop_connection();
        conn_ = mysql_init(nullptr);
        if (!conn_) {
            throw DbError("mysql_init failed", true);
        }

        unsigned int connect_timeout = 5;
        unsigned int io_timeout = 10;
        mysql_options(conn_, MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout);
        mysql_options(conn_, MYSQL_OPT_READ_TIMEOUT, &io_timeout);
        mysql_options(conn_, MYSQL_OPT_WRITE_TIMEOUT, &io_timeout);

        if (mysql_real_connect(conn_,
                               config_.host.c_str(),
                               config_.user.c_str(),
                               config_.password.c_str(),
                               config_.name.c_str(),
                               config_.port,
                               nullptr,
                               0)) {
            if (mysql_set_character_set(conn_, "utf8mb4") != 0) {
                fail(conn_, "mysql_set_character_set failed");
            }
            return;
        }

        last_error = mysql_error(conn_);
        last_code = mysql_errno(conn_);
        mysql_close(conn_);
        conn_ = nullptr;

        if (!is_disconnect_error(last_code) || attempt == kConnectAttempts) {
            break;
        }
        std::this_thread::sleep_for(
            std::chrono::milliseconds(200 * attempt));
    }

    throw DbError("mysql connect failed: " + last_error,
                  is_disconnect_error(last_code));
}

std::vector<std::vector<std::string>> Db::query(const std::string& sql) {
    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        ensure_connected();
        if (mysql_query(conn_, sql.c_str()) != 0) {
            const unsigned int code = mysql_errno(conn_);
            if (!in_transaction_ && attempt + 1 < kMaxAttempts &&
                is_disconnect_error(code)) {
                drop_connection();
                continue;
            }
            fail(conn_, "query failed");
        }

        MYSQL_RES* result = mysql_store_result(conn_);
        if (!result) {
            if (mysql_field_count(conn_) != 0) {
                const unsigned int code = mysql_errno(conn_);
                if (!in_transaction_ && attempt + 1 < kMaxAttempts &&
                    is_disconnect_error(code)) {
                    drop_connection();
                    continue;
                }
                fail(conn_, "mysql_store_result failed");
            }
            return {};
        }

        std::vector<std::vector<std::string>> rows;
        const unsigned int columns = mysql_num_fields(result);
        while (MYSQL_ROW row = mysql_fetch_row(result)) {
            const unsigned long* lengths = mysql_fetch_lengths(result);
            std::vector<std::string> values;
            values.reserve(columns);
            for (unsigned int i = 0; i < columns; ++i) {
                if (row[i]) {
                    values.emplace_back(row[i], lengths[i]);
                } else {
                    values.emplace_back();
                }
            }
            rows.push_back(std::move(values));
        }
        mysql_free_result(result);
        return rows;
    }
    throw DbError("query failed: database unavailable", true);
}

void Db::execute(const std::string& sql) {
    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        ensure_connected();
        if (mysql_query(conn_, sql.c_str()) != 0) {
            const unsigned int code = mysql_errno(conn_);
            if (!in_transaction_ && attempt + 1 < kMaxAttempts &&
                is_disconnect_error(code)) {
                drop_connection();
                continue;
            }
            fail(conn_, "execute failed");
        }
        if (MYSQL_RES* result = mysql_store_result(conn_)) {
            mysql_free_result(result);
        } else if (mysql_field_count(conn_) != 0) {
            const unsigned int code = mysql_errno(conn_);
            if (!in_transaction_ && attempt + 1 < kMaxAttempts &&
                is_disconnect_error(code)) {
                drop_connection();
                continue;
            }
            fail(conn_, "mysql_store_result failed");
        }
        return;
    }
    throw DbError("execute failed: database unavailable", true);
}

std::uint64_t Db::last_insert_id() {
    // 同 affected_rows：不能先 ping，否则会覆盖上一条 INSERT 的结果。
    if (!conn_) {
        return 0;
    }
    return static_cast<std::uint64_t>(mysql_insert_id(conn_));
}

std::uint64_t Db::affected_rows() {
    // 不能在这里先 mysql_ping：ping 会覆盖"上一条语句"的结果，
    // 使 mysql_affected_rows 返回 (my_ulonglong)-1，转成 uint64 后变成
    // 一个巨大的值（曾导致 retention 的 DELETE 循环永不退出）。
    if (!conn_) {
        return 0;
    }
    const my_ulonglong affected = mysql_affected_rows(conn_);
    if (affected == static_cast<my_ulonglong>(-1)) {
        return 0;
    }
    return static_cast<std::uint64_t>(affected);
}

std::string Db::quote(const std::string& value) {
    ensure_connected();
    std::vector<char> buffer(value.size() * 2 + 1);
    const unsigned long length = mysql_real_escape_string(
        conn_, buffer.data(), value.data(), static_cast<unsigned long>(value.size()));
    return std::string(buffer.data(), length);
}

void Db::begin() {
    if (in_transaction_) {
        throw std::runtime_error("transaction already active");
    }
    execute("START TRANSACTION");
    in_transaction_ = true;
}

void Db::commit() {
    if (!in_transaction_) {
        throw std::runtime_error("no active transaction");
    }
    try {
        execute("COMMIT");
    } catch (...) {
        in_transaction_ = false;
        throw;
    }
    in_transaction_ = false;
}

void Db::rollback() {
    if (!in_transaction_) {
        return;
    }
    try {
        execute("ROLLBACK");
    } catch (...) {
        in_transaction_ = false;
        throw;
    }
    in_transaction_ = false;
}

} // namespace vpn