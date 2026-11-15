#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <mysql.h>

namespace vpn {

class DbError : public std::runtime_error {
public:
    DbError(const std::string& message, bool connection_error)
        : std::runtime_error(message), connection_error_(connection_error) {}

    bool connection_error() const noexcept { return connection_error_; }

private:
    bool connection_error_;
};

struct DbConfig {
    std::string host{"127.0.0.1"};
    unsigned int port{3306};
    std::string name{"radius"};
    std::string user{"radius"};
    std::string password;
};

class Db {
public:
    explicit Db(const DbConfig& config);
    ~Db();

    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;

    void connect();
    std::vector<std::vector<std::string>> query(const std::string& sql);
    void execute(const std::string& sql);
    std::uint64_t last_insert_id();
    std::uint64_t affected_rows();
    std::string quote(const std::string& value);

    void begin();
    void commit();
    void rollback();

    bool in_transaction() const { return in_transaction_; }

private:
    void ensure_connected();
    void drop_connection();

    MYSQL* conn_{nullptr};
    DbConfig config_;
    bool in_transaction_{false};
};

} // namespace vpn