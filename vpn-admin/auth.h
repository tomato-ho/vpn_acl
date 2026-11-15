#pragma once

#include <cstddef>
#include <ctime>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace vpn::admin {

struct Session {
    std::string username;
    std::string csrf;
    std::time_t expires_at{0};
};

struct CreatedSession {
    std::string token;
    Session session;
};

class SessionStore {
public:
    explicit SessionStore(unsigned int ttl_seconds);

    CreatedSession create(const std::string& username);
    std::optional<Session> find(const std::string& token);
    void erase(const std::string& token);
    void erase_user(const std::string& username);

private:
    void cleanup_locked(std::time_t now);

    std::mutex mutex_;
    std::unordered_map<std::string, Session> sessions_;
    unsigned int ttl_seconds_;
};

class LoginLimiter {
public:
    bool locked(const std::string& key);
    void failure(const std::string& key);
    void success(const std::string& key);

private:
    struct Entry {
        int failures{0};
        std::time_t window_start{0};
        std::time_t locked_until{0};
    };

    void prune_locked(std::time_t now);

    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
};

std::string random_token(std::size_t bytes);

} // namespace vpn::admin