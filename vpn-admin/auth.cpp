#include "auth.h"

#include <openssl/rand.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

namespace vpn::admin {
namespace {

constexpr int kFailureWindowSeconds = 300;
constexpr int kMaxFailures = 5;
constexpr int kLockSeconds = 300;

} // namespace

std::string random_token(std::size_t bytes) {
    std::vector<unsigned char> buffer(bytes);
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    static const char* hex = "0123456789abcdef";
    std::string output;
    output.reserve(buffer.size() * 2);
    for (const unsigned char value : buffer) {
        output.push_back(hex[value >> 4]);
        output.push_back(hex[value & 0x0f]);
    }
    return output;
}

SessionStore::SessionStore(unsigned int ttl_seconds)
    : ttl_seconds_(std::max<unsigned int>(60, ttl_seconds)) {}

CreatedSession SessionStore::create(const std::string& username) {
    CreatedSession created;
    created.token = random_token(32);
    created.session.username = username;
    created.session.csrf = random_token(24);
    created.session.expires_at = std::time(nullptr) + ttl_seconds_;

    std::lock_guard<std::mutex> lock(mutex_);
    cleanup_locked(std::time(nullptr));
    sessions_[created.token] = created.session;
    return created;
}

std::optional<Session> SessionStore::find(const std::string& token) {
    if (token.empty()) {
        return std::nullopt;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = sessions_.find(token);
    if (found == sessions_.end()) {
        return std::nullopt;
    }
    const std::time_t now = std::time(nullptr);
    if (found->second.expires_at <= now) {
        sessions_.erase(found);
        return std::nullopt;
    }
    return found->second;
}

void SessionStore::erase(const std::string& token) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.erase(token);
}

void SessionStore::erase_user(const std::string& username) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->second.username == username) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

void SessionStore::cleanup_locked(std::time_t now) {
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->second.expires_at <= now) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

bool LoginLimiter::locked(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::time_t now = std::time(nullptr);
    prune_locked(now);
    const auto found = entries_.find(key);
    if (found == entries_.end()) {
        return false;
    }
    return found->second.locked_until > now;
}

void LoginLimiter::failure(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::time_t now = std::time(nullptr);
    prune_locked(now);

    Entry& entry = entries_[key];
    if (entry.locked_until > now) {
        return;
    }
    if (entry.window_start == 0 ||
        now - entry.window_start > kFailureWindowSeconds) {
        entry.failures = 0;
        entry.window_start = now;
    }
    ++entry.failures;
    if (entry.failures >= kMaxFailures) {
        entry.locked_until = now + kLockSeconds;
    }
}

void LoginLimiter::success(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(key);
}

void LoginLimiter::prune_locked(std::time_t now) {
    if (entries_.size() < 10000) {
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (it->second.locked_until <= now &&
                now - it->second.window_start > kFailureWindowSeconds) {
                it = entries_.erase(it);
            } else {
                ++it;
            }
        }
        return;
    }

    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->second.locked_until <= now) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace vpn::admin