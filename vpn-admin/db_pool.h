#pragma once

#include "vpn/db.h"
#include "vpn/service/errors.h"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <vector>

namespace vpn::admin {

class DbPool {
public:
    class Lease {
    public:
        Lease(DbPool* pool, std::unique_ptr<Db> db);
        ~Lease();

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept;
        Lease& operator=(Lease&& other) = delete;

        Db& db() { return *db_; }

    private:
        DbPool* pool_{nullptr};
        std::unique_ptr<Db> db_;
    };

    DbPool(const DbConfig& config, std::size_t size);

    Lease acquire(
        std::chrono::milliseconds timeout = std::chrono::seconds(5));

private:
    friend class Lease;

    void release(std::unique_ptr<Db> db);

    std::mutex mutex_;
    std::condition_variable condition_;
    std::vector<std::unique_ptr<Db>> available_;
    std::size_t size_{1};
};

} // namespace vpn::admin