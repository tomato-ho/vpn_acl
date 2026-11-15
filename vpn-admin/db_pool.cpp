#include "db_pool.h"

#include <algorithm>
#include <utility>

namespace vpn::admin {

DbPool::DbPool(const DbConfig& config, std::size_t size)
    : size_(std::max<std::size_t>(1, size)) {
    available_.reserve(size_);
    for (std::size_t i = 0; i < size_; ++i) {
        available_.push_back(std::make_unique<Db>(config));
    }
}

DbPool::Lease DbPool::acquire(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!condition_.wait_for(lock, timeout,
                             [this]() { return !available_.empty(); })) {
        throw service::ServiceError(
            service::ErrorCode::unavailable,
            "database connection pool timeout");
    }
    std::unique_ptr<Db> db = std::move(available_.back());
    available_.pop_back();
    return Lease(this, std::move(db));
}

void DbPool::release(std::unique_ptr<Db> db) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        available_.push_back(std::move(db));
    }
    condition_.notify_one();
}

DbPool::Lease::Lease(DbPool* pool, std::unique_ptr<Db> db)
    : pool_(pool), db_(std::move(db)) {}

DbPool::Lease::Lease(Lease&& other) noexcept
    : pool_(other.pool_), db_(std::move(other.db_)) {
    other.pool_ = nullptr;
}

DbPool::Lease::~Lease() {
    if (pool_ && db_) {
        pool_->release(std::move(db_));
    }
}

} // namespace vpn::admin