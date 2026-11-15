#include "accounting_worker.h"
#include "logging.h"

#include <exception>
#include <string>
#include <utility>

namespace vpn {

AccountingWorker::AccountingWorker(RadiusServerConfig config,
                                   std::size_t max_queue)
    : accounting_(std::make_unique<RadiusAccounting>(std::move(config))),
      max_queue_(max_queue == 0 ? 1 : max_queue) {}

AccountingWorker::~AccountingWorker() {
    stop();
}

void AccountingWorker::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (thread_.joinable()) {
        return;
    }
    stopping_ = false;
    thread_ = std::thread(&AccountingWorker::run, this);
}

void AccountingWorker::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!thread_.joinable()) {
            return;
        }
        stopping_ = true;
    }
    condition_.notify_all();
    thread_.join();
}

bool AccountingWorker::enqueue(AcctStatus status, const AcctRecord& record) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_ || queue_.size() >= max_queue_) {
            return false;
        }
        queue_.push_back(Job{status, record});
    }
    condition_.notify_one();
    return true;
}

void AccountingWorker::run() {
    while (true) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            condition_.wait(lock, [&]() {
                return stopping_ || !queue_.empty();
            });
            if (queue_.empty()) {
                if (stopping_) {
                    return;
                }
                continue;
            }
            job = queue_.front();
            queue_.pop_front();
        }

        try {
            std::string error;
            if (!accounting_->send(job.status, job.record, &error)) {
                log_warn("accounting send failed for " + job.record.username +
                         ": " + error);
            }
        } catch (const std::exception& exception) {
            log_warn(std::string("accounting worker exception: ") +
                     exception.what());
        } catch (...) {
            log_warn("accounting worker unknown exception");
        }
    }
}

} // namespace vpn