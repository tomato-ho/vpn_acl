#pragma once

#include "vpn/accounting.h"

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace vpn {

class AccountingWorker {
public:
    explicit AccountingWorker(RadiusServerConfig config,
                              std::size_t max_queue = 1024);
    ~AccountingWorker();

    AccountingWorker(const AccountingWorker&) = delete;
    AccountingWorker& operator=(const AccountingWorker&) = delete;

    void start();
    void stop();
    bool enqueue(AcctStatus status, const AcctRecord& record);

private:
    struct Job {
        AcctStatus status;
        AcctRecord record;
    };

    void run();

    std::unique_ptr<RadiusAccounting> accounting_;
    std::deque<Job> queue_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::thread thread_;
    bool stopping_{false};
    std::size_t max_queue_;
};

} // namespace vpn