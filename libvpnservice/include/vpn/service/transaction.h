#pragma once

#include "vpn/db.h"

namespace vpn::service {

class Transaction {
public:
    explicit Transaction(Db& db) : db_(db) { db_.begin(); }

    ~Transaction() {
        if (!committed_) {
            try {
                db_.rollback();
            } catch (const std::exception&) {
            }
        }
    }

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    void commit() {
        db_.commit();
        committed_ = true;
    }

private:
    Db& db_;
    bool committed_{false};
};

} // namespace vpn::service