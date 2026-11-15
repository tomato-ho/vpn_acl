#include "vpn/db_config.h"

#include <stdexcept>

namespace vpn {

DbConfig make_db_config(const Config& config) {
    DbConfig db;
    db.host = config.get("db_host", "127.0.0.1");
    db.port = config.get_uint("db_port", 3306);
    db.name = config.get("db_name", "radius");
    db.user = config.get("db_user", "radius");
    db.password = config.get("db_password");
    if (db.password.empty()) {
        throw std::runtime_error("db_password is missing");
    }
    return db;
}

} // namespace vpn