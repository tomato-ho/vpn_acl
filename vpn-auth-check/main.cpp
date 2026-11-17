// OpenVPN 认证入口：auth-user-pass-verify ... via-file
//
// OpenVPN 把用户名/密码写到临时文件的前两行，并把文件名作为 argv[1] 传入。
// 这里查 vpn_users 校验 PBKDF2 密码，写 vpn_auth_log，失败时通过
// auth_failed_reason_file 回传原因给客户端。
//
// 退出码：0 通过，1 拒绝。任何异常都按失败处理（fail-closed）。

#include "vpn/config.h"
#include "vpn/db.h"
#include "vpn/db_config.h"
#include "vpn/password.h"
#include "vpn/util.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

namespace {

using namespace vpn;

constexpr int kFailureWindowSeconds = 300;
constexpr unsigned int kMaxFailures = 5;
constexpr unsigned int kMaxFailuresPerIp = 20;

struct Credentials {
    std::string username;
    std::string password;
};

bool read_credentials(const std::string& path, Credentials* out) {
    std::ifstream input(path);
    if (!input) {
        return false;
    }
    if (!std::getline(input, out->username) ||
        !std::getline(input, out->password)) {
        return false;
    }
    auto strip_cr = [](std::string& value) {
        if (!value.empty() && value.back() == '\r') {
            value.pop_back();
        }
    };
    strip_cr(out->username);
    strip_cr(out->password);
    return !out->username.empty();
}

std::string env_value(const char* name) {
    const char* value = std::getenv(name);
    return (value && *value) ? std::string(value) : std::string();
}

std::string config_path() {
    const std::string value = env_value("VPN_AUTH_CONFIG");
    return value.empty() ? std::string("/etc/vpn-policy/config") : value;
}

// OpenVPN 在不同阶段导出的变量名不同：TLS 建立后是 trusted_ip，
// 之前只有 untrusted_ip，两个都兜一下。
std::string remote_ip_from_env() {
    std::string value = env_value("trusted_ip");
    if (value.empty()) {
        value = env_value("untrusted_ip");
    }
    return value;
}

// 把失败原因写给 OpenVPN；它会作为 AUTH_FAILED 文本返回给客户端。
void write_client_reason(const std::string& message) {
    const std::string path = env_value("auth_failed_reason_file");
    if (path.empty()) {
        return;
    }
    std::ofstream output(path, std::ios::trunc);
    if (output) {
        output << message << "\n";
    }
}

void log_attempt(Db& db,
                 const std::string& username,
                 const std::string& remote_ip,
                 bool success,
                 const std::string& reason) {
    db.execute("INSERT INTO vpn_auth_log "
               "(username, remote_ip, success, reason) VALUES ('" +
               db.quote(username) + "', '" + db.quote(remote_ip) + "', " +
               (success ? "1" : "0") + ", '" + db.quote(reason) + "')");
}

bool recently_failed(Db& db, const std::string& username,
                     const std::string& remote_ip) {
    const std::string window =
        "created_at > NOW() - INTERVAL " + std::to_string(kFailureWindowSeconds) +
        " SECOND";
    // 按 username + IP 限流，避免单个 IP 故意失败把该用户名在所有来源上锁死。
    const auto by_pair = db.query(
        "SELECT COUNT(*) FROM vpn_auth_log WHERE username = '" +
        db.quote(username) + "' AND remote_ip = '" + db.quote(remote_ip) +
        "' AND success = 0 AND " + window);
    if (!by_pair.empty() && !by_pair[0].empty()) {
        try {
            if (static_cast<unsigned int>(std::stoul(by_pair[0][0])) >=
                kMaxFailures) {
                return true;
            }
        } catch (const std::exception&) {
        }
    }
    if (!remote_ip.empty()) {
        const auto by_ip = db.query(
            "SELECT COUNT(*) FROM vpn_auth_log WHERE remote_ip = '" +
            db.quote(remote_ip) + "' AND success = 0 AND " + window);
        if (!by_ip.empty() && !by_ip[0].empty()) {
            try {
                return static_cast<unsigned int>(std::stoul(by_ip[0][0])) >=
                       kMaxFailuresPerIp;
            } catch (const std::exception&) {
            }
        }
    }
    return false;
}

int reject(Db& db,
           const Credentials& credentials,
           const std::string& remote_ip,
           const std::string& reason,
           const std::string& client_message) {
    try {
        log_attempt(db, credentials.username, remote_ip, false, reason);
    } catch (const std::exception& error) {
        std::cerr << "vpn-auth-check: 记录认证失败时出错: " << error.what()
                  << "\n";
    }
    write_client_reason(client_message);
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: vpn-auth-check <cred-file>\n";
        return 1;
    }

    Credentials credentials;
    if (!read_credentials(argv[1], &credentials)) {
        std::cerr << "vpn-auth-check: 无法读取认证文件\n";
        return 1;
    }

    const std::string remote_ip = remote_ip_from_env();

    try {
        const Config config = Config::load(resolve_config_path(config_path()));
        Db db(make_db_config(config));
        db.connect();

        if (recently_failed(db, credentials.username, remote_ip)) {
            return reject(db, credentials, remote_ip, "rate-limited",
                          "尝试次数过多，请稍后再试");
        }

        const auto rows = db.query(
            "SELECT enabled, password_hash "
            "FROM vpn_users WHERE username = '" +
            db.quote(credentials.username) + "'");
        if (rows.empty() || rows[0].size() < 2) {
            // 不存在用户也做一次 PBKDF2，减少用户名枚举的时序差异。
            (void)pbkdf2_sha256_user(credentials.password);
            return reject(db, credentials, remote_ip, "unknown-user",
                          "用户名或密码错误");
        }

        const bool enabled = rows[0][0] == "1";
        const std::string& hash = rows[0][1];

        if (!enabled || hash.empty()) {
            // 账号状态不向客户端暴露；同时做一次 PBKDF2，避免明显的时序差异。
            (void)pbkdf2_sha256_user(credentials.password);
            return reject(db, credentials, remote_ip,
                          enabled ? "no-password" : "disabled",
                          "用户名或密码错误");
        }
        if (!verify_user_password(credentials.password, hash)) {
            return reject(db, credentials, remote_ip, "bad-password",
                          "用户名或密码错误");
        }

        log_attempt(db, credentials.username, remote_ip, true, "");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "vpn-auth-check: " << error.what() << "\n";
        write_client_reason("认证服务暂时不可用，请稍后再试");
        return 1;
    }
}