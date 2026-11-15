#pragma once

#include <string>
#include <vector>

namespace vpn {

std::string pbkdf2_sha256_freeradius(const std::string& password,
                                     int iterations = 100000);
std::string pbkdf2_sha256_freeradius_header(const std::string& password,
                                            int iterations = 100000);
std::string pbkdf2_sha256_admin(const std::string& password,
                                int iterations = 200000);
// VPN 用户密码：与 vpn_admins 同格式，但默认迭代次数更低（认证在 OpenVPN 的
// 同步脚本路径上执行，需要控制延迟）。
std::string pbkdf2_sha256_user(const std::string& password,
                               int iterations = 100000);
bool verify_admin_password(const std::string& password,
                           const std::string& encoded);
// 校验 VPN 用户密码，兼容 radcheck 导出的 {PBKDF2-SHA256} 前缀格式。
bool verify_user_password(const std::string& password,
                          const std::string& encoded);

std::string base64_encode(const unsigned char* data, std::size_t length);
std::vector<unsigned char> base64_decode(const std::string& value);

} // namespace vpn