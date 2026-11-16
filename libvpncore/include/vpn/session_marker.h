#pragma once

#include <string>

namespace vpn {

// 与 IPC socket 同目录的 clients/ 下，用
// <username>@<virtual_ip>@<connection_key> 记录本次连接的 session_id。
// connection_key 用 OpenVPN 的 time_unix（连接建立时间），这样同一用户重连时
// 新旧连接各有自己的 marker，旧连接的 disconnect 不会读到新连接的 id。
std::string session_marker_path(const std::string& socket_path,
                                const std::string& username,
                                const std::string& virtual_ip,
                                const std::string& connection_key);

// 原子写入（先写 .tmp 再 rename）。失败时返回 false，不影响主流程。
bool write_session_marker(const std::string& path,
                          const std::string& session_id);

// 读取第一行；文件不存在或内容非法时返回空字符串。
std::string read_session_marker(const std::string& path);

// 在该用户/IP 的所有 marker 中取最新一个（reconcile 恢复会话时用，
// 因为 status 的 connected_since 与 connect hook 的 time_unix 可能差几秒）。
std::string find_session_marker(const std::string& socket_path,
                                const std::string& username,
                                const std::string& virtual_ip);

} // namespace vpn