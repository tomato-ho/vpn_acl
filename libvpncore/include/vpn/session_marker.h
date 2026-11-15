#pragma once

#include <string>

namespace vpn {

// 与 IPC socket 同目录的 clients/ 下，用 <username>@<virtual_ip> 记录本次连接的
// session_id，供 client-disconnect hook 精确匹配（避免靠 start_time 猜）。
std::string session_marker_path(const std::string& socket_path,
                                const std::string& username,
                                const std::string& virtual_ip);

// 原子写入（先写 .tmp 再 rename）。失败时返回 false，不影响主流程。
bool write_session_marker(const std::string& path,
                          const std::string& session_id);

// 读取第一行；文件不存在或内容非法时返回空字符串。
std::string read_session_marker(const std::string& path);

} // namespace vpn