#pragma once

#include <string>

namespace vpn::service::detail {

// 在线会话（vpn_sessions）与历史会话（vpn_session_history）合并成一个
// 关系型数据源，列与原先 radacct 的查询保持一致：
//
//   session_id, username, virtual_ip, remote_ip, start_time, stop_time_text,
//   duration_seconds, bytes_in, bytes_out, terminate_cause, is_open
//
// 别名固定为 r，便于外层继续使用 r.xxx 拼条件。
inline std::string history_source() {
    return "(SELECT h.session_id, h.username, h.virtual_ip, h.remote_ip, "
           "h.start_time, "
           "DATE_FORMAT(h.stop_time, '%Y-%m-%d %H:%i:%s') AS stop_time_text, "
           "h.duration_seconds, h.bytes_in, h.bytes_out, h.terminate_cause, "
           "0 AS is_open FROM vpn_session_history h "
           "UNION ALL "
           "SELECT s.session_id, s.username, s.virtual_ip, s.remote_ip, "
           "s.start_time, "
           "'' AS stop_time_text, "
           "TIMESTAMPDIFF(SECOND, s.start_time, NOW()) AS duration_seconds, "
           "s.bytes_in, s.bytes_out, '' AS terminate_cause, 1 AS is_open "
           "FROM vpn_sessions s) r";
}

} // namespace vpn::service::detail