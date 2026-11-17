#pragma once

#include "vpn/types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace vpn {

// 访问审计用的 nft 动态集合（全局，元素键统一为「客户端隧道 IP . 目标 IP」）。
//   flows      allow 上行（客户端 -> 目标）
//   flows_rev  allow 下行（目标 -> 客户端）
//   flows_deny deny（客户端 -> 目标）
inline constexpr const char* kFlowSetAllowUp = "flows";
inline constexpr const char* kFlowSetAllowDown = "flows_rev";
inline constexpr const char* kFlowSetDeny = "flows_deny";

struct FlowCounter {
    std::string set_name;
    std::string src_ip;
    std::string dest_ip;
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
};

// 解析 `nft -j list table` 的输出，只返回三个审计集合的元素。
std::vector<FlowCounter> parse_flow_counters_json(
    const std::string& json_text, std::string* error = nullptr);

std::string nft_base_script(const std::string& table,
                            const std::string& tun_iface);

std::string nft_forward_rules(const std::string& table,
                              const std::string& chain,
                              const std::vector<Cidr>& allow);

std::string nft_input_rules(const std::string& table,
                            const std::string& chain,
                            const std::vector<Service>& services);

std::string nft_session_script(const std::string& table,
                               const std::string& tun_iface,
                               const std::string& username,
                               std::uint32_t virtual_ip,
                               const std::vector<Cidr>& allow,
                               const std::vector<Service>& services);

std::vector<std::string> nft_cleanup_scripts(const std::string& table,
                                             const std::string& username,
                                             std::uint32_t virtual_ip);

std::string nft_chain_hash(const std::string& username);

} // namespace vpn