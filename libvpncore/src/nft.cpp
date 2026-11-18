#include "vpn/nft.h"

#include "vpn/cidr.h"

#include <nlohmann/json.hpp>

#include <iomanip>
#include <sstream>

namespace vpn {
namespace {

// 允许/反向集合的超时设得很长：policyd 会在连接/断开时主动清理元素，
// 长超时避免"空闲一段时间后计数器归零"导致少计。deny 集合保持短超时，
// 防止扫描流量长期占用容量。
constexpr const char* kFlowSetTimeout = "24h";
constexpr const char* kFlowDenyTimeout = "10m";

bool is_flow_set(const std::string& name) {
    return name == kFlowSetAllowUp || name == kFlowSetAllowDown ||
           name == kFlowSetDeny;
}

std::string json_ip(const nlohmann::json& value) {
    if (value.is_string()) {
        return value.get<std::string>();
    }
    if (value.is_number_unsigned()) {
        return format_ipv4(
            static_cast<std::uint32_t>(value.get<std::uint64_t>()));
    }
    if (value.is_number_integer()) {
        const auto number = value.get<std::int64_t>();
        if (number >= 0) {
            return format_ipv4(static_cast<std::uint32_t>(number));
        }
        return {};
    }
    if (value.is_object() && value.contains("val")) {
        return json_ip(value["val"]);
    }
    return {};
}

std::uint64_t json_counter(const nlohmann::json& counter, const char* key) {
    if (!counter.is_object() || !counter.contains(key)) {
        return 0;
    }
    const auto& value = counter[key];
    if (value.is_number_unsigned()) {
        return value.get<std::uint64_t>();
    }
    if (value.is_number_integer()) {
        const auto number = value.get<std::int64_t>();
        return number > 0 ? static_cast<std::uint64_t>(number) : 0;
    }
    return 0;
}

std::string join_cidrs(const std::vector<Cidr>& cidrs) {
    std::ostringstream out;
    bool first = true;
    for (const auto& cidr : cidrs) {
        if (!first) {
            out << ", ";
        }
        out << cidr.to_string();
        first = false;
    }
    return out.str();
}

} // namespace

std::vector<FlowCounter> parse_flow_counters_json(const std::string& json_text,
                                                  std::string* error) {
    std::vector<FlowCounter> out;
    const auto root = nlohmann::json::parse(json_text, nullptr, false);
    if (root.is_discarded() || !root.is_object() ||
        !root.contains("nftables") || !root["nftables"].is_array()) {
        if (error) {
            *error = "invalid nft json output";
        }
        return out;
    }

    for (const auto& item : root["nftables"]) {
        if (!item.is_object() || !item.contains("set") ||
            !item["set"].is_object()) {
            continue;
        }
        const auto& set = item["set"];
        const std::string name = set.value("name", "");
        if (!is_flow_set(name)) {
            continue;
        }
        if (!set.contains("elem") || !set["elem"].is_array()) {
            continue;
        }
        for (const auto& entry : set["elem"]) {
            const nlohmann::json* element = &entry;
            if (entry.is_object() && entry.contains("elem")) {
                element = &entry["elem"];
            }
            if (!element->is_object() || !element->contains("val")) {
                continue;
            }
            const auto& val = (*element)["val"];
            if (!val.is_object() || !val.contains("concat") ||
                !val["concat"].is_array() || val["concat"].size() < 2) {
                continue;
            }
            FlowCounter counter;
            counter.set_name = name;
            counter.src_ip = json_ip(val["concat"][0]);
            counter.dest_ip = json_ip(val["concat"][1]);
            if (counter.src_ip.empty() || counter.dest_ip.empty()) {
                continue;
            }
            if (element->contains("counter")) {
                const auto& stat = (*element)["counter"];
                counter.packets = json_counter(stat, "packets");
                counter.bytes = json_counter(stat, "bytes");
            }
            out.push_back(std::move(counter));
        }
    }
    return out;
}

std::string nft_chain_hash(const std::string& username) {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const unsigned char ch : username) {
        hash ^= ch;
        hash *= 1099511628211ULL;
    }
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << hash;
    return out.str();
}

std::string nft_base_script(const std::string& table,
                            const std::string& tun_iface) {
    std::ostringstream out;
    out << "add table inet " << table << "\n";
    out << "add map inet " << table
        << " user_fwd { type ipv4_addr : verdict; }\n";
    out << "add map inet " << table
        << " user_in { type ipv4_addr : verdict; }\n";

    // 访问审计集合：键统一为「客户端隧道 IP . 目标 IP」，per-element counter。
    const char* flow_sets[] = {kFlowSetAllowUp, kFlowSetAllowDown, kFlowSetDeny};
    for (const char* name : flow_sets) {
        const char* timeout = name == kFlowSetDeny ? kFlowDenyTimeout
                                                   : kFlowSetTimeout;
        out << "add set inet " << table << ' ' << name
            << " { type ipv4_addr . ipv4_addr; flags dynamic,timeout; timeout "
            << timeout << "; size " << kFlowSetCapacity
            << "; counter; }\n";
    }

    out << "add chain inet " << table
        << " forward { type filter hook forward priority filter - 10; policy accept; }\n";
    // 客户端隔离优先；同时把尝试访问其他客户端的目标记为 deny。
    out << "add rule inet " << table << " forward iifname \"" << tun_iface
        << "\" oifname \"" << tun_iface << "\" update @" << kFlowSetDeny
        << " { ip saddr . ip daddr } drop\n";
    // 下行（目标 -> 客户端）计数。放在策略链之前，保证回包都被统计。
    out << "add rule inet " << table << " forward oifname \"" << tun_iface
        << "\" ct state established,related update @" << kFlowSetAllowDown
        << " { ip daddr . ip saddr } accept\n";
    // tun0 的每个包都重新匹配当前策略：
    // 1) 允许流量在上行方向逐包计数（established 包不能绕过）；
    // 2) 收回权限后，已建立的连接也会立即被 deny。
    out << "add rule inet " << table << " forward iifname \"" << tun_iface
        << "\" ip saddr vmap @user_fwd\n";
    out << "add rule inet " << table << " forward iifname \"" << tun_iface
        << "\" counter drop\n";
    // 只影响非 tun0 的转发流量（例如 LAN 方向的 established 回包）。
    out << "add rule inet " << table
        << " forward ct state established,related accept\n";

    out << "add chain inet " << table
        << " input { type filter hook input priority filter - 10; policy accept; }\n";
    out << "add rule inet " << table << " input iifname \"" << tun_iface
        << "\" ip saddr vmap @user_in\n";
    out << "add rule inet " << table << " input iifname \"" << tun_iface
        << "\" counter drop\n";
    out << "add rule inet " << table
        << " input ct state established,related accept\n";
    return out.str();
}

std::string nft_forward_rules(const std::string& table,
                              const std::string& chain,
                              const std::vector<Cidr>& allow) {
    std::ostringstream out;
    if (!allow.empty()) {
        out << "add rule inet " << table << ' ' << chain
            << " ip daddr { " << join_cidrs(allow) << " } update @"
            << kFlowSetAllowUp << " { ip saddr . ip daddr } accept\n";
    }
    out << "add rule inet " << table << ' ' << chain << " update @"
        << kFlowSetDeny << " { ip saddr . ip daddr } counter drop\n";
    return out.str();
}

std::string nft_input_rules(const std::string& table,
                            const std::string& chain,
                            const std::vector<Service>& services) {
    std::ostringstream out;
    for (const auto& service : services) {
        out << "add rule inet " << table << ' ' << chain << " ip daddr "
            << format_ipv4(service.ip) << ' ' << service.protocol
            << " dport " << service.port << " update @" << kFlowSetAllowUp
            << " { ip saddr . ip daddr } accept\n";
    }
    out << "add rule inet " << table << ' ' << chain << " update @"
        << kFlowSetDeny << " { ip saddr . ip daddr } counter drop\n";
    return out.str();
}

std::string nft_session_script(const std::string& table,
                               const std::string& tun_iface,
                               const std::string& username,
                               std::uint32_t virtual_ip,
                               const std::vector<Cidr>& allow,
                               const std::vector<Service>& services) {
    (void)tun_iface;
    const std::string hash = nft_chain_hash(username);
    const std::string forward_chain = "uf_" + hash;
    const std::string input_chain = "ui_" + hash;

    std::ostringstream out;
    out << "add chain inet " << table << ' ' << forward_chain << "\n";
    out << nft_forward_rules(table, forward_chain, allow);

    out << "add chain inet " << table << ' ' << input_chain << "\n";
    out << nft_input_rules(table, input_chain, services);

    const std::string ip = format_ipv4(virtual_ip);
    out << "add element inet " << table << " user_fwd { " << ip
        << " : jump " << forward_chain << " }\n";
    out << "add element inet " << table << " user_in { " << ip
        << " : jump " << input_chain << " }\n";
    return out.str();
}

std::vector<std::string> nft_cleanup_scripts(const std::string& table,
                                             const std::string& username,
                                             std::uint32_t virtual_ip) {
    const std::string hash = nft_chain_hash(username);
    const std::string ip = format_ipv4(virtual_ip);
    const std::string forward_chain = "uf_" + hash;
    const std::string input_chain = "ui_" + hash;

    return {
        "delete element inet " + table + " user_fwd { " + ip + " }\n",
        "delete element inet " + table + " user_in { " + ip + " }\n",
        "delete chain inet " + table + " " + forward_chain + "\n",
        "delete chain inet " + table + " " + input_chain + "\n",
    };
}

} // namespace vpn