#include "vpn/nft.h"

#include "vpn/cidr.h"

#include <iomanip>
#include <sstream>

namespace vpn {
namespace {

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

    out << "add chain inet " << table
        << " forward { type filter hook forward priority filter - 10; policy accept; }\n";
    out << "add rule inet " << table
        << " forward ct state established,related accept\n";
    out << "add rule inet " << table << " forward iifname \"" << tun_iface
        << "\" oifname \"" << tun_iface << "\" drop\n";
    out << "add rule inet " << table << " forward iifname \"" << tun_iface
        << "\" ip saddr vmap @user_fwd\n";
    out << "add rule inet " << table << " forward iifname \"" << tun_iface
        << "\" counter drop\n";

    out << "add chain inet " << table
        << " input { type filter hook input priority filter - 10; policy accept; }\n";
    out << "add rule inet " << table
        << " input ct state established,related accept\n";
    out << "add rule inet " << table << " input iifname \"" << tun_iface
        << "\" ip saddr vmap @user_in\n";
    out << "add rule inet " << table << " input iifname \"" << tun_iface
        << "\" counter drop\n";
    return out.str();
}

std::string nft_forward_rules(const std::string& table,
                              const std::string& chain,
                              const std::vector<Cidr>& allow) {
    std::ostringstream out;
    if (!allow.empty()) {
        out << "add rule inet " << table << ' ' << chain
            << " ip daddr { " << join_cidrs(allow) << " } accept\n";
    }
    out << "add rule inet " << table << ' ' << chain << " counter drop\n";
    return out.str();
}

std::string nft_input_rules(const std::string& table,
                            const std::string& chain,
                            const std::vector<Service>& services) {
    std::ostringstream out;
    for (const auto& service : services) {
        out << "add rule inet " << table << ' ' << chain << " ip daddr "
            << format_ipv4(service.ip) << ' ' << service.protocol
            << " dport " << service.port << " accept\n";
    }
    out << "add rule inet " << table << ' ' << chain << " counter drop\n";
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