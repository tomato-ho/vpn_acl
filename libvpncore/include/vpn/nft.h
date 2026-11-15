#pragma once

#include "vpn/types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace vpn {

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