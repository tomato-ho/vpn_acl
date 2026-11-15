#include "nft_batch.h"

#include "nft_manager.h"

#include "vpn/cidr.h"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace vpn {
namespace {

constexpr const char* kForwardMap = "user_fwd";
constexpr const char* kInputMap = "user_in";

bool is_user_chain(const std::string& name) {
    return name.rfind("uf_", 0) == 0 || name.rfind("ui_", 0) == 0;
}

bool chain_referenced(const std::map<std::string, std::string>& elements,
                      const std::string& chain,
                      const std::string& skip_ip) {
    for (const auto& entry : elements) {
        if (entry.first != skip_ip && entry.second == chain) {
            return true;
        }
    }
    return false;
}

std::string delete_element(const std::string& table,
                           const std::string& map_name,
                           const std::string& ip) {
    return "delete element inet " + table + " " + map_name + " { " + ip + " }\n";
}

std::string add_element(const std::string& table,
                        const std::string& map_name,
                        const std::string& ip,
                        const std::string& chain) {
    return "add element inet " + table + " " + map_name + " { " + ip +
           " : jump " + chain + " }\n";
}

void update_map_element(const std::string& table,
                        const std::string& map_name,
                        const std::string& chain,
                        const std::string& ip,
                        std::map<std::string, std::string>* elements,
                        std::set<std::string>* touched_chains,
                        std::string* script) {
    const auto found = elements->find(ip);
    if (found != elements->end()) {
        if (found->second == chain) {
            return;
        }
        *script += delete_element(table, map_name, ip);
        touched_chains->insert(found->second);
        elements->erase(found);
    }
    *script += add_element(table, map_name, ip, chain);
    (*elements)[ip] = chain;
}

} // namespace

NftBatchPlan plan_nft_batch(const std::string& table,
                            const NftState& current,
                            const std::vector<NftSessionUpdate>& updates,
                            std::string* error) {
    NftBatchPlan plan;
    if (error) {
        error->clear();
    }

    std::vector<NftSessionUpdate> ordered = updates;
    std::sort(ordered.begin(),
              ordered.end(),
              [](const NftSessionUpdate& a, const NftSessionUpdate& b) {
                  if (a.username != b.username) {
                      return a.username < b.username;
                  }
                  return a.virtual_ip < b.virtual_ip;
              });

    std::set<std::string> seen_users;
    std::set<std::string> seen_ips;
    for (const auto& update : ordered) {
        if (update.username.empty()) {
            if (error) {
                *error = "nft batch update has empty username";
            }
            return NftBatchPlan{};
        }
        if (!seen_users.insert(update.username).second) {
            if (error) {
                *error = "duplicate nft batch username: " + update.username;
            }
            return NftBatchPlan{};
        }
        const std::string ip = format_ipv4(update.virtual_ip);
        if (!seen_ips.insert(ip).second) {
            if (error) {
                *error = "duplicate nft batch virtual IP: " + ip;
            }
            return NftBatchPlan{};
        }
    }

    std::map<std::string, std::string> forward = current.user_fwd;
    std::map<std::string, std::string> input = current.user_in;
    std::set<std::string> chains = current.chains;
    std::set<std::string> touched_chains;

    for (const auto& update : ordered) {
        const std::string ip = format_ipv4(update.virtual_ip);
        const std::string hash = nft_chain_hash(update.username);
        const std::string forward_chain = "uf_" + hash;
        const std::string input_chain = "ui_" + hash;

        if (update.remove) {
            const auto forward_entry = forward.find(ip);
            if (forward_entry != forward.end()) {
                plan.script += delete_element(table, kForwardMap, ip);
                touched_chains.insert(forward_entry->second);
                forward.erase(forward_entry);
            }
            const auto input_entry = input.find(ip);
            if (input_entry != input.end()) {
                plan.script += delete_element(table, kInputMap, ip);
                touched_chains.insert(input_entry->second);
                input.erase(input_entry);
            }
            ++plan.removed;
            continue;
        }

        if (chain_referenced(forward, forward_chain, ip)) {
            if (error) {
                *error = "nft forward chain is shared by another IP: " +
                         forward_chain;
            }
            return NftBatchPlan{};
        }
        if (chain_referenced(input, input_chain, ip)) {
            if (error) {
                *error = "nft input chain is shared by another IP: " +
                         input_chain;
            }
            return NftBatchPlan{};
        }

        if (chains.find(forward_chain) == chains.end()) {
            plan.script += "add chain inet " + table + " " + forward_chain + "\n";
            chains.insert(forward_chain);
        } else {
            plan.script +=
                "flush chain inet " + table + " " + forward_chain + "\n";
        }
        plan.script += nft_forward_rules(table, forward_chain, update.allow);

        if (chains.find(input_chain) == chains.end()) {
            plan.script += "add chain inet " + table + " " + input_chain + "\n";
            chains.insert(input_chain);
        } else {
            plan.script +=
                "flush chain inet " + table + " " + input_chain + "\n";
        }
        plan.script += nft_input_rules(table, input_chain, update.services);

        touched_chains.insert(forward_chain);
        touched_chains.insert(input_chain);
        update_map_element(table, kForwardMap, forward_chain, ip, &forward,
                           &touched_chains, &plan.script);
        update_map_element(table, kInputMap, input_chain, ip, &input,
                           &touched_chains, &plan.script);
        ++plan.applied;
    }

    for (const auto& chain : touched_chains) {
        if (!is_user_chain(chain) || chains.find(chain) == chains.end()) {
            continue;
        }
        if (chain_referenced(forward, chain, "") ||
            chain_referenced(input, chain, "")) {
            continue;
        }
        plan.script += "delete chain inet " + table + " " + chain + "\n";
        plan.deleted_chains.push_back(chain);
        chains.erase(chain);
    }

    return plan;
}

} // namespace vpn