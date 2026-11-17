#pragma once

#include "nft_batch.h"

#include "vpn/nft.h"
#include "vpn/types.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace vpn {

struct NftState {
    std::map<std::string, std::string> user_fwd;
    std::map<std::string, std::string> user_in;
    std::set<std::string> chains;
};

class NftManager {
public:
    NftManager(std::string nft_bin,
               std::string table,
               std::string tun_iface,
               std::string work_dir,
               bool dry_run);

    bool ensure_base(std::string* error);
    bool check_base(std::string* error);
    bool table_exists();
    bool apply_updates(const std::vector<NftSessionUpdate>& updates,
                       NftBatchStats* stats,
                       std::string* error);
    bool apply_session(const std::string& username,
                       std::uint32_t virtual_ip,
                       const std::vector<Cidr>& allow,
                       const std::vector<Service>& services,
                       std::string* error);
    bool remove_session(const std::string& username,
                        std::uint32_t virtual_ip,
                        std::string* error);
    bool read_state(NftState* state, std::string* error);
    // 读取三个审计集合的元素计数。
    bool read_flow_counters(std::vector<FlowCounter>* counters,
                            std::string* error);
    // 删除某个客户端 IP 在所有审计集合里的元素（连接/断开时清理）。
    bool flush_flows(const std::string& ip, std::string* error);
    // 检测现有表是否包含审计集合（用于升级时触发重建）。
    bool has_flow_sets(bool* present);
    // 原子重建表：delete table + base + 给定会话。
    bool rebuild(const std::vector<NftSessionUpdate>& sessions,
                 std::string* error);
    // 删除不属于任何在线客户端的审计集合元素（崩溃/漏清理后的兜底）。
    bool cleanup_flow_elements(const std::set<std::string>& keep_ips,
                               std::size_t* removed,
                               std::string* error);
    bool cleanup_orphans(const std::set<std::string>& keep_ips,
                         const std::set<std::string>& keep_chains,
                         std::size_t* removed_elements,
                         std::size_t* removed_chains,
                         std::string* error);

private:
    bool run_script(const std::string& script,
                    std::string* error,
                    bool quiet = false,
                    bool check_only = false);
    bool run_args(const std::vector<std::string>& args,
                  std::string* error,
                  bool quiet = false);
    bool run_capture(const std::vector<std::string>& args,
                     std::string* output,
                     std::string* error);

    std::string nft_bin_;
    std::string table_;
    std::string tun_iface_;
    std::string work_dir_;
    bool dry_run_{false};
    // reconcile 线程与 IPC 线程都会调用 nft，串行化避免脚本互相覆盖。
    std::recursive_mutex mutex_;
};

} // namespace vpn