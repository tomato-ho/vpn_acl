#include "nft_manager.h"

#include "vpn/cidr.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace vpn {
namespace {

bool write_all(int fd, const std::string& data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t written =
            ::write(fd, data.data() + offset, data.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

std::string parse_key(const nlohmann::json& value) {
    if (value.is_string()) {
        return value.get<std::string>();
    }
    if (value.is_object() && value.contains("val")) {
        const auto& inner = value["val"];
        if (inner.is_string()) {
            return inner.get<std::string>();
        }
        if (inner.is_number_unsigned()) {
            return format_ipv4(
                static_cast<std::uint32_t>(inner.get<std::uint64_t>()));
        }
    }
    return {};
}

std::string parse_verdict(const nlohmann::json& value) {
    if (!value.is_object() || !value.contains("jump")) {
        return {};
    }
    const auto& jump = value["jump"];
    if (jump.is_string()) {
        return jump.get<std::string>();
    }
    if (jump.is_object() && jump.contains("target") &&
        jump["target"].is_string()) {
        return jump["target"].get<std::string>();
    }
    return {};
}

bool is_user_chain(const std::string& name) {
    return name.rfind("uf_", 0) == 0 || name.rfind("ui_", 0) == 0;
}

} // namespace

NftManager::NftManager(std::string nft_bin,
                       std::string table,
                       std::string tun_iface,
                       std::string work_dir,
                       bool dry_run)
    : nft_bin_(std::move(nft_bin)),
      table_(std::move(table)),
      tun_iface_(std::move(tun_iface)),
      work_dir_(std::move(work_dir)),
      dry_run_(dry_run) {
    if (work_dir_.empty()) {
        work_dir_ = "/run/vpn-policyd";
    }
}

bool NftManager::run_args(const std::vector<std::string>& args,
                          std::string* error,
                          bool quiet) {
    if (dry_run_) {
        std::cerr << "nft";
        for (const auto& arg : args) {
            std::cerr << ' ' << arg;
        }
        std::cerr << "\n";
        return true;
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 2);
    argv.push_back(const_cast<char*>(nft_bin_.c_str()));
    for (const auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    const pid_t pid = ::fork();
    if (pid < 0) {
        if (error) {
            *error = std::string("fork failed: ") + std::strerror(errno);
        }
        return false;
    }
    if (pid == 0) {
        if (quiet) {
            const int null_fd = ::open("/dev/null", O_WRONLY);
            if (null_fd >= 0) {
                ::dup2(null_fd, STDOUT_FILENO);
                ::dup2(null_fd, STDERR_FILENO);
                ::close(null_fd);
            }
        }
        ::execv(nft_bin_.c_str(), argv.data());
        _exit(127);
    }

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) {
        if (error) {
            *error = std::string("waitpid failed: ") + std::strerror(errno);
        }
        return false;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (error) {
            *error = "nft command failed";
        }
        return false;
    }
    return true;
}

bool NftManager::run_capture(const std::vector<std::string>& args,
                             std::string* output,
                             std::string* error) {
    if (dry_run_) {
        if (output) {
            output->clear();
        }
        return true;
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 2);
    argv.push_back(const_cast<char*>(nft_bin_.c_str()));
    for (const auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    int pipefd[2] = {-1, -1};
    if (::pipe(pipefd) != 0) {
        if (error) {
            *error = std::string("pipe failed: ") + std::strerror(errno);
        }
        return false;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        const std::string message = std::strerror(errno);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        if (error) {
            *error = "fork failed: " + message;
        }
        return false;
    }
    if (pid == 0) {
        ::close(pipefd[0]);
        ::dup2(pipefd[1], STDOUT_FILENO);
        const int null_fd = ::open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            ::dup2(null_fd, STDERR_FILENO);
            ::close(null_fd);
        }
        ::close(pipefd[1]);
        ::execv(nft_bin_.c_str(), argv.data());
        _exit(127);
    }

    ::close(pipefd[1]);
    std::string captured;
    char buffer[4096];
    bool read_ok = true;
    while (true) {
        const ssize_t received = ::read(pipefd[0], buffer, sizeof(buffer));
        if (received == 0) {
            break;
        }
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            read_ok = false;
            break;
        }
        captured.append(buffer, static_cast<std::size_t>(received));
    }
    ::close(pipefd[0]);

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) {
        if (error) {
            *error = std::string("waitpid failed: ") + std::strerror(errno);
        }
        return false;
    }
    if (!read_ok) {
        if (error) {
            *error = "failed to read nft output";
        }
        return false;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (error) {
            *error = "nft list command failed";
        }
        return false;
    }
    if (output) {
        *output = std::move(captured);
    }
    return true;
}

bool NftManager::run_script(const std::string& script,
                            std::string* error,
                            bool quiet,
                            bool check_only) {
    if (dry_run_) {
        std::cerr << "--- nft script ---\n" << script << "--- end ---\n";
        return true;
    }

    ::mkdir(work_dir_.c_str(), 0750);
    std::string path = work_dir_ + "/nft-XXXXXX";
    std::vector<char> buffer(path.begin(), path.end());
    buffer.push_back('\0');
    const int fd = ::mkstemp(buffer.data());
    if (fd < 0) {
        if (error) {
            *error = std::string("mkstemp failed: ") + std::strerror(errno);
        }
        return false;
    }
    path.assign(buffer.data());

    const bool written = write_all(fd, script);
    ::close(fd);
    if (!written) {
        ::unlink(path.c_str());
        if (error) {
            *error = "failed to write nft script";
        }
        return false;
    }

    const bool ok = check_only
                        ? run_args({"-c", "-f", path}, error, quiet)
                        : run_args({"-f", path}, error, quiet);
    ::unlink(path.c_str());
    return ok;
}

bool NftManager::table_exists() {
    std::string error;
    return run_args({"list", "table", "inet", table_}, &error, true);
}

bool NftManager::ensure_base(std::string* error) {
    if (dry_run_) {
        return run_script(nft_base_script(table_, tun_iface_), error);
    }
    if (table_exists()) {
        return true;
    }
    return run_script(nft_base_script(table_, tun_iface_), error);
}

bool NftManager::check_base(std::string* error) {
    return run_script(nft_base_script(table_, tun_iface_), error, false, true);
}

bool NftManager::read_state(NftState* state, std::string* error) {
    if (!state) {
        if (error) {
            *error = "state output is null";
        }
        return false;
    }
    state->user_fwd.clear();
    state->user_in.clear();
    state->chains.clear();
    if (dry_run_) {
        return true;
    }

    std::string output;
    if (!run_capture({"-j", "list", "table", "inet", table_}, &output,
                     error)) {
        return false;
    }

    const auto root = nlohmann::json::parse(output, nullptr, false);
    if (root.is_discarded() || !root.is_object() ||
        !root.contains("nftables") || !root["nftables"].is_array()) {
        if (error) {
            *error = "invalid nft json output";
        }
        return false;
    }

    for (const auto& item : root["nftables"]) {
        if (item.contains("map") && item["map"].is_object()) {
            const auto& map = item["map"];
            const std::string name = map.value("name", "");
            if (name != "user_fwd" && name != "user_in") {
                continue;
            }
            if (!map.contains("elem") || !map["elem"].is_array()) {
                continue;
            }
            for (const auto& element : map["elem"]) {
                if (!element.is_array() || element.size() < 2) {
                    continue;
                }
                const std::string ip = parse_key(element[0]);
                const std::string chain = parse_verdict(element[1]);
                if (ip.empty() || chain.empty()) {
                    continue;
                }
                if (name == "user_fwd") {
                    state->user_fwd[ip] = chain;
                } else {
                    state->user_in[ip] = chain;
                }
            }
        } else if (item.contains("chain") && item["chain"].is_object()) {
            const std::string name = item["chain"].value("name", "");
            if (!name.empty()) {
                state->chains.insert(name);
            }
        }
    }
    return true;
}

bool NftManager::apply_updates(const std::vector<NftSessionUpdate>& updates,
                               NftBatchStats* stats,
                               std::string* error) {
    if (stats) {
        *stats = NftBatchStats{};
    }
    if (updates.empty()) {
        return true;
    }

    if (dry_run_) {
        for (const auto& update : updates) {
            if (update.remove) {
                for (const auto& script : nft_cleanup_scripts(
                         table_, update.username, update.virtual_ip)) {
                    if (!run_script(script, nullptr, true)) {
                        return false;
                    }
                }
                if (stats) {
                    ++stats->removed;
                }
            } else {
                const std::string script = nft_session_script(
                    table_, tun_iface_, update.username, update.virtual_ip,
                    update.allow, update.services);
                if (!run_script(script, nullptr, false)) {
                    return false;
                }
                if (stats) {
                    ++stats->applied;
                }
            }
        }
        return true;
    }

    std::string base_error;
    if (!ensure_base(&base_error)) {
        if (error) {
            *error = "failed to restore nftables base table: " + base_error;
        }
        return false;
    }

    NftState state;
    if (!read_state(&state, error)) {
        return false;
    }

    std::string plan_error;
    const NftBatchPlan plan =
        plan_nft_batch(table_, state, updates, &plan_error);
    if (!plan_error.empty()) {
        if (error) {
            *error = plan_error;
        }
        return false;
    }

    if (stats) {
        stats->applied = plan.applied;
        stats->removed = plan.removed;
    }

    if (plan.script.empty()) {
        return true;
    }

    if (!run_script(plan.script, error)) {
        return false;
    }
    if (stats) {
        stats->nft_calls = 1;
    }

    NftState after;
    if (!read_state(&after, error)) {
        return false;
    }

    for (const auto& update : updates) {
        const std::string ip = format_ipv4(update.virtual_ip);
        if (update.remove) {
            if (after.user_fwd.find(ip) != after.user_fwd.end() ||
                after.user_in.find(ip) != after.user_in.end()) {
                if (error) {
                    *error = "nft session element still exists after cleanup";
                }
                return false;
            }
            continue;
        }

        const std::string hash = nft_chain_hash(update.username);
        const std::string forward_chain = "uf_" + hash;
        const std::string input_chain = "ui_" + hash;
        const auto forward = after.user_fwd.find(ip);
        const auto input = after.user_in.find(ip);
        if (forward == after.user_fwd.end() ||
            forward->second != forward_chain ||
            input == after.user_in.end() || input->second != input_chain ||
            after.chains.find(forward_chain) == after.chains.end() ||
            after.chains.find(input_chain) == after.chains.end()) {
            if (error) {
                *error = "nft session verification failed";
            }
            return false;
        }
    }

    for (const auto& chain : plan.deleted_chains) {
        if (after.chains.find(chain) != after.chains.end()) {
            if (error) {
                *error = "nft chain still exists after cleanup: " + chain;
            }
            return false;
        }
    }
    return true;
}

bool NftManager::apply_session(const std::string& username,
                               std::uint32_t virtual_ip,
                               const std::vector<Cidr>& allow,
                               const std::vector<Service>& services,
                               std::string* error) {
    NftSessionUpdate update;
    update.username = username;
    update.virtual_ip = virtual_ip;
    update.allow = allow;
    update.services = services;
    return apply_updates({update}, nullptr, error);
}

bool NftManager::remove_session(const std::string& username,
                                std::uint32_t virtual_ip,
                                std::string* error) {
    NftSessionUpdate update;
    update.username = username;
    update.virtual_ip = virtual_ip;
    update.remove = true;
    return apply_updates({update}, nullptr, error);
}

bool NftManager::cleanup_orphans(const std::set<std::string>& keep_ips,
                                 const std::set<std::string>& keep_chains,
                                 std::size_t* removed_elements,
                                 std::size_t* removed_chains,
                                 std::string* error) {
    if (removed_elements) {
        *removed_elements = 0;
    }
    if (removed_chains) {
        *removed_chains = 0;
    }
    if (dry_run_ || !table_exists()) {
        return true;
    }

    NftState state;
    if (!read_state(&state, error)) {
        return false;
    }

    std::set<std::string> orphan_ips;
    for (const auto& entry : state.user_fwd) {
        if (keep_ips.find(entry.first) == keep_ips.end()) {
            orphan_ips.insert(entry.first);
        }
    }
    for (const auto& entry : state.user_in) {
        if (keep_ips.find(entry.first) == keep_ips.end()) {
            orphan_ips.insert(entry.first);
        }
    }

    std::set<std::string> referenced_chains;
    for (const auto& entry : state.user_fwd) {
        if (keep_ips.find(entry.first) != keep_ips.end()) {
            referenced_chains.insert(entry.second);
        }
    }
    for (const auto& entry : state.user_in) {
        if (keep_ips.find(entry.first) != keep_ips.end()) {
            referenced_chains.insert(entry.second);
        }
    }

    std::string script;
    std::size_t element_count = 0;
    std::size_t chain_count = 0;
    for (const auto& ip : orphan_ips) {
        if (state.user_fwd.find(ip) != state.user_fwd.end()) {
            script += "delete element inet " + table_ + " user_fwd { " + ip +
                      " }\n";
            ++element_count;
        }
        if (state.user_in.find(ip) != state.user_in.end()) {
            script += "delete element inet " + table_ + " user_in { " + ip +
                      " }\n";
            ++element_count;
        }
    }

    std::set<std::string> deleted_chains;
    for (const auto& chain : state.chains) {
        if (!is_user_chain(chain)) {
            continue;
        }
        if (keep_chains.find(chain) != keep_chains.end() ||
            referenced_chains.find(chain) != referenced_chains.end()) {
            continue;
        }
        script += "delete chain inet " + table_ + " " + chain + "\n";
        deleted_chains.insert(chain);
        ++chain_count;
    }

    if (script.empty()) {
        return true;
    }
    if (!run_script(script, error)) {
        return false;
    }

    NftState after;
    if (!read_state(&after, error)) {
        return false;
    }
    for (const auto& ip : orphan_ips) {
        if (after.user_fwd.find(ip) != after.user_fwd.end() ||
            after.user_in.find(ip) != after.user_in.end()) {
            if (error) {
                *error = "orphan nft element still exists";
            }
            return false;
        }
    }
    for (const auto& chain : deleted_chains) {
        if (after.chains.find(chain) != after.chains.end()) {
            if (error) {
                *error = "orphan nft chain still exists";
            }
            return false;
        }
    }

    if (removed_elements) {
        *removed_elements = element_count;
    }
    if (removed_chains) {
        *removed_chains = chain_count;
    }
    return true;
}

} // namespace vpn