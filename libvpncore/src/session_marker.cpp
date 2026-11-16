#include "vpn/session_marker.h"

#include <dirent.h>
#include <sys/stat.h>

#include <cstdio>
#include <fstream>
#include <string>

namespace vpn {
namespace {

std::string sanitize(std::string value) {
    for (char& ch : value) {
        if (ch == '/' || ch == '\0' || ch == '\n' || ch == '\r') {
            ch = '_';
        }
    }
    return value;
}

std::string trim(std::string value) {
    while (!value.empty() &&
           (value.back() == '\n' || value.back() == '\r' ||
            value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }
    std::size_t start = 0;
    while (start < value.size() &&
           (value[start] == ' ' || value[start] == '\t')) {
        ++start;
    }
    return value.substr(start);
}

} // namespace

std::string session_marker_path(const std::string& socket_path,
                                const std::string& username,
                                const std::string& virtual_ip,
                                const std::string& connection_key) {
    std::string dir = socket_path;
    const auto slash = dir.find_last_of('/');
    dir = slash == std::string::npos ? std::string(".") : dir.substr(0, slash);
    const std::string key = connection_key.empty() ? "0" : connection_key;
    return dir + "/clients/" + sanitize(username) + "@" +
           sanitize(virtual_ip) + "@" + sanitize(key);
}

bool write_session_marker(const std::string& path,
                          const std::string& session_id) {
    if (path.empty() || session_id.empty()) {
        return false;
    }
    const auto slash = path.find_last_of('/');
    if (slash != std::string::npos) {
        const std::string dir = path.substr(0, slash);
        ::mkdir(dir.c_str(), 0750); // 已存在时忽略错误
    }

    const std::string tmp = path + ".tmp";
    {
        std::ofstream output(tmp, std::ios::trunc);
        if (!output) {
            return false;
        }
        output << session_id << "\n";
        if (!output) {
            return false;
        }
    }
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

std::string find_session_marker(const std::string& socket_path,
                                const std::string& username,
                                const std::string& virtual_ip) {
    std::string dir = socket_path;
    const auto slash = dir.find_last_of('/');
    dir = slash == std::string::npos ? std::string(".") : dir.substr(0, slash);
    dir += "/clients";

    DIR* handle = ::opendir(dir.c_str());
    if (handle == nullptr) {
        return {};
    }
    const std::string prefix =
        sanitize(username) + "@" + sanitize(virtual_ip) + "@";
    std::string best_key;
    std::string best_session;
    while (dirent* entry = ::readdir(handle)) {
        const std::string name = entry->d_name;
        if (name.rfind(prefix, 0) != 0) {
            continue;
        }
        const std::string key = name.substr(prefix.size());
        if (key <= best_key) {
            continue;
        }
        const std::string session =
            read_session_marker(dir + "/" + name);
        if (!session.empty()) {
            best_key = key;
            best_session = session;
        }
    }
    ::closedir(handle);
    return best_session;
}

std::string read_session_marker(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        return {};
    }
    std::string line;
    if (!std::getline(input, line)) {
        return {};
    }
    line = trim(line);
    if (line.empty() || line.size() > 64) {
        return {};
    }
    return line;
}

} // namespace vpn