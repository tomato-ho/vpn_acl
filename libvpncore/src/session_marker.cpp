#include "vpn/session_marker.h"

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
                                const std::string& virtual_ip) {
    std::string dir = socket_path;
    const auto slash = dir.find_last_of('/');
    dir = slash == std::string::npos ? std::string(".") : dir.substr(0, slash);
    return dir + "/clients/" + sanitize(username) + "@" +
           sanitize(virtual_ip);
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