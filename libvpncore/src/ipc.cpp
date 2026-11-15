#include "vpn/ipc.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace vpn {
namespace {

constexpr std::size_t kMaxLine = 8192;
constexpr std::size_t kMaxFields = 128;

bool has_bad_chars(const std::string& value) {
    return value.find('\n') != std::string::npos ||
           value.find('\r') != std::string::npos;
}

bool write_all(int fd, const std::string& data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t written =
            ::send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
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

bool read_line(int fd, std::string* line) {
    line->clear();
    char ch = 0;
    while (line->size() < kMaxLine) {
        const ssize_t received = ::read(fd, &ch, 1);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (received == 0) {
            return false;
        }
        if (ch == '\n') {
            if (!line->empty() && line->back() == '\r') {
                line->pop_back();
            }
            return true;
        }
        line->push_back(ch);
    }
    return false;
}

void set_timeouts(int fd, int timeout_seconds) {
    timeval timeout{};
    timeout.tv_sec = timeout_seconds > 0 ? timeout_seconds : 1;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

bool connect_socket(const std::string& path,
                    int* fd,
                    std::string* error,
                    int timeout_seconds) {
    if (path.size() + 1 >= sizeof(sockaddr_un::sun_path)) {
        if (error) {
            *error = "socket path is too long";
        }
        return false;
    }

    const int socket_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        if (error) {
            *error = std::string("socket failed: ") + std::strerror(errno);
        }
        return false;
    }
    set_timeouts(socket_fd, timeout_seconds);

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);

    if (::connect(socket_fd, reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) != 0) {
        if (error) {
            *error = std::string("connect failed: ") + std::strerror(errno);
        }
        ::close(socket_fd);
        return false;
    }

    *fd = socket_fd;
    return true;
}

} // namespace

bool ipc_request(const std::string& socket_path,
                 const std::string& command,
                 const IpcFields& fields,
                 std::string* response,
                 std::string* error,
                 int timeout_seconds) {
    if (command.empty() || has_bad_chars(command)) {
        if (error) {
            *error = "invalid command";
        }
        return false;
    }
    for (const auto& entry : fields) {
        if (entry.first.empty() || has_bad_chars(entry.first) ||
            has_bad_chars(entry.second)) {
            if (error) {
                *error = "invalid request field";
            }
            return false;
        }
    }

    int fd = -1;
    if (!connect_socket(socket_path, &fd, error, timeout_seconds)) {
        return false;
    }

    std::string payload = command + "\n";
    for (const auto& entry : fields) {
        payload += entry.first;
        payload += '=';
        payload += entry.second;
        payload += '\n';
    }
    payload += "END\n";

    if (!write_all(fd, payload)) {
        if (error) {
            *error = std::string("write failed: ") + std::strerror(errno);
        }
        ::close(fd);
        return false;
    }

    std::string reply;
    if (!read_line(fd, &reply)) {
        if (error) {
            *error = "failed to read response";
        }
        ::close(fd);
        return false;
    }
    ::close(fd);

    if (reply == "OK") {
        if (response) {
            response->clear();
        }
        return true;
    }
    if (reply.rfind("OK ", 0) == 0) {
        if (response) {
            *response = reply.substr(3);
        }
        return true;
    }
    if (response) {
        *response = reply;
    }
    if (error) {
        if (reply.rfind("ERR ", 0) == 0) {
            *error = reply.substr(4);
        } else {
            *error = "unexpected response: " + reply;
        }
    }
    return false;
}

bool ipc_read_block(int fd,
                    std::string* command,
                    IpcFields* fields,
                    std::string* error) {
    std::string line;
    if (!read_line(fd, &line) || line.empty()) {
        if (error) {
            *error = "missing command";
        }
        return false;
    }
    *command = line;
    fields->clear();

    std::size_t count = 0;
    while (true) {
        if (!read_line(fd, &line)) {
            if (error) {
                *error = "failed to read request block";
            }
            return false;
        }
        if (line == "END") {
            return true;
        }
        if (line.empty()) {
            continue;
        }
        const auto equal = line.find('=');
        if (equal == std::string::npos) {
            if (error) {
                *error = "invalid request line";
            }
            return false;
        }
        if (++count > kMaxFields) {
            if (error) {
                *error = "too many request fields";
            }
            return false;
        }
        (*fields)[line.substr(0, equal)] = line.substr(equal + 1);
    }
}

bool ipc_write_response(int fd, bool ok, const std::string& message) {
    std::string response;
    if (ok) {
        response = message.empty() ? "OK\n" : "OK " + message + "\n";
    } else {
        response = "ERR " + message + "\n";
    }
    return write_all(fd, response);
}

} // namespace vpn