#pragma once

#include <map>
#include <string>

namespace vpn {

using IpcFields = std::map<std::string, std::string>;

bool ipc_request(const std::string& socket_path,
                 const std::string& command,
                 const IpcFields& fields,
                 std::string* response,
                 std::string* error,
                 int timeout_seconds = 5);

bool ipc_read_block(int fd,
                    std::string* command,
                    IpcFields* fields,
                    std::string* error);

bool ipc_write_response(int fd, bool ok, const std::string& message);

} // namespace vpn