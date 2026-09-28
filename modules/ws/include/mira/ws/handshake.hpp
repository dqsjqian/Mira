#pragma once

#include "mira/ws/frame.hpp"
#include <string>
#include <string_view>

namespace Mira::ws {

struct ClientHandshake {
    std::string request;
    std::string key;
};

Result<std::string> accept_key(std::string_view key);
Result<ClientHandshake> client_handshake(std::string_view host, std::string_view target = "/");
Result<std::string> server_handshake(std::string_view request, Limits limits = {});
Result<void> validate_server_handshake(std::string_view response, std::string_view key,
                                       Limits limits = {});

} // namespace Mira::ws
