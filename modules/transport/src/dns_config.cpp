#include "mira/transport/dns_config.hpp"
#include "socket_compat.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <sstream>
#if MIRA_PLATFORM_APPLE
#include <resolv.h>
#elif MIRA_PLATFORM_WINDOWS
#include <iphlpapi.h>
#endif

namespace Mira::transport {
namespace {
Result<void> add_server(DnsServerConfig& config, Endpoint value, std::size_t maximum) {
    if (std::find(config.servers.begin(), config.servers.end(), value) != config.servers.end()) return {};
    if (config.servers.size() >= maximum) return fail(Errc::limit_exceeded);
    config.servers.push_back(std::move(value));
    return {};
}
bool valid_domain(std::string_view value) {
    if (value.empty() || value.size() > 253) return false;
    if (value.back() == '.') value.remove_suffix(1);
    while (!value.empty()) {
        const auto dot = value.find('.');
        const auto label = value.substr(0, dot);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
        for (char c : label)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
        if (dot == std::string_view::npos) break;
        value.remove_prefix(dot + 1);
    }
    return true;
}
}  // namespace

Result<DnsServerConfig> parse_resolver_config(std::string_view text, std::size_t max_servers,
                                             std::size_t max_search_domains) {
    if (text.size() > 64 * 1024 || max_servers == 0 || max_servers > 256 ||
        max_search_domains == 0 || max_search_domains > 256 || text.find('\0') != std::string_view::npos)
        return fail(Errc::invalid_argument);
    DnsServerConfig config;
    std::istringstream input{std::string{text}};
    std::string line;
    while (std::getline(input, line)) {
        line.erase(line.find_first_of("#;") == std::string::npos ? line.size() : line.find_first_of("#;"));
        std::istringstream fields{line};
        std::string directive, value;
        if (!(fields >> directive)) continue;
        if (directive == "nameserver") {
            std::string extra;
            if (!(fields >> value) || (fields >> extra)) return fail(Errc::invalid_argument);
            auto endpoint = Endpoint::parse(value, 53);
            if (!endpoint) return fail(endpoint.error());
            auto added = add_server(config, *endpoint, max_servers);
            if (!added) return fail(added.error());
        } else if (directive == "search" || directive == "domain") {
            config.search_domains.clear();
            while (fields >> value) {
                if (!valid_domain(value)) return fail(Errc::invalid_argument);
                if (config.search_domains.size() == max_search_domains) return fail(Errc::limit_exceeded);
                config.search_domains.push_back(value);
            }
            if (config.search_domains.empty() || (directive == "domain" && config.search_domains.size() != 1))
                return fail(Errc::invalid_argument);
        } else if (directive == "options") {
            while (fields >> value) {
                if (value == "rotate") { config.rotate = true; continue; }
                const auto colon = value.find(':');
                if (colon == std::string::npos) continue;
                const auto key = value.substr(0, colon);
                if (key != "ndots" && key != "timeout" && key != "attempts") continue;
                unsigned number = 0;
                const auto part = std::string_view{value}.substr(colon + 1);
                auto [end, error] = std::from_chars(part.data(), part.data() + part.size(), number);
                if (error != std::errc{} || end != part.data() + part.size() ||
                    number > (key == "ndots" ? 15U : key == "timeout" ? 30U : 5U) ||
                    (key != "ndots" && number == 0)) return fail(Errc::invalid_argument);
                if (key == "ndots") config.ndots = number;
                else if (key == "timeout") config.timeout_seconds = number;
                else config.attempts = number;
            }
        }
    }
    return config;
}

Result<DnsServerConfig> system_dns_config() {
#if MIRA_PLATFORM_ANDROID
    return fail(Errc::not_supported);
#elif MIRA_PLATFORM_APPLE
    struct State {
        struct __res_state value{};
        bool ready{false};
        ~State() { if (ready) ::res_ndestroy(&value); }
    } state;
    if (::res_ninit(&state.value) != 0) return fail(Errc::not_supported);
    state.ready = true;
    std::array<union res_sockaddr_union, 16> servers{};
    const int count = ::res_getservers(&state.value, servers.data(), static_cast<int>(servers.size()));
    if (count <= 0 || count > static_cast<int>(servers.size())) return fail(Errc::not_supported);
    DnsServerConfig config;
    for (int i = 0; i < count; ++i) {
        const auto& server = servers[static_cast<std::size_t>(i)];
        const auto size = server.sin.sin_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        auto endpoint = Endpoint::from_bytes({reinterpret_cast<const std::byte*>(&server), size});
        if (!endpoint) return fail(endpoint.error());
        auto added = add_server(config, *endpoint, servers.size());
        if (!added) return fail(added.error());
    }
    for (const auto* domain : state.value.dnsrch)
        if (domain && *domain && valid_domain(domain)) config.search_domains.emplace_back(domain);
    config.ndots = state.value.ndots;
    return config;
#elif MIRA_PLATFORM_WINDOWS
    ULONG size = 16 * 1024;
    std::vector<std::byte> storage(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    ULONG result = ::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
        nullptr, adapters, &size);
    if (result == ERROR_BUFFER_OVERFLOW && size <= 1024 * 1024) {
        storage.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
        result = ::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            nullptr, adapters, &size);
    }
    if (result != NO_ERROR) return fail(socket_error(static_cast<int>(result)));
    DnsServerConfig config;
    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;
        for (auto* dns = adapter->FirstDnsServerAddress; dns; dns = dns->Next) {
            auto endpoint = Endpoint::from_bytes({reinterpret_cast<const std::byte*>(dns->Address.lpSockaddr),
                static_cast<std::size_t>(dns->Address.iSockaddrLength)});
            if (!endpoint) continue;
            auto with_port = Endpoint::parse(endpoint->address(), 53);
            if (!with_port) return fail(with_port.error());
            auto added = add_server(config, *with_port, 16);
            if (!added) return fail(added.error());
        }
    }
    if (config.servers.empty()) return fail(Errc::not_supported);
    return config;
#else
    std::ifstream input{"/etc/resolv.conf", std::ios::binary};
    if (!input) return fail(Errc::not_supported);
    std::string text(64 * 1024 + 1, '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    text.resize(static_cast<std::size_t>(input.gcount()));
    if (text.size() > 64 * 1024) return fail(Errc::limit_exceeded);
    auto config = parse_resolver_config(text);
    if (!config) return fail(config.error());
    if (config->servers.empty()) return fail(Errc::not_supported);
    return config;
#endif
}
}  // namespace Mira::transport
