#pragma once

#include "mira/transport/endpoint.hpp"
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace Mira::transport {

struct DnsServerConfig {
    std::vector<Endpoint> servers;
    std::vector<std::string> search_domains;
    unsigned ndots{1};
    unsigned timeout_seconds{5};
    unsigned attempts{2};
    bool rotate{false};
};

/// Parse a bounded resolv.conf snapshot. Numeric nameservers only, no network
/// lookups. Reject malformed known directives rather than choosing an implicit
/// public resolver. Unknown directives are ignored; maxima bound allocations.
[[nodiscard]] Result<DnsServerConfig> parse_resolver_config(std::string_view text,
    std::size_t max_servers = 16, std::size_t max_search_domains = 16);

/// Read a point-in-time default DNS-server configuration outside the event loop.
/// Apple uses a private res_state, Windows enumerates active adapter DNS servers,
/// Linux/BSD read resolv.conf. This is not split-DNS/VPN/per-network routing:
/// use Resolver::resolve for native NSS and scoped system policy. Android apps
/// must supply their current Network/LinkProperties DNS list; this call returns
/// not_supported instead of using undocumented properties or a public fallback.
[[nodiscard]] Result<DnsServerConfig> system_dns_config();

}  // namespace Mira::transport
