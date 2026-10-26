#include "check.hpp"
#include "mira/transport/dns_config.hpp"
#include "mira/core/platform.hpp"

using namespace Mira;
using namespace Mira::transport;
int main() {
    const auto result = parse_resolver_config(
        "# local resolver\nnameserver 127.0.0.1\nnameserver ::1 ; fallback\n"
        "nameserver 127.0.0.1\nsearch example.test sub.example.test.\n"
        "options ndots:2 timeout:3 attempts:4 rotate unknown\n");
    CHECK(result.has_value());
    if (result) {
        CHECK(result->servers.size() == 2);
        CHECK(result->servers[0] == Endpoint::loopback(53));
        CHECK(result->servers[1] == Endpoint::loopback(53, Family::ipv6));
        CHECK(result->search_domains.size() == 2);
        CHECK(result->ndots == 2 && result->timeout_seconds == 3 && result->attempts == 4 && result->rotate);
    }
    CHECK(!parse_resolver_config("nameserver example.test\n"));
    CHECK(!parse_resolver_config("nameserver 127.0.0.1 extra\n"));
    CHECK(!parse_resolver_config("nameserver\n"));
    CHECK(!parse_resolver_config("search bad..test\n"));
    CHECK(!parse_resolver_config("options timeout:0\n"));
    CHECK(!parse_resolver_config("options ndots:16\n"));
    CHECK(!parse_resolver_config("options attempts:two\n"));
    CHECK(!parse_resolver_config(std::string(65537, ' ')));
    CHECK(!parse_resolver_config(std::string("a\0b", 3)));
    CHECK(!parse_resolver_config("nameserver 127.0.0.1\nnameserver ::1", 1));
    CHECK(!parse_resolver_config("search a.test b.test", 16, 1));
    const auto override_search = parse_resolver_config("search a.test b.test\ndomain final.test");
    CHECK(override_search && override_search->search_domains == std::vector<std::string>{"final.test"});
    const auto system = system_dns_config();
    // Network configuration is environment-dependent. No configured default is
    // explicit, never an implicit public DNS fallback. Pure parsing is covered above.
    CHECK(system.has_value() || system.error() == make_error_code(Errc::not_supported));
    if (system) for (const auto& server : system->servers) CHECK(server.port() == 53);
#if MIRA_PLATFORM_ANDROID
    CHECK(!system && system.error() == make_error_code(Errc::not_supported));
#endif
    return test::summary();
}
