// UDP DNS with automatic TCP fallback, against in-memory fakes.
//
// No sockets: the sandbox blocks UDP, so a fallback test that dials real
// sockets would fail for environmental reasons. The fakes below answer from
// whatever query they receive (preserving its transaction ID), which is
// exactly the property the fallback relies on.

#include "check.hpp"
#include "mira/core/event_loop.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/dns/fallback.hpp"

#include <algorithm>

using namespace Mira;
using namespace Mira::dns;
using namespace std::chrono_literals;

namespace {

OperationOptions budget() { return {.deadline = Clock::now() + 5s}; }
Message question() { return make_query(Name::parse("example.test").value(), type::a).value(); }

Message answer_for(const Message& query, bool tc) {
    Message response = query;
    response.header.qr = true;
    response.header.tc = tc;
    response.answers.push_back(
        {query.questions.front().name, type::a, class_in, 30, AData{{127, 0, 0, 1}}});
    return response;
}

struct Packet {
    std::size_t size;
    std::string peer;
};

// Scripted UDP peer: answers whatever query it receives, in the configured
// mode. Mode 3 never answers, so the helper sees a timeout instead.
struct FakeDatagram {
    int mode = 0;  // 0 normal, 1 truncated, 2 nxdomain, 3 silent
    std::vector<std::byte> last_sent{};
    Task<Result<std::size_t>> send_to(std::span<const std::byte> out, std::string, OperationOptions = {}) {
        last_sent.assign(out.begin(), out.end());
        co_return out.size();
    }
    Task<Result<Packet>> receive_from(std::span<std::byte> in, OperationOptions = {}) {
        if (mode == 3) co_return fail(Errc::timed_out);
        auto query = decode(last_sent);
        if (!query) co_return fail(query.error());
        auto response = answer_for(*query, mode == 1);
        if (mode == 2) {
            response.header.rcode = rcode::nxdomain;
            response.answers.clear();
        }
        auto wire = encode(response);
        if (!wire) co_return fail(wire.error());
        if (wire->size() > in.size()) co_return fail(DnsError::too_large);
        std::copy(wire->begin(), wire->end(), in.begin());
        co_return Packet{wire->size(), "server"};
    }
};

// TCP peer that builds its length-prefixed response from the query it was
// sent, so the transaction ID always matches even though query_tcp
// re-randomizes it. Mode 1 answers with a wrong ID (mismatched response).
struct FakeTcpStream {
    int mode = 0;  // 0 normal, 1 mismatched
    std::vector<std::byte> outbound{};
    std::vector<std::byte> inbound{};
    std::size_t pos = 0;
    bool built = false;
    Task<Result<std::size_t>> write_some(std::span<const std::byte> data, OperationOptions = {}) {
        outbound.insert(outbound.end(), data.begin(), data.end());
        co_return data.size();
    }
    Task<Result<std::size_t>> read_some(std::span<std::byte> out, OperationOptions = {}) {
        if (!built) {
            if (outbound.size() < 2) co_return fail(Errc::eof);
            const std::size_t size =
                (std::to_integer<std::size_t>(outbound[0]) << 8) | std::to_integer<std::size_t>(outbound[1]);
            if (outbound.size() < 2 + size) co_return fail(Errc::eof);
            auto query = decode(std::span<const std::byte>{outbound}.subspan(2, size));
            if (!query) co_return fail(query.error());
            auto response = answer_for(*query, false);
            if (mode == 1)
                response.header.id = static_cast<std::uint16_t>(response.header.id + 1);
            auto wire = encode(response);
            if (!wire) co_return fail(wire.error());
            inbound.push_back(static_cast<std::byte>(wire->size() >> 8));
            inbound.push_back(static_cast<std::byte>(wire->size() & 255U));
            inbound.insert(inbound.end(), wire->begin(), wire->end());
            built = true;
        }
        const auto count = std::min(out.size(), inbound.size() - pos);
        std::copy_n(inbound.begin() + static_cast<std::ptrdiff_t>(pos), count, out.begin());
        pos += count;
        co_return count;
    }
};

Task<void> exercise() {
    test::section("fallback only on truncation; other UDP failures pass through");
    {
        FakeDatagram udp;
        bool connected = false;
        auto connect = [&](OperationOptions) -> Task<Result<FakeTcpStream>> {
            connected = true;
            co_return FakeTcpStream{};
        };
        const auto response = co_await query_with_tcp_fallback(udp, std::string{"server"}, connect, question(), budget());
        CHECK(response.has_value() && response->answers.size() == 1 && !response->header.tc);
        CHECK(!connected);
    }
    {
        FakeDatagram udp{.mode = 2};
        bool connected = false;
        auto connect = [&](OperationOptions) -> Task<Result<FakeTcpStream>> {
            connected = true;
            co_return FakeTcpStream{};
        };
        const auto response = co_await query_with_tcp_fallback(udp, std::string{"server"}, connect, question(), budget());
        CHECK(response.has_value() && response->header.rcode == rcode::nxdomain);
        CHECK(!connected);
    }
    {
        FakeDatagram udp{.mode = 3};
        bool connected = false;
        auto connect = [&](OperationOptions) -> Task<Result<FakeTcpStream>> {
            connected = true;
            co_return FakeTcpStream{};
        };
        const auto response = co_await query_with_tcp_fallback(udp, std::string{"server"}, connect, question(), budget());
        CHECK(!response && response.error() == Errc::timed_out);
        CHECK(!connected);
    }

    test::section("truncation retries over TCP and returns the full answer");
    {
        FakeDatagram udp{.mode = 1};
        bool connected = false;
        auto connect = [&](OperationOptions) -> Task<Result<FakeTcpStream>> {
            connected = true;
            co_return FakeTcpStream{};
        };
        const auto response = co_await query_with_tcp_fallback(udp, std::string{"server"}, connect, question(), budget());
        CHECK(response.has_value() && response->answers.size() == 1 && !response->header.tc);
        CHECK(connected);
    }

    test::section("TCP-phase failures replace the truncation error");
    {
        FakeDatagram udp{.mode = 1};
        auto refuse = [](OperationOptions) -> Task<Result<FakeTcpStream>> {
            co_return fail(std::make_error_code(std::errc::connection_refused));
        };
        const auto response = co_await query_with_tcp_fallback(udp, std::string{"server"}, refuse, question(), budget());
        CHECK(!response && response.error() == std::make_error_code(std::errc::connection_refused));
    }
    {
        FakeDatagram udp{.mode = 1};
        auto mismatch = [](OperationOptions) -> Task<Result<FakeTcpStream>> {
            co_return FakeTcpStream{.mode = 1};
        };
        const auto response =
            co_await query_with_tcp_fallback(udp, std::string{"server"}, mismatch, question(), budget());
        CHECK(!response && response.error() == DnsError::mismatched_response);
    }
}

Task<void> root() { co_await exercise(); }

}  // namespace

int main() {
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (loop) {
        CHECK(loop->run_until_complete(root()).has_value());
        CHECK(loop->outstanding() == 0);
    }
    return test::summary();
}
