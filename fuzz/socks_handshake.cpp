// Drive both SOCKS5 roles over scripted bytes: never crash, never over-read.
#include "mira/core/event_loop.hpp"
#include "mira/socks/socks5.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string_view>

namespace {
struct Script {
    std::string_view input;
    std::size_t cursor = 0;
    std::size_t step = 1;
    Mira::Task<Mira::Result<std::size_t>> read_some(std::span<std::byte> into,
                                                    Mira::OperationOptions = {}) {
        if (cursor == input.size()) co_return Mira::fail(Mira::Errc::eof);
        const auto n = std::min({into.size(), input.size() - cursor, step});
        std::memcpy(into.data(), input.data() + cursor, n);
        cursor += n;
        co_return n;
    }
    Mira::Task<Mira::Result<std::size_t>> write_some(std::span<const std::byte> from,
                                                     Mira::OperationOptions = {}) {
        co_return from.size();
    }
};

Mira::Task<void> drive(std::string_view input) {
    const std::size_t step = input.empty() ? 1 : (static_cast<unsigned char>(input[0]) % 7) + 1;
    {
        Script peer{input, 0, step};
        Mira::socks::ServerOptions options;
        options.allow_no_auth = true;
        options.verify = [](std::string_view u, std::string_view) { return u == "u"; };
        const auto request = co_await Mira::socks::accept(peer, options);
        if (peer.cursor > input.size()) std::abort();
        if (request && request->target.kind() == Mira::socks::Address::Kind::domain &&
            request->target.name().empty())
            std::abort();
    }
    {
        Script peer{input, 0, step};
        Mira::socks::ClientOptions options;
        options.credentials = Mira::socks::Credentials{"user", "pass"};
        auto target = Mira::socks::Address::domain("example.com", 443);
        const auto reply = co_await Mira::socks::connect(peer, *target, options);
        if (peer.cursor > input.size()) std::abort();
        if (reply && reply->code != Mira::socks::ReplyCode::succeeded) std::abort();
    }
    if (input.size() <= 300) {
        auto parsed = Mira::socks::Address::parse(input, 1);
        if (parsed) {
            auto again = Mira::socks::Address::parse(parsed->host(), 1);
            if (!again || *again != *parsed) std::abort();
        }
    }
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 4096) return 0;
    static auto loop = Mira::EventLoop::create();
    if (!loop) std::abort();
    const std::string_view input(reinterpret_cast<const char*>(data), size);
    if (!loop->run_until_complete(drive(input))) std::abort();
    return 0;
}
