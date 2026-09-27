#pragma once

#include "mira/core/event_loop.hpp"
#include "mira/transport/endpoint.hpp"

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Mira::transport {

enum class ResolveTransport { tcp, udp };

struct ResolveQuery {
    std::string hostname;
    std::string service;
    std::optional<Family> family{};
    ResolveTransport transport{ResolveTransport::tcp};
};

struct ResolverOptions {
    std::size_t workers{2};
    std::size_t queue_capacity{64};
    std::size_t max_results{64};
};

/// getaddrinfo EAI_* errors are independent of errno/Winsock socket errors.
/// When a POSIX system resolve returns EAI_SYSTEM, resolve instead returns the
/// socket_error for the errno value observed at that moment.
[[nodiscard]] const std::error_category& resolver_category() noexcept;
[[nodiscard]] Error resolver_error(int native_code) noexcept;

/// Fixed-size thread-pool system resolver; performs no DNS caching, retries,
/// or endpoint connection selection. Cancellation/timeout only ends the wait
/// and cannot interrupt a system getaddrinfo already entered. The destructor
/// cancels all waits and joins the worker threads, possibly waiting for the
/// system call to return; it never detaches. resolve must be called on the
/// corresponding loop thread; do not move/destroy concurrently with member
/// calls. A started wait holds independent state, so another thread may
/// destroy the Resolver and block in join.
class Resolver {
public:
    using Endpoints = std::vector<Endpoint>;
    /// Injectable synchronous resolve function, invoked on the thread pool; it
    /// must be thread-safe and must not access the loop. max_results is the
    /// output cap; the framework still deduplicates/validates/clamps returned
    /// values. The internal memory and execution duration of a custom Backend
    /// are the caller's responsibility to bound.
    using Backend = std::function<Result<Endpoints>(const ResolveQuery&, std::size_t max_results)>;

    [[nodiscard]] static Result<Resolver> create(ResolverOptions options = {}, Backend backend = {});
    Resolver(Resolver&&) noexcept;
    Resolver& operator=(Resolver&&) noexcept;
    Resolver(const Resolver&) = delete;
    Resolver& operator=(const Resolver&) = delete;
    ~Resolver();

    /// Parameters are owned by value; empty hostname/service, embedded NUL, or
    /// sizes over 4096 bytes are all rejected. Still counts toward
    /// loop.outstanding() when no other work exists; completion is delivered
    /// only on the loop thread. Before submission: stop > deadline > parameter
    /// validation; at delivery: published result > user cancellation > timer
    /// timeout > resolver/loop shutdown (cancelled). Exceeding the result limit
    /// yields limit_exceeded. A Task may start after the Resolver is destroyed,
    /// but the EventLoop must live until the wait begins.
    [[nodiscard]] Task<Result<Endpoints>> resolve(EventLoop& loop, ResolveQuery query,
                                                 OperationOptions options = {});

private:
    class Impl;
    explicit Resolver(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

}  // namespace Mira::transport
