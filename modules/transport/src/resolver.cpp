#include "mira/transport/resolver.hpp"

// GCC 14/15 inlines the expected<vector<Endpoint>, error_code> move out of
// the job's optional and reports _M_end_of_storage (stl_vector.h:106) as
// possibly uninitialized. The value is fully constructed before it is
// stored, so this is a false positive — and because the diagnostic is
// attributed to the inlined header code rather than the co_return below, it
// can only be suppressed at file scope. GCC 16 and MinGW GCC were checked
// against the same code and do not warn.
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 14
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

#include "socket_compat.hpp"

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <list>
#include <mutex>
#include <new>
#include <stop_token>
#include <thread>
#include <utility>

namespace Mira::transport {
namespace {

class ResolverCategory final : public std::error_category {
public:
    const char* name() const noexcept override { return "Mira.resolver"; }
    std::string message(int code) const override {
#if MIRA_PLATFORM_WINDOWS
        // gai_strerrorA is uneven across Windows toolchains: the SDK copy
        // prints the WSA codes, while MinGW's returns an empty string for
        // several of them (WSATYPE_NOT_FOUND among them). A diagnostic must
        // never be empty, so a static table covers the codes getaddrinfo
        // documents before falling back to the raw value.
        if (const char* text = ::gai_strerrorA(code); text != nullptr && *text != '\0')
            return std::string{text};
        switch (code) {
        case WSAHOST_NOT_FOUND: return "host not found";
        case WSATRY_AGAIN: return "host lookup try again";
        case WSANO_RECOVERY: return "host lookup non-recoverable failure";
        case WSANO_DATA: return "name valid but no record of the requested type";
        case WSATYPE_NOT_FOUND: return "service not found for the socket type";
        case WSAEINVAL: return "invalid argument to getaddrinfo";
        case WSAESOCKTNOSUPPORT: return "socket type unsupported by getaddrinfo";
        case WSAEAFNOSUPPORT: return "address family unsupported by getaddrinfo";
        default: return "unknown getaddrinfo error " + std::to_string(code);
        }
#else
        const char* text = ::gai_strerror(code);
        return text != nullptr && *text != '\0' ? std::string{text}
                                                : "unknown getaddrinfo error";
#endif
    }
};

bool same_endpoint(const Endpoint& a, const Endpoint& b) {
    if (a.family() != b.family() || a.port() != b.port()) return false;
    if (a.family() == Family::ipv4) {
        sockaddr_in left{}, right{};
        std::memcpy(&left, a.address_bytes().data(), sizeof(left));
        std::memcpy(&right, b.address_bytes().data(), sizeof(right));
        return left.sin_addr.s_addr == right.sin_addr.s_addr;
    }
    sockaddr_in6 left{}, right{};
    std::memcpy(&left, a.address_bytes().data(), sizeof(left));
    std::memcpy(&right, b.address_bytes().data(), sizeof(right));
    return left.sin6_scope_id == right.sin6_scope_id &&
           std::memcmp(&left.sin6_addr, &right.sin6_addr, sizeof(left.sin6_addr)) == 0;
}

Result<void> append_endpoint(Resolver::Endpoints& out, Endpoint endpoint, std::size_t limit) {
    if (endpoint.address_bytes().empty()) return fail(Errc::invalid_argument);
    if (std::any_of(out.begin(), out.end(), [&](const Endpoint& other) {
            return same_endpoint(endpoint, other);
        })) return {};
    if (out.size() == limit) return fail(Errc::limit_exceeded);
    out.push_back(std::move(endpoint));
    return {};
}

Result<Resolver::Endpoints> system_resolve(const ResolveQuery& query, std::size_t limit) {
#if MIRA_PLATFORM_WINDOWS
    struct Winsock {
        bool started{false};
        ~Winsock() { if (started) ::WSACleanup(); }
    } winsock;
    WSADATA data{};
    const int startup = ::WSAStartup(MAKEWORD(2, 2), &data);
    if (startup != 0) return fail(socket_error(startup));
    winsock.started = true;
#endif
    addrinfo hints{};
    hints.ai_family = !query.family ? AF_UNSPEC :
        (*query.family == Family::ipv4 ? AF_INET : AF_INET6);
    hints.ai_socktype = query.transport == ResolveTransport::tcp ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_protocol = query.transport == ResolveTransport::tcp ? IPPROTO_TCP : IPPROTO_UDP;
    addrinfo* raw = nullptr;
    const int status = ::getaddrinfo(query.hostname.c_str(), query.service.c_str(), &hints, &raw);
#if !MIRA_PLATFORM_WINDOWS
    const int saved_errno = errno;
#endif
    const std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> addresses{raw, &::freeaddrinfo};
#if !MIRA_PLATFORM_WINDOWS
    if (status == EAI_SYSTEM) return fail(socket_error(saved_errno));
#endif
    if (status != 0) return fail(resolver_error(status));
    Resolver::Endpoints endpoints;
    for (const addrinfo* current = addresses.get(); current != nullptr; current = current->ai_next) {
        if (current->ai_family != AF_INET && current->ai_family != AF_INET6) continue;
        auto endpoint = Endpoint::from_bytes({reinterpret_cast<const std::byte*>(current->ai_addr),
                                              static_cast<std::size_t>(current->ai_addrlen)});
        if (!endpoint) return fail(endpoint.error());
        auto added = append_endpoint(endpoints, std::move(*endpoint), limit);
        if (!added) return fail(added.error());
    }
    if (endpoints.empty()) return fail(resolver_error(EAI_NONAME));
    return endpoints;
}

}  // namespace

const std::error_category& resolver_category() noexcept {
    static ResolverCategory category;
    return category;
}

Error resolver_error(int native_code) noexcept { return {native_code, resolver_category()}; }

class Resolver::Impl {
public:
    struct Waiter {
        std::mutex mutex;
        std::stop_source completion;
        bool user_cancelled{false};
        bool abandoned{false};
    };

    struct Job {
        explicit Job(ResolveQuery value) : query(std::move(value)) {}
        ResolveQuery query;
        std::mutex mutex;
        std::optional<Result<Endpoints>> result;
        // Access waiters only under State::mutex; cancellation is per waiter.
        std::vector<std::shared_ptr<Waiter>> waiters;
        bool cacheable{true};
        bool shutdown{false};
    };

    struct CacheEntry {
        ResolveQuery query;
        Result<Endpoints> result;
        Clock::time_point expires;
    };

    struct State {
        ResolverOptions options;
        Backend backend;
        std::mutex mutex;
        std::condition_variable ready;
        std::deque<std::shared_ptr<Job>> queue;
        std::vector<std::shared_ptr<Job>> active;
        std::list<CacheEntry> cache;
        bool closing{false};

        State(ResolverOptions value, Backend resolve) : options(value), backend(std::move(resolve)) {
            active.reserve(options.workers);
        }
    };

    static bool same_query(const ResolveQuery& a, const ResolveQuery& b) noexcept {
        return a.hostname == b.hostname && a.service == b.service &&
               a.family == b.family && a.transport == b.transport;
    }

    static bool waiting(const std::shared_ptr<Waiter>& waiter) {
        const std::lock_guard lock{waiter->mutex};
        return !waiter->abandoned && !waiter->user_cancelled;
    }

    static void prune_waiters(Job& job) {
        std::erase_if(job.waiters, [](const auto& waiter) { return !waiting(waiter); });
    }

    static void cache_result(State& shared, const Job& job, const Result<Endpoints>& result) {
        const auto& policy = shared.options.cache;
        auto lifetime = std::chrono::milliseconds::zero();
        if (result) lifetime = policy.positive_lifetime;
        else if (result.error() == resolver_error(EAI_NONAME)) lifetime = policy.negative_lifetime;
        if (policy.capacity == 0 || lifetime <= lifetime.zero() || shared.closing || !job.cacheable) return;
        const auto now = Clock::now();
        std::erase_if(shared.cache, [&](const auto& entry) {
            return entry.expires <= now || same_query(entry.query, job.query);
        });
        // Cache allocation failure must not lose a completed result or kill a worker.
        try {
            shared.cache.push_front({job.query, result, now + lifetime});
            while (shared.cache.size() > policy.capacity) shared.cache.pop_back();
        } catch (const std::bad_alloc&) {
        }
    }

    std::shared_ptr<State> state;
    std::vector<std::thread> threads;

    Impl(ResolverOptions options, Backend backend)
        : state(std::make_shared<State>(options, backend ? std::move(backend) : system_resolve)) {
        threads.reserve(options.workers);
        try {
            for (std::size_t i = 0; i < options.workers; ++i) {
                threads.emplace_back([shared = state] { work(shared); });
            }
        } catch (...) {
            close();
            throw;
        }
    }

    ~Impl() { close(); }

    void close() noexcept {
        {
            const std::lock_guard lock{state->mutex};
            state->closing = true;
            // The completion callbacks only post cancellation; they never
            // synchronously resume coroutines or take the State lock.
            for (const auto& job : state->queue) close_job(job);
            for (const auto& job : state->active) close_job(job);
            state->queue.clear();
        }
        state->ready.notify_all();
        for (auto& thread : threads) if (thread.joinable()) thread.join();
    }

    static void close_job(const std::shared_ptr<Job>& job) noexcept {
        {
            const std::lock_guard lock{job->mutex};
            job->shutdown = true;
        }
        for (const auto& waiter : job->waiters) waiter->completion.request_stop();
    }

    static void work(const std::shared_ptr<State>& shared) noexcept {
        for (;;) {
            std::shared_ptr<Job> job;
            {
                std::unique_lock lock{shared->mutex};
                shared->ready.wait(lock, [&] { return shared->closing || !shared->queue.empty(); });
                if (shared->closing) return;
                job = std::move(shared->queue.front());
                shared->queue.pop_front();
                shared->active.push_back(job);
            }
            bool skip = false;
            {
                const std::lock_guard lock{shared->mutex};
                prune_waiters(*job);
                skip = shared->closing || job->waiters.empty();
                if (skip) std::erase(shared->active, job);
            }
            if (skip) continue;
            {
                Result<Endpoints> result = fail(std::make_error_code(std::errc::io_error));
                try {
                    result = shared->backend(job->query, shared->options.max_results);
                    if (result) {
                        Endpoints unique;
                        for (auto& endpoint : *result) {
                            auto added = append_endpoint(unique, std::move(endpoint), shared->options.max_results);
                            if (!added) {
                                result = fail(added.error());
                                break;
                            }
                        }
                        if (result) {
                            if (unique.empty()) result = fail(resolver_error(EAI_NONAME));
                            else result = std::move(unique);
                        }
                    }
                } catch (const std::bad_alloc&) {
                    result = fail(std::make_error_code(std::errc::not_enough_memory));
                } catch (...) {
                    result = fail(std::make_error_code(std::errc::io_error));
                }
                const std::lock_guard state_lock{shared->mutex};
                {
                    const std::lock_guard job_lock{job->mutex};
                    if (!job->shutdown) {
                        cache_result(*shared, *job, result);
                        job->result.emplace(std::move(result));
                    }
                }
                for (const auto& waiter : job->waiters) waiter->completion.request_stop();
                std::erase(shared->active, job);
            }
        }
    }

    static Task<Result<Endpoints>> resolve(std::shared_ptr<State> shared, EventLoop& loop,
                                           ResolveQuery query, OperationOptions options) {
        if (options.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (options.deadline && *options.deadline <= Clock::now()) co_return fail(Errc::timed_out);
        if (query.hostname.empty() || query.service.empty() || query.hostname.size() > 4096 ||
            query.service.size() > 4096 || query.hostname.find('\0') != std::string::npos ||
            query.service.find('\0') != std::string::npos ||
            (query.family && *query.family != Family::ipv4 && *query.family != Family::ipv6) ||
            (query.transport != ResolveTransport::tcp && query.transport != ResolveTransport::udp)) {
            co_return fail(Errc::invalid_argument);
        }
        if (!shared) co_return fail(Errc::cancelled);
        auto waiter = std::make_shared<Waiter>();
        struct WaitGuard {
            std::shared_ptr<Waiter> waiter;
            ~WaitGuard() {
                const std::lock_guard lock{waiter->mutex};
                waiter->abandoned = true;
            }
        } guard{waiter};
        std::shared_ptr<Job> job;
        std::stop_callback user_cancel{options.stop, [waiter] {
            {
                const std::lock_guard lock{waiter->mutex};
                waiter->user_cancelled = true;
            }
            waiter->completion.request_stop();
        }};
        {
            const std::lock_guard lock{shared->mutex};
            if (shared->closing) co_return fail(Errc::cancelled);
            const auto now = Clock::now();
            std::erase_if(shared->cache, [&](const auto& entry) { return entry.expires <= now; });
            const auto cached = std::find_if(shared->cache.begin(), shared->cache.end(),
                [&](const auto& entry) { return same_query(query, entry.query); });
            if (cached != shared->cache.end()) {
                shared->cache.splice(shared->cache.begin(), shared->cache, cached);
                co_return shared->cache.front().result;
            }
            std::erase_if(shared->queue, [](const auto& pending) {
                prune_waiters(*pending);
                return pending->waiters.empty();
            });
            if (shared->options.deduplicate_in_flight) {
                for (const auto& pending : shared->queue)
                    if (same_query(query, pending->query)) { job = pending; break; }
                if (!job) for (const auto& pending : shared->active)
                    if (same_query(query, pending->query)) { job = pending; break; }
            }
            if (job) {
                prune_waiters(*job);
                if (job->waiters.size() >= shared->options.max_waiters_per_query)
                    co_return fail(Errc::limit_exceeded);
                job->waiters.push_back(waiter);
            } else {
                if (shared->queue.size() >= shared->options.queue_capacity)
                    co_return fail(Errc::limit_exceeded);
                job = std::make_shared<Job>(std::move(query));
                job->waiters.push_back(waiter);
                shared->queue.push_back(job);
            }
        }
        shared->ready.notify_one();
        const auto waited = co_await loop.sleep_until(Clock::time_point::max(),
            {.stop = waiter->completion.get_token(), .deadline = options.deadline});
        bool user_cancelled = false;
        {
            const std::lock_guard lock{waiter->mutex};
            waiter->abandoned = true;
            user_cancelled = waiter->user_cancelled;
        }
        const std::lock_guard lock{job->mutex};
        if (job->result) co_return *job->result;
        if (user_cancelled) co_return fail(Errc::cancelled);
        if (!waited && waited.error() == Errc::timed_out) co_return fail(Errc::timed_out);
        co_return fail(Errc::cancelled);
    }
};

Result<Resolver> Resolver::create(ResolverOptions options, Backend backend) {
    if (options.workers == 0 || options.workers > 64 || options.queue_capacity == 0 ||
        options.queue_capacity > 65536 || options.max_results == 0 || options.max_results > 4096 ||
        options.max_waiters_per_query == 0 || options.max_waiters_per_query > 65536 ||
        options.cache.capacity > 65536 || options.cache.positive_lifetime.count() < 0 ||
        options.cache.negative_lifetime.count() < 0 ||
        options.cache.positive_lifetime > std::chrono::hours{24 * 365} ||
        options.cache.negative_lifetime > std::chrono::hours{24 * 365}) {
        return fail(Errc::invalid_argument);
    }
    try {
        return Resolver{std::make_unique<Impl>(options, std::move(backend))};
    } catch (const std::system_error& error) {
        return fail(error.code());
    } catch (const std::bad_alloc&) {
        return fail(std::make_error_code(std::errc::not_enough_memory));
    }
}

Resolver::Resolver(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Resolver::Resolver(Resolver&&) noexcept = default;
Resolver& Resolver::operator=(Resolver&&) noexcept = default;
Resolver::~Resolver() = default;

void Resolver::clear_cache() {
    if (!impl_) return;
    const auto& state = impl_->state;
    const std::lock_guard lock{state->mutex};
    state->cache.clear();
    for (const auto& job : state->queue) job->cacheable = false;
    for (const auto& job : state->active) job->cacheable = false;
}

Task<Result<Resolver::Endpoints>> Resolver::resolve(EventLoop& loop, ResolveQuery query,
                                                    OperationOptions options) {
    // The non-coroutine wrapper holds the state at call time, so a lazily
    // started Task never dereferences a destroyed this.
    return Impl::resolve(impl_ ? impl_->state : nullptr, loop, std::move(query), std::move(options));
}

}  // namespace Mira::transport
