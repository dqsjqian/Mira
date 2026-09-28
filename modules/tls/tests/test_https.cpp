#include "check.hpp"
#include "mira/http/connection.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/tls/context.hpp"
#include "mira/tls/error.hpp"
#include "mira/tls/stream.hpp"
#include "mira/transport/tcp.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace Mira;
using namespace Mira::transport;
using namespace std::chrono_literals;

namespace {

std::span<const std::byte> bytes_of(std::string_view text) {
    return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

void require(bool condition) {
    if (!condition) {
        throw std::runtime_error("TLS test certificate generation failed");
    }
}

using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;

Key generate_key() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context{
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free};
    require(context != nullptr);
    require(EVP_PKEY_keygen_init(context.get()) == 1);
    require(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), NID_X9_62_prime256v1) == 1);
    EVP_PKEY* raw = nullptr;
    require(EVP_PKEY_keygen(context.get(), &raw) == 1);
    return Key{raw, EVP_PKEY_free};
}

void extension(X509* certificate, X509* issuer, int nid, const char* value) {
    X509V3_CTX context{};
    X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext{
        X509V3_EXT_conf_nid(nullptr, &context, nid, value), X509_EXTENSION_free};
    require(ext != nullptr);
    require(X509_add_ext(certificate, ext.get(), -1) == 1);
}

Certificate generate_certificate(EVP_PKEY* key,
                                 std::string_view common_name,
                                 long serial,
                                 X509* issuer = nullptr,
                                 EVP_PKEY* issuer_key = nullptr,
                                 const char* ext_key_usage = "serverAuth") {
    Certificate certificate{X509_new(), X509_free};
    require(certificate != nullptr);
    require(X509_set_version(certificate.get(), 2) == 1);
    require(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) == 1);
    require(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -3600) != nullptr);
    require(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400) != nullptr);
    require(X509_set_pubkey(certificate.get(), key) == 1);
    X509_NAME* subject = X509_get_subject_name(certificate.get());
    require(X509_NAME_add_entry_by_txt(subject,
                                       "CN",
                                       MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char*>(common_name.data()),
                                       static_cast<int>(common_name.size()),
                                       -1,
                                       0) == 1);
    require(X509_set_issuer_name(certificate.get(),
                                 issuer != nullptr ? X509_get_subject_name(issuer) : subject) == 1);
    X509* authority = issuer != nullptr ? issuer : certificate.get();
    extension(certificate.get(),
              authority,
              NID_basic_constraints,
              issuer != nullptr ? "critical,CA:FALSE" : "critical,CA:TRUE,pathlen:0");
    extension(certificate.get(),
              authority,
              NID_key_usage,
              issuer != nullptr ? "critical,digitalSignature" : "critical,keyCertSign,cRLSign");
    extension(certificate.get(), authority, NID_subject_key_identifier, "hash");
    if (issuer != nullptr) {
        extension(certificate.get(), authority, NID_authority_key_identifier, "keyid:always");
        extension(certificate.get(), authority, NID_ext_key_usage, ext_key_usage);
        extension(certificate.get(), authority, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1");
    }
    require(X509_sign(certificate.get(), issuer_key != nullptr ? issuer_key : key, EVP_sha256()) >
            0);
    return certificate;
}

struct Certificates {
    std::filesystem::path directory;
    std::vector<std::filesystem::path> files;
    std::string ca;
    std::string other_ca;
    std::string server;
    std::string key;
    std::string client;
    std::string client_key;

    ~Certificates() {
        std::error_code ignored;
        for (const auto& file : files) {
            std::filesystem::remove(file, ignored);
        }
        if (!directory.empty()) {
            std::filesystem::remove(directory, ignored);
        }
    }

    std::string write(std::string_view name, X509* certificate, EVP_PKEY* private_key = nullptr) {
        const auto path = directory / name;
        files.push_back(path);
        std::unique_ptr<BIO, decltype(&BIO_free)> output{BIO_new_file(path.string().c_str(), "w"),
                                                         BIO_free};
        require(output != nullptr);
        if (private_key != nullptr) {
            require(PEM_write_bio_PrivateKey(
                        output.get(), private_key, nullptr, nullptr, 0, nullptr, nullptr) == 1);
        } else {
            require(PEM_write_bio_X509(output.get(), certificate) == 1);
        }
        return path.string();
    }

    void create() {
        std::array<unsigned char, 12> random{};
        require(RAND_bytes(random.data(), static_cast<int>(random.size())) == 1);
        constexpr char hex[] = "0123456789abcdef";
        std::string suffix;
        for (auto value : random) {
            suffix += hex[value >> 4];
            suffix += hex[value & 15];
        }
        const auto candidate =
            std::filesystem::path{MIRA_TLS_TEST_BINARY_DIR} / ("certificates-" + suffix);
        require(std::filesystem::create_directory(candidate));
        directory = candidate;
        std::filesystem::permissions(
            directory, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
        const auto ca_key = generate_key();
        const auto ca_cert = generate_certificate(ca_key.get(), "Mirat CA", 1);
        const auto unrelated_key = generate_key();
        const auto unrelated_cert = generate_certificate(unrelated_key.get(), "Unrelated CA", 2);
        const auto server_key = generate_key();
        const auto server_cert =
            generate_certificate(server_key.get(), "localhost", 3, ca_cert.get(), ca_key.get());
        ca = write("ca.pem", ca_cert.get());
        other_ca = write("unrelated-ca.pem", unrelated_cert.get());
        server = write("server.pem", server_cert.get());
        key = write("server-key.pem", nullptr, server_key.get());
        const auto client_key_pair = generate_key();
        const auto client_cert = generate_certificate(
            client_key_pair.get(), "test client", 4, ca_cert.get(), ca_key.get(), "clientAuth");
        client = write("client.pem", client_cert.get());
        client_key = write("client-key.pem", nullptr, client_key_pair.get());
    }
};

struct DetachedTask {
    struct promise_type {
        DetachedTask get_return_object() noexcept { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::terminate(); }
    };
};

// Limits the length of each ciphertext I/O so TLS records are independent of
// TCP fragmentation boundaries.
struct FragmentedSocket {
    tcp::Socket& socket;
    std::size_t limit;
    std::size_t reads = 0;
    std::size_t writes = 0;

    /// `options` is forwarded rather than dropped: this wraps a real socket,
    /// so it is a layer that genuinely waits, and swallowing a deadline here
    /// would make one silently do nothing. The same absolute deadline reaching
    /// every fragment is what a deadline on the whole transfer means.
    Task<Result<std::size_t>> read_some(std::span<std::byte> destination,
                                       OperationOptions options = {}) {
        ++reads;
        co_return co_await socket.read_some(destination.first(std::min(limit, destination.size())),
                                           std::move(options));
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                        OperationOptions options = {}) {
        ++writes;
        co_return co_await socket.write_some(source.first(std::min(limit, source.size())),
                                            std::move(options));
    }
};

static_assert(AsyncStream<tls::Stream<tcp::Socket>>);
static_assert(ClosableStream<tls::Stream<tcp::Socket>>);
static_assert(ClosableStream<tls::Stream<FragmentedSocket>>);
static_assert(AsyncStream<tls::Stream<FragmentedSocket>>);

enum class Scenario { https, truncated, verify_failure, alpn_failure };

struct Exchange {
    tcp::Socket server_socket;
    tcp::Socket client_socket;
    int done = 0;
    Error server_error;
    Error client_error;
    std::string target;
    std::string body;
    std::string response;
    std::string payload;
    std::string protocol;
    std::size_t client_reads = 0;
    std::size_t client_writes = 0;
};

struct Completion {
    int& count;
    ~Completion() { ++count; }
};

template<class Stream>
Task<void> check_initial_state(Stream& stream) {
    std::array<std::byte, 1> byte{};
    const auto read = co_await stream.read_some(byte);
    CHECK(!read && read.error() == tls::Errc::invalid_state);
    const auto written = co_await stream.write_some(byte);
    CHECK(!written && written.error() == tls::Errc::invalid_state);
    const auto shutdown = co_await stream.shutdown();
    CHECK(!shutdown && shutdown.error() == tls::Errc::invalid_state);
}

template<class Stream>
Task<void> check_established_state(Stream& stream) {
    const auto again = co_await stream.handshake();
    CHECK(again.has_value());
    const auto read = co_await stream.read_some({});
    CHECK(read && *read == 0);
    const auto written = co_await stream.write_some({});
    CHECK(written && *written == 0);
}

DetachedTask run_server(EventLoop& loop, tcp::Listener& listener,
                        const tls::Context& context,
                        Exchange& exchange,
                        Scenario scenario,
                        std::size_t fragment) {
    Completion completion{exchange.done};
    auto accepted = co_await listener.accept();
    if (!accepted) {
        exchange.server_error = accepted.error();
        co_return;
    }
    exchange.server_socket = std::move(*accepted);
    FragmentedSocket transport{exchange.server_socket, fragment};
    auto created = tls::Stream<FragmentedSocket>::create(loop, transport, context);
    if (!created) {
        exchange.server_error = created.error();
        co_return;
    }
    auto& stream = *created;
    co_await check_initial_state(stream);
    const auto handshake = co_await stream.handshake();
    if (!handshake) {
        exchange.server_error = handshake.error();
        co_return;
    }
    co_await check_established_state(stream);
    if (scenario == Scenario::verify_failure || scenario == Scenario::alpn_failure) {
        std::array<std::byte, 1> byte{};
        const auto read = co_await stream.read_some(byte);
        if (!read) {
            exchange.server_error = read.error();
        }
        co_return;
    }
    if (scenario == Scenario::truncated) {
        const auto written = co_await write_all(stream, bytes_of("authenticated prefix"));
        if (!written) {
            exchange.server_error = written.error();
        }
        const auto stopped = exchange.server_socket.shutdown_send();
        CHECK(stopped.has_value());
        co_return;
    }
    auto handler = [&exchange](const http::Request& request,
                               auto& writer,
                               std::span<const std::byte> body) -> Task<Result<void>> {
        exchange.target = request.target;
        exchange.body.assign(reinterpret_cast<const char*>(body.data()), body.size());
        http::Response response;
        response.status = 200;
        response.headers.append("Content-Type", "application/octet-stream");
        co_return co_await writer.send(response, bytes_of(exchange.payload));
    };
    const auto served = co_await http::serve_connection(stream, handler);
    if (!served) {
        exchange.server_error = served.error();
        co_return;
    }
    const auto shutdown = co_await stream.shutdown();
    if (!shutdown) {
        exchange.server_error = shutdown.error();
        co_return;
    }
    const auto written = co_await stream.write_some(bytes_of("after shutdown"));
    CHECK(!written && written.error() == tls::Errc::invalid_state);
    const auto shutdown_again = co_await stream.shutdown();
    CHECK(shutdown_again.has_value());
}

DetachedTask run_client(EventLoop& loop,
                        Endpoint endpoint,
                        const tls::Context& context,
                        std::string peer_name,
                        Exchange& exchange,
                        Scenario scenario,
                        std::size_t fragment) {
    Completion completion{exchange.done};
    auto connected = co_await tcp::connect(loop, endpoint);
    if (!connected) {
        exchange.client_error = connected.error();
        co_return;
    }
    exchange.client_socket = std::move(*connected);
    FragmentedSocket transport{exchange.client_socket, fragment};
    auto created = tls::Stream<FragmentedSocket>::create(loop, transport, context, peer_name);
    if (!created) {
        exchange.client_error = created.error();
        co_return;
    }
    auto& stream = *created;
    co_await check_initial_state(stream);
    const auto handshake = co_await stream.handshake();
    if (!handshake) {
        exchange.client_error = handshake.error();
        if (scenario == Scenario::verify_failure || scenario == Scenario::alpn_failure) {
            co_await check_initial_state(stream);
            const auto again = co_await stream.handshake();
            CHECK(!again && again.error() == tls::Errc::invalid_state);
        }
        // Keep TCP open: the peer must observe the fatal TLS alert, not rely
        // on a transport close to unblock its handshake/read.
        co_return;
    }
    CHECK(scenario != Scenario::verify_failure && scenario != Scenario::alpn_failure);
    co_await check_established_state(stream);
    CHECK(stream.negotiated_protocol() == exchange.protocol);
    if (scenario == Scenario::https) {
        const std::string request = "POST /secure HTTP/1.1\r\nHost: localhost\r\n"
                                    "Content-Length: " +
                                    std::to_string(exchange.payload.size()) +
                                    "\r\nConnection: close\r\n\r\n" + exchange.payload;
        const auto written = co_await write_all(stream, bytes_of(request));
        if (!written) {
            exchange.client_error = written.error();
            co_return;
        }
    }
    std::array<std::byte, 4093> buffer{};
    for (;;) {
        const auto read = co_await stream.read_some(buffer);
        if (!read) {
            exchange.client_error = read.error();
            break;
        }
        CHECK(*read > 0);
        if (*read == 0) {
            break;
        }
        exchange.response.append(reinterpret_cast<const char*>(buffer.data()), *read);
    }
    if (scenario == Scenario::https && exchange.client_error == Errc::eof) {
        const auto read_again = co_await stream.read_some(buffer);
        CHECK(!read_again && read_again.error() == Errc::eof);
        const auto write_after_eof = co_await stream.write_some(bytes_of("after peer close"));
        CHECK(!write_after_eof && write_after_eof.error() == tls::Errc::invalid_state);
    }
    exchange.client_reads = transport.reads;
    exchange.client_writes = transport.writes;
}

void run_exchange(const Certificates& certificates,
                  std::string_view name,
                  std::string_view peer_name,
                  Scenario scenario = Scenario::https,
                  bool unrelated_ca = false,
                  std::size_t fragment = 65536,
                  std::size_t payload_size = 4,
                  std::string_view protocol = {}) {
    test::section(name);
    auto server_context = tls::Context::server(certificates.server, certificates.key, protocol);
    auto client_context =
        tls::Context::client(unrelated_ca ? certificates.other_ca : certificates.ca,
                             scenario == Scenario::alpn_failure ? "unmatched/1" : protocol);
    CHECK(server_context.has_value());
    CHECK(client_context.has_value());
    if (!server_context || !client_context) {
        return;
    }
    // The state is created before the loop so every reference is still valid
    // when cancellation callbacks run.
    Exchange exchange;
    exchange.protocol = protocol;
    exchange.payload.resize(payload_size);
    for (std::size_t i = 0; i < payload_size; ++i) {
        exchange.payload[i] = static_cast<char>('a' + (i % 26));
    }
    auto loop_result = EventLoop::create();
    CHECK(loop_result.has_value());
    if (!loop_result) {
        return;
    }
    auto& loop = *loop_result;
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) {
        return;
    }
    struct Cleanup {
        Exchange& exchange;
        ~Cleanup() {
            exchange.client_socket.close();
            exchange.server_socket.close();
        }
    } cleanup{exchange};
    run_server(loop, *listener, *server_context, exchange, scenario, fragment);
    run_client(loop,
               listener->local_endpoint(),
               *client_context,
               std::string{peer_name},
               exchange,
               scenario,
               fragment);
    const auto deadline = EventLoop::Clock::now() + 5s;
    while (exchange.done < 2 && EventLoop::Clock::now() < deadline) {
        const auto iteration = loop.run_once(10ms);
        CHECK(iteration.has_value());
        if (!iteration) {
            break;
        }
    }
    CHECK(exchange.done == 2);
    if (exchange.done != 2) {
        return;
    }
    if (scenario == Scenario::verify_failure || scenario == Scenario::alpn_failure) {
        CHECK(exchange.client_error == (scenario == Scenario::verify_failure
                                            ? tls::Errc::certificate_verify_failed
                                            : tls::Errc::protocol_error));
        CHECK(exchange.server_error == tls::Errc::protocol_error);
    } else if (scenario == Scenario::truncated) {
        CHECK(!exchange.server_error);
        CHECK(exchange.client_error == tls::Errc::truncated);
        CHECK(exchange.response == "authenticated prefix");
    } else {
        CHECK(!exchange.server_error);
        CHECK(exchange.client_error == Errc::eof);
        CHECK(exchange.target == "/secure");
        CHECK(exchange.body == exchange.payload);
        const std::string expected = "HTTP/1.1 200 OK\r\n"
                                     "Content-Type: application/octet-stream\r\nContent-Length: " +
                                     std::to_string(exchange.payload.size()) + "\r\n\r\n" +
                                     exchange.payload;
        CHECK(exchange.response == expected);
        if (fragment < payload_size) {
            CHECK(exchange.client_reads > payload_size / fragment);
            CHECK(exchange.client_writes > payload_size / fragment);
        }
    }
}

/// A transport whose reads park until the test resumes them by hand.
///
/// `options` is accepted and ignored deliberately: this stream's whole purpose
/// is to be stuck, so it must not resolve for any reason the test did not
/// cause. Recording what it was handed is a separate concern — see
/// `RecordingTransport`.
struct ControlledTransport {
    std::coroutine_handle<> waiting;
    bool zero_write = false;

    Task<Result<std::size_t>> read_some(std::span<std::byte>, OperationOptions = {}) {
        struct Pause {
            std::coroutine_handle<>& waiting;
            bool await_ready() const noexcept { return false; }
            void await_suspend(std::coroutine_handle<> continuation) const noexcept {
                waiting = continuation;
            }
            void await_resume() const noexcept {}
        };
        co_await Pause{waiting};
        co_return fail(Errc::eof);
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                        OperationOptions = {}) {
        co_return zero_write ? std::size_t{0} : source.size();
    }
};

/// Records every wire deadline. TLS owns independent loop timers and must never
/// forward operation deadlines to ciphertext transfers or cancel them to rearm.
struct RecordingTransport {
    std::vector<std::optional<Clock::time_point>> seen;
    std::size_t allowed_writes = 0;

    Task<Result<std::size_t>> read_some(std::span<std::byte>, OperationOptions options = {}) {
        seen.push_back(options.deadline);
        co_return fail(Errc::eof);
    }

    Task<Result<std::size_t>> write_some(std::span<const std::byte> source,
                                         OperationOptions options = {}) {
        seen.push_back(options.deadline);
        if (allowed_writes == 0) {
            co_return fail(Errc::cancelled);
        }
        --allowed_writes;
        co_return source.size();
    }
};

Task<void> bounded_recording_handshake(tls::Stream<RecordingTransport>& stream,
                                       Clock::time_point deadline) {
    const auto handshake = co_await stream.handshake({.deadline = deadline});
    CHECK(!handshake);
}

void test_options_reach_the_underlying_stream(const Certificates& certificates) {
    test::section("TLS owns deadline timers and leaves every wire operation deadline-free");
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (!loop) return;

    Result<tls::Context> context = tls::Context::client(certificates.ca);
    CHECK(context.has_value());
    if (!context) {
        return;
    }

    RecordingTransport transport;
    transport.allowed_writes = 2;  // let the ClientHello out, then stop
    Result<tls::Stream<RecordingTransport>> stream =
        tls::Stream<RecordingTransport>::create(*loop, transport, *context, "localhost");
    CHECK(stream.has_value());
    if (!stream) {
        return;
    }

    const auto deadline = Clock::now() + std::chrono::seconds{30};
    CHECK(loop->run_until_complete(bounded_recording_handshake(*stream, deadline)).has_value());
    CHECK(loop->outstanding() == 0);
    CHECK(!transport.seen.empty());
    for (const auto& observed : transport.seen) CHECK(!observed.has_value());

    // And with no options, nothing is invented on the way down.
    RecordingTransport plain;
    plain.allowed_writes = 2;
    Result<tls::Stream<RecordingTransport>> bare =
        tls::Stream<RecordingTransport>::create(*loop, plain, *context, "localhost");
    CHECK(bare.has_value());
    if (!bare) {
        return;
    }
    CHECK(!bare->handshake().sync_get());
    CHECK(!plain.seen.empty());
    bool none_carried_one = !plain.seen.empty();
    for (const std::optional<Clock::time_point>& observed : plain.seen) {
        none_carried_one = none_carried_one && !observed.has_value();
    }
    CHECK(none_carried_one);
}

DetachedTask start_handshake(tls::Stream<ControlledTransport>& stream, Error& error, int& done) {
    Completion completion{done};
    const auto result = co_await stream.handshake();
    if (!result) {
        error = result.error();
    }
}

void test_shared_buffer_budget(const Certificates& certificates) {
    test::section("TLS shared BIO and stream buffer reservations");
    auto context = tls::Context::client(certificates.ca);
    auto loop = EventLoop::create();
    CHECK(context && loop);
    if (!context || !loop) return;
    ResourceBudget budget{tls::Engine::reserved_buffer_bytes};
    {
        auto engine = tls::Engine::create(*context, "localhost", budget);
        CHECK(engine.has_value());
        CHECK(budget.used() == tls::Engine::reserved_buffer_bytes);
        auto rejected = tls::Engine::create(*context, "localhost", budget);
        CHECK(!rejected && rejected.error() == Errc::would_block);
        CHECK(budget.used() == tls::Engine::reserved_buffer_bytes);
        if (engine) {
            auto moved = std::move(*engine);
            moved.invalidate();
            CHECK(budget.used() == tls::Engine::reserved_buffer_bytes);
        }
    }
    CHECK(budget.used() == 0);
    ControlledTransport transport;
    using Secure = tls::Stream<ControlledTransport>;
    ResourceBudget buffers{Secure::reserved_buffer_bytes};
    {
        auto stream = Secure::create(*loop, transport, *context, "localhost", buffers);
        CHECK(stream.has_value());
        CHECK(buffers.used() == Secure::reserved_buffer_bytes);
        auto second = Secure::create(*loop, transport, *context, "localhost", buffers);
        CHECK(!second && second.error() == Errc::would_block);
        if (stream) stream->close();
        CHECK(buffers.used() == Secure::reserved_buffer_bytes);
    }
    CHECK(buffers.used() == 0);
    ResourceBudget too_small{Secure::reserved_buffer_bytes - 1};
    auto failed = Secure::create(*loop, transport, *context, "localhost", too_small);
    CHECK(!failed && failed.error() == Errc::would_block);
    CHECK(too_small.used() == 0);
    auto bad_name = Secure::create(*loop, transport, *context, "", buffers);
    CHECK(!bad_name && bad_name.error() == Errc::invalid_argument);
    CHECK(buffers.used() == 0);
}

void test_concurrent_operations(const Certificates& certificates) {
    test::section("TLS overlapping operations and zero-progress ciphertext writes");
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (!loop) return;
    auto context = tls::Context::client(certificates.ca);
    CHECK(context.has_value());
    if (!context) {
        return;
    }
    ControlledTransport transport;
    auto created = tls::Stream<ControlledTransport>::create(*loop, transport, *context, "localhost");
    CHECK(created.has_value());
    if (!created) {
        return;
    }
    auto moved = std::move(*created);
    auto missing_name = tls::Stream<ControlledTransport>::create(*loop, transport, *context);
    CHECK(!missing_name && missing_name.error() == Errc::invalid_argument);
    const std::string embedded_nul{"localhost\0wrong.example", 23};
    auto invalid_name = tls::Stream<ControlledTransport>::create(*loop, transport, *context, embedded_nul);
    CHECK(!invalid_name && invalid_name.error() == Errc::invalid_argument);
    const auto moved_from = created->handshake().sync_get();
    CHECK(!moved_from && moved_from.error() == tls::Errc::invalid_state);
    Error error;
    int done = 0;
    start_handshake(moved, error, done);
    CHECK(done == 0);
    CHECK(static_cast<bool>(transport.waiting));
    std::array<std::byte, 1> byte{};
    const auto read = moved.read_some(byte).sync_get();
    CHECK(!read && read.error() == tls::Errc::operation_in_progress);
    const auto written = moved.write_some(byte).sync_get();
    CHECK(!written && written.error() == tls::Errc::operation_in_progress);
    const auto handshake = moved.handshake().sync_get();
    CHECK(!handshake && handshake.error() == tls::Errc::operation_in_progress);
    const auto shutdown = moved.shutdown().sync_get();
    CHECK(!shutdown && shutdown.error() == tls::Errc::operation_in_progress);
    if (transport.waiting) {
        std::exchange(transport.waiting, {}).resume();
    }
    CHECK(done == 1);
    CHECK(error == tls::Errc::truncated);
    check_initial_state(moved).sync_get();
    const auto retry = moved.handshake().sync_get();
    CHECK(!retry && retry.error() == tls::Errc::invalid_state);

    ControlledTransport no_progress;
    no_progress.zero_write = true;
    auto stream = tls::Stream<ControlledTransport>::create(*loop, no_progress, *context, "localhost");
    CHECK(stream.has_value());
    if (stream) {
        const auto result = stream->handshake().sync_get();
        CHECK(!result && result.error() == tls::Errc::protocol_error);
        check_initial_state(*stream).sync_get();
    }
}

struct AlpnExchange {
    std::array<tcp::Socket, 2> sockets;
    std::array<Error, 2> errors;
    std::array<std::string, 2> negotiated;
    int done = 0;
};

DetachedTask run_alpn_peer(EventLoop& loop,
                           tcp::Listener& listener,
                           std::optional<tls::Context> context,
                           AlpnExchange& exchange,
                           std::size_t peer,
                           bool destroy_context) {
    Completion completion{exchange.done};
    // Split by role rather than `peer == 0 ? co_await ... : co_await ...`:
    // co_await inside the branches of a conditional operator miscompiles
    // under GCC 15 (MinGW); see run_mtls_peer for the same note.
    Result<tcp::Socket> connected;
    if (peer == 0) {
        connected = co_await listener.accept();
    } else {
        connected = co_await tcp::connect(loop, listener.local_endpoint());
    }
    if (!connected) {
        exchange.errors[peer] = connected.error();
        co_return;
    }
    auto& socket = exchange.sockets[peer];
    socket = std::move(*connected);
    auto stream = tls::Stream<tcp::Socket>::create(loop, socket, *context, peer == 0 ? "" : "localhost");
    if (!stream) {
        exchange.errors[peer] = stream.error();
        co_return;
    }
    if (destroy_context) context.reset();
    const auto handshake = co_await stream->handshake();
    if (!handshake) {
        exchange.errors[peer] = handshake.error();
        co_return;
    }
    exchange.negotiated[peer] = stream->negotiated_protocol();
    // ALPN only selects the name; arbitrary application data is exchanged here,
    // without pretending to implement HTTP/2.
    if (peer == 0) {
        const auto sent = co_await write_all(*stream, bytes_of("alpn"));
        CHECK(sent.has_value());
        const auto shutdown = co_await stream->shutdown();
        CHECK(shutdown.has_value());
    } else {
        std::array<std::byte, 16> buffer{};
        std::string received;
        for (;;) {
            const auto read = co_await stream->read_some(buffer);
            if (!read) {
                CHECK(read.error() == Errc::eof);
                break;
            }
            received.append(reinterpret_cast<const char*>(buffer.data()), *read);
        }
        CHECK(received == "alpn");
    }
}

void run_alpn_exchange(const Certificates& certificates,
                       std::string_view name,
                       std::span<const std::string_view> server_protocols,
                       std::span<const std::string_view> client_protocols,
                       std::string_view expected,
                       bool failure = false,
                       bool destroy_context = false) {
    test::section(name);
    const auto make_owned_context = [&certificates](std::span<const std::string_view> protocols,
                                                    bool server_side) {
        std::vector<std::string> storage;
        storage.reserve(protocols.size());
        for (const auto protocol : protocols) storage.emplace_back(protocol);
        std::vector<std::string_view> copied;
        for (const auto& protocol : storage) copied.push_back(protocol);
        return server_side
                   ? tls::Context::server_alpn(certificates.server, certificates.key, copied)
                   : tls::Context::client_alpn(certificates.ca, copied);
    };
    // The configuration inputs are destroyed before the handshake, verifying that
    // the API copies the data instead of retaining string_views.
    auto server = make_owned_context(server_protocols, true);
    auto client = make_owned_context(client_protocols, false);
    CHECK(server.has_value());
    CHECK(client.has_value());
    if (!server || !client) return;
    AlpnExchange exchange;
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (!loop) return;
    auto listener = tcp::Listener::bind(*loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) return;
    struct Cleanup {
        AlpnExchange& exchange;
        ~Cleanup() {
            for (auto& socket : exchange.sockets) socket.close();
        }
    } cleanup{exchange};
    run_alpn_peer(*loop, *listener, std::move(*server), exchange, 0, destroy_context);
    run_alpn_peer(*loop, *listener, std::move(*client), exchange, 1, destroy_context);
    const auto deadline = EventLoop::Clock::now() + 5s;
    while (exchange.done < 2 && EventLoop::Clock::now() < deadline) {
        const auto iteration = loop->run_once(10ms);
        CHECK(iteration.has_value());
        if (!iteration) break;
    }
    CHECK(exchange.done == 2);
    for (std::size_t peer = 0; peer < 2; ++peer) {
        if (failure) {
            CHECK(exchange.errors[peer] == tls::Errc::protocol_error);
        } else {
            CHECK(!exchange.errors[peer]);
            CHECK(exchange.negotiated[peer] == expected);
        }
    }
}

void test_alpn(const Certificates& certificates) {
    constexpr std::array<std::string_view, 2> server{"h2", "http/1.1"};
    constexpr std::array<std::string_view, 2> reversed{"http/1.1", "h2"};
    constexpr std::array<std::string_view, 1> http1{"http/1.1"};
    constexpr std::array<std::string_view, 1> unmatched{"other/1"};
    run_alpn_exchange(certificates,
                      "ALPN selects h2 by server rather than client preference order",
                      server,
                      reversed,
                      "h2");
    run_alpn_exchange(certificates,
                      "ALPN falls back when the client offers only HTTP/1.1",
                      server,
                      http1,
                      "http/1.1");
    run_alpn_exchange(certificates,
                      "ALPN allows no negotiation when the client sends no extension",
                      server,
                      {},
                      "");
    run_alpn_exchange(certificates,
                      "ALPN allows no negotiation when the server disables it",
                      {},
                      reversed,
                      "");
    run_alpn_exchange(certificates,
                      "ALPN sends a fatal alert when no protocol is shared",
                      server,
                      unmatched,
                      "",
                      true);
    run_alpn_exchange(certificates,
                      "ALPN SSL_CTX still retains the list after early Context destruction",
                      server,
                      reversed,
                      "h2",
                      false,
                      true);
    const std::string binary{"h\0\xff", 3};
    const std::array<std::string_view, 2> binary_server{binary, "h2"};
    const std::array<std::string_view, 2> binary_client{"h2", binary};
    run_alpn_exchange(certificates,
                      "ALPN binary protocol names preserve NUL and high bytes",
                      binary_server,
                      binary_client,
                      binary,
                      false,
                      true);

    test::section("ALPN list validation and encoded length boundaries");
    const auto invalid = [&certificates](std::span<const std::string_view> protocols) {
        const auto client = tls::Context::client_alpn(certificates.ca, protocols);
        const auto server_context =
            tls::Context::server_alpn(certificates.server, certificates.key, protocols);
        CHECK(!client && client.error() == Errc::invalid_argument);
        CHECK(!server_context && server_context.error() == Errc::invalid_argument);
    };
    const std::array<std::string_view, 1> empty{""};
    invalid(empty);
    const std::array<std::string_view, 2> duplicate{"h2", "h2"};
    invalid(duplicate);
    const std::array<std::string_view, 2> binary_duplicate{binary, binary};
    invalid(binary_duplicate);
    const std::string oversized(256, 'x');
    const std::array<std::string_view, 1> oversized_protocol{oversized};
    invalid(oversized_protocol);
    const auto legacy_client = tls::Context::client(certificates.ca, oversized);
    CHECK(!legacy_client && legacy_client.error() == Errc::invalid_argument);
    const auto legacy_server = tls::Context::server(certificates.server, certificates.key, oversized);
    CHECK(!legacy_server && legacy_server.error() == Errc::invalid_argument);

    const std::string longest(255, 'x');
    const std::array<std::string_view, 1> longest_protocol{longest};
    run_alpn_exchange(certificates,
                      "ALPN 255-byte name is negotiable",
                      longest_protocol,
                      longest_protocol,
                      longest);
    std::vector<std::string> names;
    names.reserve(256);
    for (unsigned int i = 0; i < 256; ++i) {
        names.emplace_back(255, 'x');
        names.back()[0] = static_cast<char>(i);
    }
    std::vector<std::string_view> protocols;
    for (const auto& protocol : names) protocols.push_back(protocol);
    invalid(protocols);  // 256 * (255 + 1) = 65536.
    protocols.back() = protocols.back().substr(0, 254);
    CHECK(tls::Context::client_alpn(certificates.ca, protocols).has_value());
    CHECK(tls::Context::server_alpn(certificates.server, certificates.key, protocols).has_value());
}

struct MtlsExchange {
    std::array<tcp::Socket, 2> sockets;
    std::array<Error, 2> errors;
    int done = 0;
};

DetachedTask run_mtls_peer(EventLoop& loop,
                           tcp::Listener& listener,
                           std::optional<tls::Context> context,
                           MtlsExchange& exchange,
                           std::size_t peer) {
    Completion completion{exchange.done};
    // The connection step is split by role instead of written as
    // `peer == 0 ? co_await accept() : co_await connect()`: co_await inside
    // the branches of a conditional operator miscompiles under GCC 15
    // (MinGW) — the operation completes but its awaiter is never resumed,
    // so the exchange stalls until the deadline. Plain if/else lowers
    // correctly on every toolchain.
    Result<tcp::Socket> connected;
    if (peer == 0) {
        connected = co_await listener.accept();
    } else {
        connected = co_await tcp::connect(loop, listener.local_endpoint());
    }
    if (!connected) {
        exchange.errors[peer] = connected.error();
        co_return;
    }
    auto& socket = exchange.sockets[peer];
    socket = std::move(*connected);
    auto stream = tls::Stream<tcp::Socket>::create(loop, socket, *context, peer == 0 ? "" : "localhost");
    if (!stream) {
        exchange.errors[peer] = stream.error();
        co_return;
    }
    const auto handshake = co_await stream->handshake();
    if (!handshake) {
        exchange.errors[peer] = handshake.error();
        co_return;
    }
    if (peer == 0) {
        const auto sent = co_await write_all(*stream, bytes_of("mtls"));
        CHECK(sent.has_value());
        const auto shutdown = co_await stream->shutdown();
        CHECK(shutdown.has_value());
    } else {
        std::array<std::byte, 16> buffer{};
        std::string received;
        for (;;) {
            const auto read = co_await stream->read_some(buffer);
            if (!read) {
                // A TLS 1.3 client may finish its handshake before the server
                // rejects it: the rejection surfaces as a fatal alert on the
                // first read, not as a handshake failure. Only eof means the
                // data arrived intact.
                if (read.error() != Errc::eof) exchange.errors[peer] = read.error();
                break;
            }
            received.append(reinterpret_cast<const char*>(buffer.data()), *read);
        }
        if (exchange.errors[peer]) {
            CHECK(exchange.errors[peer] == tls::Errc::protocol_error);
        } else {
            CHECK(received == "mtls");
        }
    }
}

void run_mtls_exchange(std::string_view name,
                       tls::Context server_context,
                       tls::Context client_context,
                       bool expect_failure) {
    test::section(name);
    MtlsExchange exchange;
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (!loop) return;
    auto listener = tcp::Listener::bind(*loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) return;
    struct Cleanup {
        MtlsExchange& exchange;
        ~Cleanup() {
            for (auto& socket : exchange.sockets) socket.close();
        }
    } cleanup{exchange};
    run_mtls_peer(*loop, *listener, std::move(server_context), exchange, 0);
    run_mtls_peer(*loop, *listener, std::move(client_context), exchange, 1);
    const auto deadline = EventLoop::Clock::now() + 5s;
    while (exchange.done < 2 && EventLoop::Clock::now() < deadline) {
        const auto iteration = loop->run_once(10ms);
        CHECK(iteration.has_value());
        if (!iteration) break;
    }
    CHECK(exchange.done == 2);
    if (expect_failure) {
        // Server-side client certificate verification failure → fatal alert;
        // both sides end with a protocol error.
        CHECK(exchange.errors[0] == tls::Errc::protocol_error);
        CHECK(exchange.errors[1] == tls::Errc::protocol_error);
    } else {
        CHECK(!exchange.errors[0]);
        CHECK(!exchange.errors[1]);
    }
}

void test_mtls(const Certificates& certificates) {
    test::section("mTLS client certificate verification and protocol version configuration");
    const auto server_config = [&certificates] {
        tls::Context::ServerConfig config;
        config.cert_file = certificates.server;
        config.key_file = certificates.key;
        return config;
    };
    const auto client_config = [&certificates] {
        tls::Context::ClientConfig config;
        config.ca_file = certificates.ca;
        return config;
    };

    // A client that presents no certificate is rejected in mandatory mode.
    auto require_cert = server_config();
    require_cert.client_ca_file = certificates.ca;
    auto server_ctx = tls::Context::server(require_cert);
    auto anonymous = tls::Context::client(client_config());
    CHECK(server_ctx.has_value());
    CHECK(anonymous.has_value());
    if (server_ctx && anonymous)
        run_mtls_exchange("mTLS handshake rejected for a client presenting no certificate",
                          std::move(*server_ctx), std::move(*anonymous), true);

    // A client presenting a certificate issued by the CA passes verification and
    // completes an application data round trip.
    auto presenting = client_config();
    presenting.cert_file = certificates.client;
    presenting.key_file = certificates.client_key;
    server_ctx = tls::Context::server(require_cert);
    auto client_ctx = tls::Context::client(presenting);
    CHECK(server_ctx.has_value());
    CHECK(client_ctx.has_value());
    if (server_ctx && client_ctx)
        run_mtls_exchange("mTLS client certificate verifies and data can be exchanged",
                          std::move(*server_ctx), std::move(*client_ctx), false);

    // min_version accepts only 1.2/1.3; a 1.3 server handshakes normally with
    // a plain client.
    auto outdated = server_config();
    outdated.min_version = "1.1";
    const auto rejected = tls::Context::server(outdated);
    CHECK(!rejected && rejected.error() == Errc::invalid_argument);
    auto modern = server_config();
    modern.min_version = "1.3";
    auto modern_ctx = tls::Context::server(modern);
    auto plain_client = tls::Context::client(client_config());
    CHECK(modern_ctx.has_value());
    CHECK(plain_client.has_value());
    if (modern_ctx && plain_client)
        run_mtls_exchange("min_version 1.3 handshakes normally with a TLS 1.3 client",
                          std::move(*modern_ctx), std::move(*plain_client), false);

    // The client certificate and private key must appear as a pair.
    auto half = client_config();
    half.cert_file = certificates.client;
    const auto missing_key = tls::Context::client(half);
    CHECK(!missing_key && missing_key.error() == Errc::invalid_argument);
    half.cert_file = {};
    half.key_file = certificates.client_key;
    const auto missing_cert = tls::Context::client(half);
    CHECK(!missing_cert && missing_cert.error() == Errc::invalid_argument);
}

using DuplexStream = tls::Stream<FragmentedSocket>;

Task<void> duplex_receive(DuplexStream& stream, const std::string& expected,
                          std::string& received, OperationOptions options) {
    std::array<std::byte, 2903> buffer{};
    while (received.size() != expected.size()) {
        const auto result = co_await stream.read_some(buffer, options);
        CHECK(result.has_value());
        if (!result) co_return;
        received.append(reinterpret_cast<const char*>(buffer.data()), *result);
        CHECK(received.size() <= expected.size());
        if (received.size() > expected.size()) co_return;
    }
    CHECK(received == expected);
}

Task<void> duplex_send(DuplexStream& stream, const std::string& payload,
                       OperationOptions options) {
    const auto result = co_await write_all(stream, bytes_of(payload), options);
    CHECK(result.has_value());
}

Task<void> duplex_peer(EventLoop& loop, tcp::Listener& listener, const tls::Context& context,
                       std::size_t peer, std::array<DuplexStream*, 2>& streams,
                       std::array<bool, 2>& reading, const std::array<std::string, 2>& payloads) {
    const OperationOptions options{.deadline = Clock::now() + 8s};
    Result<tcp::Socket> socket;
    if (peer == 0) socket = co_await listener.accept(options);
    else socket = co_await tcp::connect(loop, listener.local_endpoint(), {}, options);
    CHECK(socket.has_value());
    if (!socket) co_return;
    FragmentedSocket transport{*socket, 113};
    auto stream = DuplexStream::create(loop, transport, context, peer == 0 ? "" : "localhost");
    CHECK(stream.has_value());
    if (!stream) co_return;
    const auto handshake = co_await stream->handshake(options);
    CHECK(handshake.has_value());
    if (!handshake) co_return;
    streams[peer] = &*stream;
    while (!streams[1 - peer]) co_await loop.yield();
    std::string received;
    TaskScope scope;
    scope.spawn(duplex_receive(*stream, payloads[1 - peer], received, options));
    CHECK(scope.pending() == 1);
    std::array<std::byte, 1> duplicate{};
    const auto overlap = co_await stream->read_some(duplicate, options);
    CHECK(!overlap && overlap.error() == tls::Errc::operation_in_progress);
    const auto repeated_handshake = co_await stream->handshake(options);
    CHECK(!repeated_handshake && repeated_handshake.error() == tls::Errc::operation_in_progress);
    const auto early_shutdown = co_await stream->shutdown(options);
    CHECK(!early_shutdown && early_shutdown.error() == tls::Errc::operation_in_progress);
    reading[peer] = true;
    while (!reading[1 - peer]) co_await loop.yield();
    scope.spawn(duplex_send(*stream, payloads[peer], options));
    co_await scope.join();
    const auto closed = co_await stream->shutdown(options);
    CHECK(closed.has_value());
    CHECK(transport.writes > payloads[peer].size() / transport.limit);
}

Task<void> duplex_exchange(EventLoop& loop, tcp::Listener& listener,
                           const tls::Context& server, const tls::Context& client) {
    std::array<DuplexStream*, 2> streams{};
    std::array<bool, 2> reading{};
    std::array<std::string, 2> payloads{std::string(320 * 1024 + 17, 'a'),
                                     std::string(384 * 1024 + 31, 'b')};
    for (std::size_t i = 0; i < payloads[0].size(); ++i)
        payloads[0][i] = static_cast<char>('a' + i % 23);
    TaskScope scope;
    scope.spawn(duplex_peer(loop, listener, server, 0, streams, reading, payloads));
    scope.spawn(duplex_peer(loop, listener, client, 1, streams, reading, payloads));
    co_await scope.join();
}

void test_duplex(const Certificates& certificates) {
    test::section("TLS duplex: both socket peers park reads before large fragmented writes");
    auto server = tls::Context::server(certificates.server, certificates.key);
    auto client = tls::Context::client(certificates.ca);
    auto loop = EventLoop::create();
    CHECK(server && client && loop);
    if (!server || !client || !loop) return;
    auto listener = tcp::Listener::bind(*loop, Endpoint::loopback(0));
    CHECK(listener.has_value());
    if (!listener) return;
    CHECK(loop->run_until_complete(duplex_exchange(*loop, *listener, *server, *client)).has_value());
}

enum class Fault {
    reader_timeout, writer_timeout, reader_cancel, writer_cancel, zero_write, exception, corrupt_record, close
};

struct StalledSocket {
    tcp::Socket& socket;
    EventLoop& loop;
    bool stall = false;
    bool zero = false;
    bool throws = false;
    std::size_t pending_read = 0;
    std::size_t pending_write = 0;

    Task<Result<std::size_t>> read_some(std::span<std::byte> bytes, OperationOptions options = {}) {
        ++pending_read;
        const auto result = co_await socket.read_some(bytes, options);
        --pending_read;
        co_return result;
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes, OperationOptions options = {}) {
        if (throws) throw std::runtime_error("injected transport exception");
        if (zero) co_return std::size_t{0};
        if (stall) {
            ++pending_write;
            const auto pause = co_await loop.sleep_for(30s, options);
            --pending_write;
            if (!pause) co_return fail(pause.error());
        }
        co_return co_await socket.write_some(bytes, options);
    }
};

using FaultStream = tls::Stream<StalledSocket>;

Task<void> fault_operation(FaultStream& stream, bool reading, OperationOptions options,
                           Error& error, bool& threw) {
    std::array<std::byte, 4096> buffer{};
    try {
        Result<std::size_t> result;
        if (reading) result = co_await stream.read_some(buffer, options);
        else result = co_await stream.write_some(buffer, options);
        CHECK(!result);
        if (!result) error = result.error();
    } catch (const std::runtime_error&) {
        threw = true;
    }
}

Task<void> fault_peer(EventLoop& loop, tcp::Listener& listener, const tls::Context& context,
                      std::size_t peer, Fault fault, bool& exercised, bool& attack) {
    const OperationOptions bounded{.deadline = Clock::now() + 4s};
    Result<tcp::Socket> socket;
    if (peer == 0) socket = co_await listener.accept(bounded);
    else socket = co_await tcp::connect(loop, listener.local_endpoint(), {}, bounded);
    CHECK(socket.has_value());
    if (!socket) co_return;
    StalledSocket transport{*socket, loop};
    auto stream = FaultStream::create(loop, transport, context, peer == 0 ? "" : "localhost");
    CHECK(stream.has_value());
    if (!stream) co_return;
    const auto handshake = co_await stream->handshake(bounded);
    CHECK(handshake.has_value());
    if (!handshake) co_return;
    if (peer == 0) {
        if (fault == Fault::corrupt_record) {
            while (!attack) co_await loop.yield();
            const std::array<std::byte, 7> corrupt{
                std::byte{0x15}, std::byte{3}, std::byte{3}, std::byte{0}, std::byte{2},
                std::byte{2}, std::byte{0x50}};
            const auto sent = co_await write_all(*socket, corrupt, bounded);
            CHECK(sent.has_value());
        }
        while (!exercised) co_await loop.yield();
        co_return;
    }
    const bool reading = fault == Fault::reader_cancel || fault == Fault::reader_timeout ||
                         fault == Fault::corrupt_record;
    std::stop_source stop;
    OperationOptions limited;
    if (fault == Fault::reader_timeout || fault == Fault::writer_timeout)
        limited.deadline = Clock::now() + 20ms;
    if (fault == Fault::reader_cancel || fault == Fault::writer_cancel)
        limited.stop = stop.get_token();
    transport.stall = true;
    std::array<Error, 2> errors{};
    std::array<bool, 2> threw{};
    TaskScope scope;
    scope.spawn(fault_operation(*stream, true, reading ? limited : OperationOptions{}, errors[0], threw[0]));
    transport.zero = fault == Fault::zero_write;
    transport.throws = fault == Fault::exception;
    scope.spawn(fault_operation(*stream, false, reading ? OperationOptions{} : limited, errors[1], threw[1]));
    if (fault != Fault::zero_write && fault != Fault::exception) {
        for (int turn = 0; turn < 16 && (transport.pending_read == 0 || transport.pending_write == 0); ++turn)
            co_await loop.yield();
        std::array<std::byte, 1> duplicate{};
        const auto overlap = co_await stream->write_some(duplicate);
        CHECK(!overlap && overlap.error() == tls::Errc::operation_in_progress);
        CHECK(transport.pending_read == 1);
        CHECK(transport.pending_write == 1);
    }
    attack = true;
    if (fault == Fault::reader_cancel || fault == Fault::writer_cancel) {
        std::jthread cancelling([source = stop] () mutable { source.request_stop(); });
    }
    if (fault == Fault::close) stream->close();
    co_await scope.join();
    CHECK(transport.pending_read == 0 && transport.pending_write == 0);
    if (fault == Fault::close) {
        CHECK(errors[0] == tls::Errc::invalid_state && errors[1] == tls::Errc::invalid_state);
    } else if (fault == Fault::exception) {
        CHECK(threw[1] && !threw[0]);
        CHECK(errors[0] == tls::Errc::invalid_state);
    } else {
        const auto expected = fault == Fault::reader_timeout || fault == Fault::writer_timeout
            ? Mira::make_error_code(Errc::timed_out)
            : fault == Fault::zero_write || fault == Fault::corrupt_record
                ? tls::make_error_code(tls::Errc::protocol_error)
                : Mira::make_error_code(Errc::cancelled);
        CHECK(errors[reading ? 0U : 1U] == expected);
        CHECK(errors[reading ? 1U : 0U] == tls::Errc::invalid_state);
    }
    std::array<std::byte, 1> byte{};
    const auto invalid = co_await stream->write_some(byte);
    CHECK(!invalid && invalid.error() == tls::Errc::invalid_state);
    exercised = true;
}

Task<void> fault_exchange(EventLoop& loop, tcp::Listener& listener, const tls::Context& server,
                          const tls::Context& client, Fault fault) {
    bool exercised = false;
    bool attack = false;
    TaskScope scope;
    scope.spawn(fault_peer(loop, listener, server, 0, fault, exercised, attack));
    scope.spawn(fault_peer(loop, listener, client, 1, fault, exercised, attack));
    co_await scope.join();
}

void test_faults(const Certificates& certificates) {
    test::section("TLS independent deadlines and cross-thread cancellation wake both directions");
    for (const auto fault : {Fault::reader_timeout, Fault::writer_timeout, Fault::reader_cancel,
                             Fault::writer_cancel, Fault::zero_write, Fault::exception,
                             Fault::corrupt_record, Fault::close}) {
        auto server = tls::Context::server(certificates.server, certificates.key);
        auto client = tls::Context::client(certificates.ca);
        auto loop = EventLoop::create();
        CHECK(server && client && loop);
        if (!server || !client || !loop) return;
        auto listener = tcp::Listener::bind(*loop, Endpoint::loopback(0));
        CHECK(listener.has_value());
        if (!listener) return;
        CHECK(loop->run_until_complete(fault_exchange(*loop, *listener, *server, *client, fault)).has_value());
        CHECK(loop->outstanding() == 0);
    }
}

struct Gate {
    EventLoop& loop;
    std::stop_source wake;
    bool waiting = false;
    bool released = false;

    explicit Gate(EventLoop& executor) : loop(executor) {}

    struct Forward {
        std::stop_source wake;
        void operator()() const noexcept {
            auto retained = wake;
            retained.request_stop();
        }
    };

    Task<Result<void>> wait(OperationOptions options) {
        if (options.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (released) co_return Result<void>{};
        waiting = true;
        {
            std::stop_callback forward(options.stop, Forward{wake});
            const auto result = co_await loop.sleep_for(5s, {.stop = wake.get_token()});
            static_cast<void>(result);
        }
        waiting = false;
        if (options.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (!released) co_return fail(Errc::timed_out);
        co_return Result<void>{};
    }

    void release() {
        released = true;
        auto retained = wake;
        retained.request_stop();
    }

    void reset() {
        CHECK(!waiting);
        wake = std::stop_source{};
        released = false;
    }
};

// A synchronous TLS peer with controllable completion gates. A gated read has
// already removed ciphertext from the transport before cancellation can erase
// its completion, reproducing IOCP's consumed-bytes/cancelled-result ordering.
struct EngineTransport {
    tls::Engine peer;
    Gate available;
    Gate read_completion;
    Gate write_completion;
    std::vector<std::byte> incoming;
    Error peer_error;
    bool peer_ready = false;
    bool hold_read = false;
    bool hold_write = false;
    std::stop_source* stop_after_read = nullptr;
    unsigned cancelled_reads = 0;
    unsigned cancelled_writes = 0;
    unsigned reads = 0;
    unsigned writes = 0;

    EngineTransport(EventLoop& loop, tls::Engine engine)
        : peer(std::move(engine)), available{loop}, read_completion{loop}, write_completion{loop} {}

    void drain_peer() {
        std::array<std::byte, tls::Engine::buffer_capacity> bytes{};
        const auto drained = peer.drain(bytes);
        CHECK(drained.has_value());
        if (!drained || *drained == 0) return;
        incoming.insert(incoming.end(), bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(*drained));
        available.release();
    }

    void handshake_peer() {
        if (peer_ready || peer_error) return;
        const auto result = peer.handshake();
        if (!result) peer_error = result.error();
        else peer_ready = result->status == tls::Engine::Status::complete;
        drain_peer();
    }

    void send(std::string_view text) {
        const auto result = peer.write(bytes_of(text));
        CHECK(result && result->status == tls::Engine::Status::complete);
        drain_peer();
    }

    Task<Result<std::size_t>> read_some(std::span<std::byte> bytes, OperationOptions options = {}) {
        CHECK(!options.deadline);
        ++reads;
        while (incoming.empty()) {
            available.reset();
            const auto waiting = co_await available.wait(options);
            if (!waiting) {
                if (waiting.error() == Errc::cancelled) ++cancelled_reads;
                co_return fail(waiting.error());
            }
        }
        const auto size = std::min(bytes.size(), incoming.size());
        std::copy_n(incoming.begin(), size, bytes.begin());
        incoming.erase(incoming.begin(), incoming.begin() + static_cast<std::ptrdiff_t>(size));
        if (auto* stopped = std::exchange(stop_after_read, nullptr)) stopped->request_stop();
        if (std::exchange(hold_read, false)) {
            const auto waiting = co_await read_completion.wait(options);
            if (!waiting) {
                if (waiting.error() == Errc::cancelled) ++cancelled_reads;
                co_return fail(waiting.error());
            }
        }
        co_return size;
    }

    Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes, OperationOptions options = {}) {
        CHECK(!options.deadline);
        ++writes;
        const auto fed = peer.feed(bytes);
        CHECK(fed && *fed == bytes.size());
        if (!fed) co_return fail(fed.error());
        handshake_peer();
        if (std::exchange(hold_write, false)) {
            const auto waiting = co_await write_completion.wait(options);
            if (!waiting) {
                if (waiting.error() == Errc::cancelled) ++cancelled_writes;
                co_return fail(waiting.error());
            }
        }
        co_return bytes.size();
    }
};

using GatedStream = tls::Stream<EngineTransport>;

Task<void> gated_read(GatedStream& stream, bool& done, Error& error, OperationOptions options = {}) {
    std::array<std::byte, 8> bytes{};
    const auto result = co_await stream.read_some(bytes, options);
    if (!result) error = result.error();
    else CHECK(std::string_view(reinterpret_cast<const char*>(bytes.data()), *result) == "reply");
    done = true;
}

Task<void> gated_write(GatedStream& stream, bool& done, Error& error, OperationOptions options = {}) {
    const auto result = co_await stream.write_some(bytes_of("request"), options);
    if (!result) error = result.error();
    else CHECK(*result == 7);
    done = true;
}

Task<void> gated_handshake(GatedStream& stream, bool& done, Error& error, OperationOptions options) {
    const auto result = co_await stream.handshake(options);
    if (!result) error = result.error();
    done = true;
}

Task<void> test_late_deadline(EventLoop& loop, GatedStream& stream, EngineTransport& transport) {
    const auto handshake = co_await stream.handshake();
    CHECK(handshake.has_value());
    if (!handshake) co_return;
    transport.send("reply");
    transport.hold_read = true;
    bool read_done = false;
    bool write_done = false;
    Error read_error, write_error;
    TaskScope scope;
    scope.spawn(gated_read(stream, read_done, read_error));
    CHECK(transport.read_completion.waiting);
    CHECK(!read_done);
    scope.spawn(gated_write(stream, write_done, write_error, {.deadline = Clock::now() + 2s}));
    while (!write_done) co_await loop.yield();
    CHECK(!write_error);
    CHECK(!read_done);
    CHECK(transport.cancelled_reads == 0);
    transport.read_completion.release();
    co_await scope.join();
    CHECK(read_done && !read_error);
    CHECK(transport.cancelled_reads == 0 && transport.cancelled_writes == 0);
    const auto subsequent = co_await stream.write_some({});
    CHECK(subsequent.has_value());
}

Task<void> test_independent_watermark(EventLoop& loop, GatedStream& stream, EngineTransport& transport) {
    const auto handshake = co_await stream.handshake();
    CHECK(handshake.has_value());
    if (!handshake) co_return;
    transport.send("reply");
    transport.hold_write = true;
    bool read_done = false;
    bool write_done = false;
    Error read_error, write_error;
    TaskScope scope;
    scope.spawn(gated_write(stream, write_done, write_error));
    CHECK(transport.write_completion.waiting && !write_done);
    scope.spawn(gated_read(stream, read_done, read_error, {.deadline = Clock::now() + 100ms}));
    while (!read_done) co_await loop.yield();
    CHECK(!read_error);
    CHECK(!write_done);
    CHECK(transport.cancelled_writes == 0);
    transport.write_completion.release();
    co_await scope.join();
    CHECK(write_done && !write_error);
}

Task<void> test_registration_stop(EventLoop& loop, std::optional<GatedStream>& owner,
                                  EngineTransport& transport) {
    const auto handshake = co_await owner->handshake();
    CHECK(handshake.has_value());
    if (!handshake) co_return;
    transport.send("reply");
    std::stop_source stop;
    transport.stop_after_read = &stop;
    std::array<std::byte, 8> bytes{};
    const auto result = co_await owner->read_some(bytes, {.stop = stop.get_token()});
    CHECK(!result && result.error() == Errc::cancelled);
    // Cancellation was posted during await_suspend's synchronous transport
    // drive. Destroy the owner before the queued weak callback is dispatched.
    owner.reset();
    co_await loop.yield();
    CHECK(loop.outstanding() == 0);
}

Task<void> test_rejected_options(GatedStream& stream, EngineTransport& transport) {
    const auto handshake = co_await stream.handshake();
    CHECK(handshake.has_value());
    if (!handshake) co_return;
    bool read_done = false;
    Error read_error;
    TaskScope scope;
    scope.spawn(gated_read(stream, read_done, read_error));
    CHECK(!read_done);
    std::stop_source stopped;
    stopped.request_stop();
    const auto cancelled = co_await stream.write_some(bytes_of("ignored"), {.stop = stopped.get_token()});
    CHECK(!cancelled && cancelled.error() == Errc::cancelled);
    const auto expired = co_await stream.write_some(bytes_of("ignored"), {.deadline = Clock::now()});
    CHECK(!expired && expired.error() == Errc::timed_out);
    CHECK(!read_done && transport.cancelled_reads == 0);
    transport.send("reply");
    co_await scope.join();
    CHECK(read_done && !read_error);
    CHECK(transport.cancelled_reads == 0);
}

Task<void> test_pending_alert(EventLoop& loop, GatedStream& stream, EngineTransport& transport,
                              bool cancel_alert) {
    transport.hold_write = true;
    bool done = false;
    Error error;
    std::stop_source stop;
    TaskScope scope;
    scope.spawn(gated_handshake(stream, done, error,
                                {.stop = stop.get_token(), .deadline = Clock::now() + 2s}));
    CHECK(!done && transport.write_completion.waiting);
    CHECK(transport.reads > 0);
    CHECK(transport.cancelled_writes == 0);
    if (cancel_alert) stop.request_stop();
    else transport.write_completion.release();
    co_await scope.join();
    CHECK(done && error == tls::Errc::certificate_verify_failed);
    if (cancel_alert) {
        CHECK(transport.cancelled_writes == 1);
        CHECK(transport.writes == 1);
    } else {
        CHECK(transport.cancelled_writes == 0);
        CHECK(transport.writes > 1);
        CHECK(transport.peer_error == tls::Errc::protocol_error);
    }
    CHECK(loop.outstanding() == 0);
}

Task<void> destroy_after_read(std::optional<GatedStream>& owner, bool& done) {
    std::array<std::byte, 8> bytes{};
    const auto result = co_await owner->read_some(bytes, {.deadline = Clock::now() + 2s});
    CHECK(result && *result == 5);
    owner.reset();
    done = true;
}

Task<void> test_owner_destruction(EventLoop& loop, std::optional<GatedStream>& owner,
                                  EngineTransport& transport) {
    const auto handshake = co_await owner->handshake();
    CHECK(handshake.has_value());
    if (!handshake) co_return;
    bool done = false;
    TaskScope scope;
    scope.spawn(destroy_after_read(owner, done));
    CHECK(!done);
    transport.send("reply");
    co_await scope.join();
    CHECK(done && !owner);
    CHECK(loop.outstanding() == 0);
}

void test_deterministic_scheduling(const Certificates& certificates) {
    test::section("TLS deterministic completion ordering, cancellation, watermarks and fatal alerts");
    for (unsigned scenario = 0; scenario < 7; ++scenario) {
        auto loop = EventLoop::create();
        auto server = tls::Context::server(certificates.server, certificates.key);
        auto client = tls::Context::client(scenario == 3 || scenario == 4
                                              ? certificates.other_ca : certificates.ca);
        CHECK(loop && server && client);
        if (!loop || !server || !client) return;
        auto peer = tls::Engine::create(*server);
        CHECK(peer.has_value());
        if (!peer) return;
        EngineTransport transport{*loop, std::move(*peer)};
        auto created = GatedStream::create(*loop, transport, *client, "localhost");
        CHECK(created.has_value());
        if (!created) return;
        std::optional<GatedStream> owner{std::move(*created)};
        if (scenario == 0)
            CHECK(loop->run_until_complete(test_late_deadline(*loop, *owner, transport)).has_value());
        else if (scenario == 1)
            CHECK(loop->run_until_complete(test_independent_watermark(*loop, *owner, transport)).has_value());
        else if (scenario == 2)
            CHECK(loop->run_until_complete(test_rejected_options(*owner, transport)).has_value());
        else if (scenario == 3 || scenario == 4)
            CHECK(loop->run_until_complete(test_pending_alert(*loop, *owner, transport, scenario == 4)).has_value());
        else if (scenario == 5)
            CHECK(loop->run_until_complete(test_owner_destruction(*loop, owner, transport)).has_value());
        else
            CHECK(loop->run_until_complete(test_registration_stop(*loop, owner, transport)).has_value());
        CHECK(loop->outstanding() == 0);
    }
}

struct KeyUpdateTransport {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context{nullptr, SSL_CTX_free};
    std::unique_ptr<SSL, decltype(&SSL_free)> peer{nullptr, SSL_free};
    BIO* input = nullptr;
    BIO* output = nullptr;
    Gate available;
    Gate write_completion;
    std::string received;
    bool ready = false;
    bool hold_write = false;
    unsigned updates = 0;

    explicit KeyUpdateTransport(EventLoop& loop, const Certificates& certificates)
        : available{loop}, write_completion{loop} {
        context.reset(SSL_CTX_new(TLS_server_method()));
        require(context != nullptr);
        require(SSL_CTX_use_certificate_chain_file(context.get(), certificates.server.c_str()) == 1);
        require(SSL_CTX_use_PrivateKey_file(context.get(), certificates.key.c_str(), SSL_FILETYPE_PEM) == 1);
        peer.reset(SSL_new(context.get()));
        require(peer != nullptr);
        input = BIO_new(BIO_s_mem());
        output = BIO_new(BIO_s_mem());
        require(input && output);
        SSL_set_bio(peer.get(), input, output);
        SSL_set_accept_state(peer.get());
        SSL_set_msg_callback(peer.get(), &KeyUpdateTransport::message);
        SSL_set_msg_callback_arg(peer.get(), this);
    }

    static void message(int writing, int, int content_type, const void* data,
                         std::size_t size, SSL*, void* argument) {
        if (writing == 0 && content_type == SSL3_RT_HANDSHAKE && size != 0 &&
            *static_cast<const unsigned char*>(data) == SSL3_MT_KEY_UPDATE)
            ++static_cast<KeyUpdateTransport*>(argument)->updates;
    }

    void notify() {
        if (BIO_ctrl_pending(output) != 0) available.release();
    }

    void drive() {
        ERR_clear_error();
        if (!ready) {
            const int result = SSL_do_handshake(peer.get());
            const int error = result == 1 ? SSL_ERROR_NONE : SSL_get_error(peer.get(), result);
            CHECK(error == SSL_ERROR_NONE || error == SSL_ERROR_WANT_READ);
            ready = result == 1;
        } else {
            std::array<std::byte, 16384> bytes{};
            for (;;) {
                std::size_t count = 0;
                ERR_clear_error();
                const int result = SSL_read_ex(peer.get(), bytes.data(), bytes.size(), &count);
                const int error = result == 1 ? SSL_ERROR_NONE : SSL_get_error(peer.get(), result);
                if (result == 1) {
                    received.append(reinterpret_cast<const char*>(bytes.data()), count);
                } else {
                    CHECK(error == SSL_ERROR_WANT_READ);
                    break;
                }
            }
        }
        notify();
    }

    void update_and_send() {
        require(SSL_version(peer.get()) == TLS1_3_VERSION);
        ERR_clear_error();
        require(SSL_key_update(peer.get(), SSL_KEY_UPDATE_REQUESTED) == 1);
        std::size_t count = 0;
        ERR_clear_error();
        require(SSL_write_ex(peer.get(), "reply", 5, &count) == 1 && count == 5);
        notify();
    }

    Task<Result<std::size_t>> read_some(std::span<std::byte> bytes, OperationOptions options = {}) {
        while (BIO_ctrl_pending(output) == 0) {
            available.reset();
            const auto waiting = co_await available.wait(options);
            if (!waiting) co_return fail(waiting.error());
        }
        const auto result = BIO_read(output, bytes.data(), static_cast<int>(bytes.size()));
        CHECK(result > 0);
        co_return static_cast<std::size_t>(result);
    }

    Task<Result<std::size_t>> write_some(std::span<const std::byte> bytes, OperationOptions options = {}) {
        const auto result = BIO_write(input, bytes.data(), static_cast<int>(bytes.size()));
        CHECK(result == static_cast<int>(bytes.size()));
        drive();
        if (std::exchange(hold_write, false)) {
            const auto waiting = co_await write_completion.wait(options);
            if (!waiting) co_return fail(waiting.error());
        }
        co_return bytes.size();
    }
};

Task<void> key_update_writer(tls::Stream<KeyUpdateTransport>& stream, bool& done) {
    const auto result = co_await stream.write_some(bytes_of("request"));
    CHECK(result && *result == 7);
    done = true;
}

Task<void> key_update_exchange(EventLoop& loop, tls::Stream<KeyUpdateTransport>& stream,
                               KeyUpdateTransport& transport) {
    const auto handshake = co_await stream.handshake({.deadline = Clock::now() + 2s});
    CHECK(handshake.has_value());
    if (!handshake) co_return;
    transport.hold_write = true;
    bool write_done = false;
    TaskScope scope;
    scope.spawn(key_update_writer(stream, write_done));
    // This continuation can run inside TLS pump(); the nested request is
    // registered immediately, but its wire submission follows after yielding.
    co_await loop.yield();
    CHECK(!write_done && transport.write_completion.waiting);
    transport.update_and_send();
    std::array<std::byte, 8> bytes{};
    const auto read = co_await stream.read_some(bytes, {.deadline = Clock::now() + 2s});
    CHECK(read && *read == 5);
    CHECK(!write_done);
    transport.write_completion.release();
    co_await scope.join();
    const auto reply = co_await stream.write_some(bytes_of("updated"), {.deadline = Clock::now() + 2s});
    CHECK(reply && *reply == 7);
    CHECK(transport.received == "requestupdated");
    CHECK(transport.updates == 1);
}

void test_key_update(const Certificates& certificates) {
    test::section("TLS 1.3 KeyUpdate while the opposite ciphertext write is pending");
    auto loop = EventLoop::create();
    auto client = tls::Context::client(certificates.ca);
    CHECK(loop && client);
    if (!loop || !client) return;
    KeyUpdateTransport transport{*loop, certificates};
    auto stream = tls::Stream<KeyUpdateTransport>::create(*loop, transport, *client, "localhost");
    CHECK(stream.has_value());
    if (!stream) return;
    CHECK(loop->run_until_complete(key_update_exchange(*loop, *stream, transport)).has_value());
    CHECK(loop->outstanding() == 0);
}

void test_configuration(const Certificates& certificates) {
    test::section("TLS configuration errors and error domains");
    const auto missing = (certificates.directory / "does-not-exist.pem").string();
    const auto client = tls::Context::client(missing);
    CHECK(!client && client.error() == tls::Errc::configuration_error);
    const auto server = tls::Context::server(certificates.server, missing);
    CHECK(!server && server.error() == tls::Errc::configuration_error);
    const auto mismatched = tls::Context::server(certificates.ca, certificates.key);
    CHECK(!mismatched && mismatched.error() == tls::Errc::configuration_error);
    CHECK(tls::make_error_code(tls::Errc::truncated) != make_error_code(Errc::eof));
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2) {
        std::set_terminate([] { std::_Exit(77); });
        auto context = tls::Context::client();
        auto loop = EventLoop::create();
        if (!context || !loop) return 2;
        ControlledTransport transport;
        auto created = tls::Stream<ControlledTransport>::create(*loop, transport, *context, "localhost");
        if (!created) return 2;
        std::optional<tls::Stream<ControlledTransport>> stream{std::move(*created)};
        Error error;
        int done = 0;
        start_handshake(*stream, error, done);
        if (done != 0 || !transport.waiting) return 3;
        const std::string_view mode(argv[1]);
        if (mode == "--destroy-active") stream.reset();
        else if (mode == "--move-active") {
            auto moved = std::move(*stream);
            static_cast<void>(moved);
        } else if (mode == "--replace-active") {
            auto replacement = tls::Stream<ControlledTransport>::create(*loop, transport, *context, "localhost");
            if (!replacement) return 2;
            *stream = std::move(*replacement);
        }
        return 4;
    }
    try {
        Certificates certificates;
        certificates.create();
        test_configuration(certificates);
        test_duplex(certificates);
        test_deterministic_scheduling(certificates);
        test_key_update(certificates);
        test_faults(certificates);
        test_mtls(certificates);
        test_alpn(certificates);
        test_shared_buffer_budget(certificates);
        test_concurrent_operations(certificates);
        test_options_reach_the_underlying_stream(certificates);
        run_exchange(certificates, "HTTPS DNS identity verification and close_notify", "localhost");
        run_exchange(certificates, "HTTPS IP SAN identity verification", "127.0.0.1");
        run_exchange(certificates,
                     "HTTPS ALPN http/1.1",
                     "localhost",
                     Scenario::https,
                     false,
                     113,
                     4096,
                     "http/1.1");
        run_exchange(certificates,
                     "ALPN mismatch must fail",
                     "localhost",
                     Scenario::alpn_failure,
                     false,
                     113,
                     4,
                     "http/1.1");
        run_exchange(certificates,
                     "HTTPS large payload with short ciphertext I/O",
                     "localhost",
                     Scenario::https,
                     false,
                     113,
                     192 * 1024);
        run_exchange(certificates,
                     "TLS rejects unknown CA",
                     "localhost",
                     Scenario::verify_failure,
                     true);
        run_exchange(
            certificates, "TLS DNS hostname mismatch", "wrong.example", Scenario::verify_failure);
        run_exchange(certificates, "TLS IP SAN mismatch", "127.0.0.2", Scenario::verify_failure);
        run_exchange(
            certificates,
            "TLS bare TCP EOF must not count as a clean close",
            "localhost",
            Scenario::truncated);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        CHECK(false);
    }
    return test::summary();
}
