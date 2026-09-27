#include "check.hpp"
#include "mira/http/connection.hpp"
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
#include <openssl/evp.h>
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

DetachedTask run_server(tcp::Listener& listener,
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
    auto created = tls::Stream<FragmentedSocket>::create(transport, context);
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
    auto created = tls::Stream<FragmentedSocket>::create(transport, context, peer_name);
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
    run_server(*listener, *server_context, exchange, scenario, fragment);
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

/// Records what every underlying operation was handed, and refuses the handshake
/// once the test has seen enough.
///
/// `tls::Stream` drives its underlying stream an unbounded number of times per
/// TLS operation, so "the deadline reached the underlying stream" is not one
/// assertion but a claim about every one of those turns.
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

void test_options_reach_the_underlying_stream(const Certificates& certificates) {
    test::section("TLS hands the same absolute deadline to every underlying read and write");

    Result<tls::Context> context = tls::Context::client(certificates.ca);
    CHECK(context.has_value());
    if (!context) {
        return;
    }

    RecordingTransport transport;
    transport.allowed_writes = 2;  // let the ClientHello out, then stop
    Result<tls::Stream<RecordingTransport>> stream =
        tls::Stream<RecordingTransport>::create(transport, *context, "localhost");
    CHECK(stream.has_value());
    if (!stream) {
        return;
    }

    // One absolute deadline for the whole handshake. No layer subtracts
    // elapsed time — that is the property that made absolute the right choice,
    // and it is only observable from down here.
    const auto deadline = Clock::now() + std::chrono::seconds{30};
    const Result<void> handshake = stream->handshake({.deadline = deadline}).sync_get();
    CHECK(!handshake);  // the transport refused before the handshake could finish

    CHECK(!transport.seen.empty());
    bool every_turn_carried_it = !transport.seen.empty();
    for (const std::optional<Clock::time_point>& observed : transport.seen) {
        every_turn_carried_it =
            every_turn_carried_it && observed.has_value() && *observed == deadline;
    }
    CHECK(every_turn_carried_it);

    // And with no options, nothing is invented on the way down.
    RecordingTransport plain;
    plain.allowed_writes = 2;
    Result<tls::Stream<RecordingTransport>> bare =
        tls::Stream<RecordingTransport>::create(plain, *context, "localhost");
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

void test_concurrent_operations(const Certificates& certificates) {
    test::section("TLS overlapping operations and zero-progress ciphertext writes");
    auto context = tls::Context::client(certificates.ca);
    CHECK(context.has_value());
    if (!context) {
        return;
    }
    ControlledTransport transport;
    auto created = tls::Stream<ControlledTransport>::create(transport, *context, "localhost");
    CHECK(created.has_value());
    if (!created) {
        return;
    }
    auto moved = std::move(*created);
    auto missing_name = tls::Stream<ControlledTransport>::create(transport, *context);
    CHECK(!missing_name && missing_name.error() == Errc::invalid_argument);
    const std::string embedded_nul{"localhost\0wrong.example", 23};
    auto invalid_name = tls::Stream<ControlledTransport>::create(transport, *context, embedded_nul);
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
    auto stream = tls::Stream<ControlledTransport>::create(no_progress, *context, "localhost");
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
    auto stream = tls::Stream<tcp::Socket>::create(socket, *context, peer == 0 ? "" : "localhost");
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
    auto stream = tls::Stream<tcp::Socket>::create(socket, *context, peer == 0 ? "" : "localhost");
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

int main() {
    try {
        Certificates certificates;
        certificates.create();
        test_configuration(certificates);
        test_mtls(certificates);
        test_alpn(certificates);
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
