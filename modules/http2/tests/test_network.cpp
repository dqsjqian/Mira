#include "check.hpp"
#include "mira/core/task_scope.hpp"
#include "mira/http2/connection.hpp"
#include "mira/transport/tcp.hpp"
#ifdef MIRA_HTTP2_TEST_TLS
#include "mira/tls/stream.hpp"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <filesystem>
#include <memory>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <map>
#include <stdexcept>
#include <string>

using namespace Mira;
using namespace Mira::transport;
using namespace Mira::http2;
using namespace std::chrono_literals;

namespace {
void require(bool ok) { if (!ok) throw std::runtime_error("HTTP2 network test precondition failed"); }
std::span<const std::byte> bytes(const std::string& text) { return std::as_bytes(std::span(text)); }
Headers request_headers(std::string path, std::string method = "GET") {
    return {{":method", std::move(method)}, {":scheme", "https"}, {":authority", "localhost"}, {":path", std::move(path)}};
}
struct FragmentedSocket {
    tcp::Socket& socket;
    Task<Result<std::size_t>> read_some(std::span<std::byte> buffer, OperationOptions options = {}) {
        co_return co_await socket.read_some(buffer.first(std::min<std::size_t>(137, buffer.size())), options);
    }
    Task<Result<std::size_t>> write_some(std::span<const std::byte> buffer, OperationOptions options = {}) {
        co_return co_await socket.write_some(buffer.first(std::min<std::size_t>(251, buffer.size())), options);
    }
};
struct Results { bool server = false; bool client = false; };

template<BoundedStream S>
Task<void> serve(S& transport, Results& results, OperationOptions options) {
    auto session = Session::create(Role::server);
    require(session.has_value());
    Connection connection(transport, std::move(*session));
    std::map<std::int32_t, std::vector<std::byte>> uploads;
    std::map<std::int32_t, bool> responded;
    unsigned completed = 0;
    while (completed < 2) {
        auto result = co_await connection.pump(options);
        CHECK(result.has_value());
        if (!result) co_return;
        for (auto id : connection.session().streams()) {
            const auto* stream = connection.session().stream(id);
            if (stream->error || responded[id]) continue;
            auto chunk = connection.session().take_body(id);
            CHECK(chunk.has_value());
            if (!chunk) co_return;
            uploads[id].insert(uploads[id].end(), chunk->begin(), chunk->end());
            if (!stream->remote_end) continue;
            if (!uploads[id].empty()) {
                CHECK(uploads[id].size() == 150000);
                CHECK(uploads[id][19] == std::byte{0});
            }
            const auto body = uploads[id].empty() ? std::vector<std::byte>{std::byte{'o'}, std::byte{'k'}} : uploads[id];
            CHECK(connection.session().respond(id, {{":status", "200"}}, body).has_value());
            responded[id] = true;
            ++completed;
        }
        const auto flushed = co_await connection.flush(options);
        CHECK(flushed.has_value());
    }
    // Large responses may still be waiting on stream windows; keep driving until both streams close.
    for (;;) {
        bool closed = true;
        for (auto id : connection.session().streams()) if (!connection.session().stream(id)->closed) closed = false;
        if (closed) break;
        auto result = co_await connection.pump(options);
        CHECK(result.has_value());
        if (!result) co_return;
    }
    CHECK(connection.session().goaway().has_value());
    const auto flushed = co_await connection.flush(options);
    CHECK(flushed.has_value());
    results.server = true;
}

template<BoundedStream S>
Task<void> query(S& transport, Results& results, OperationOptions options) {
    auto session = Session::create(Role::client);
    require(session.has_value());
    Connection connection(transport, std::move(*session));
    std::string payload(150000, 'q'); payload[19] = '\0';
    auto post = connection.session().request(request_headers("/echo", "POST"), bytes(payload));
    auto get = connection.session().request(request_headers("/small"));
    require(post.has_value() && get.has_value());
    std::map<std::int32_t, std::vector<std::byte>> bodies;
    for (;;) {
        auto result = co_await connection.pump(options);
        CHECK(result.has_value());
        if (!result) co_return;
        bool complete = true;
        for (auto id : {*post, *get}) {
            const auto* stream = connection.session().stream(id);
            CHECK(!stream->error);
            auto chunk = connection.session().take_body(id);
            CHECK(chunk.has_value());
            if (!chunk) co_return;
            bodies[id].insert(bodies[id].end(), chunk->begin(), chunk->end());
            if (!stream->remote_end) complete = false;
        }
        const auto flushed = co_await connection.flush(options);
        CHECK(flushed.has_value());
        if (complete) break;
    }
    CHECK(bodies[*post] == std::vector<std::byte>(bytes(payload).begin(), bytes(payload).end()));
    CHECK(bodies[*get] == std::vector<std::byte>({std::byte{'o'}, std::byte{'k'}}));
    // Confirm the server GOAWAY has fully arrived before letting the underlying socket destruct.
    while (connection.session().state() == State::open) {
        auto result = co_await connection.read(options);
        CHECK(result.has_value());
        if (!result) co_return;
    }
    CHECK(!connection.session().request(request_headers("/after-goaway")));
    results.client = true;
}

#ifdef MIRA_HTTP2_TEST_TLS
struct CertificateFiles {
    std::filesystem::path directory;
    std::string certificate;
    std::string key;
    CertificateFiles() {
        std::array<unsigned char, 12> random{};
        require(RAND_bytes(random.data(), static_cast<int>(random.size())) == 1);
        std::string suffix;
        constexpr char hex[] = "0123456789abcdef";
        for (auto value : random) { suffix += hex[value >> 4]; suffix += hex[value & 15]; }
        directory = std::filesystem::path(MIRA_HTTP2_TEST_BINARY_DIR) / ("h2-cert-" + suffix);
        require(std::filesystem::create_directory(directory));
        std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
        certificate = (directory / "cert.pem").string(); key = (directory / "key.pem").string();
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
        require(context && EVP_PKEY_keygen_init(context.get()) == 1);
        require(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), NID_X9_62_prime256v1) == 1);
        EVP_PKEY* raw = nullptr;
        require(EVP_PKEY_keygen(context.get(), &raw) == 1);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> private_key(raw, EVP_PKEY_free);
        std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
        require(cert && X509_set_version(cert.get(), 2) == 1);
        require(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) == 1);
        require(X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600) != nullptr);
        require(X509_gmtime_adj(X509_getm_notAfter(cert.get()), 86400) != nullptr);
        require(X509_set_pubkey(cert.get(), private_key.get()) == 1);
        auto* name = X509_get_subject_name(cert.get());
        require(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                    reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) == 1);
        require(X509_set_issuer_name(cert.get(), name) == 1);
        X509V3_CTX ext_context{};
        X509V3_set_ctx(&ext_context, cert.get(), cert.get(), nullptr, nullptr, 0);
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(
            X509V3_EXT_conf_nid(nullptr, &ext_context, NID_subject_alt_name, "DNS:localhost"), X509_EXTENSION_free);
        require(ext && X509_add_ext(cert.get(), ext.get(), -1) == 1);
        require(X509_sign(cert.get(), private_key.get(), EVP_sha256()) > 0);
        std::unique_ptr<BIO, decltype(&BIO_free)> cert_out(BIO_new_file(certificate.c_str(), "w"), BIO_free);
        std::unique_ptr<BIO, decltype(&BIO_free)> key_out(BIO_new_file(key.c_str(), "w"), BIO_free);
        require(cert_out && key_out);
        require(PEM_write_bio_X509(cert_out.get(), cert.get()) == 1);
        require(PEM_write_bio_PrivateKey(key_out.get(), private_key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1);
    }
    ~CertificateFiles() {
        std::error_code ignored;
        std::filesystem::remove(certificate, ignored);
        std::filesystem::remove(key, ignored);
        std::filesystem::remove(directory, ignored);
    }
};
#endif

Task<void> server_task(tcp::Listener& listener, Results& results, OperationOptions options
#ifdef MIRA_HTTP2_TEST_TLS
    , const tls::Context* context
#endif
) {
    auto socket = co_await listener.accept(options);
    CHECK(socket.has_value());
    if (!socket) co_return;
    FragmentedSocket fragmented{*socket};
#ifdef MIRA_HTTP2_TEST_TLS
    if (context) {
        auto secured = tls::Stream<FragmentedSocket>::create(fragmented, *context);
        require(secured.has_value());
        auto result = co_await secured->handshake(options);
        CHECK(result.has_value());
        if (!result) co_return;
        CHECK(secured->negotiated_protocol() == "h2");
        co_await serve(*secured, results, options);
        co_return;
    }
#endif
    co_await serve(fragmented, results, options);
}
Task<void> client_task(EventLoop& loop, Endpoint endpoint, Results& results, OperationOptions options
#ifdef MIRA_HTTP2_TEST_TLS
    , const tls::Context* context
#endif
) {
    auto socket = co_await tcp::connect(loop, endpoint, {}, options);
    CHECK(socket.has_value());
    if (!socket) co_return;
    FragmentedSocket fragmented{*socket};
#ifdef MIRA_HTTP2_TEST_TLS
    if (context) {
        auto secured = tls::Stream<FragmentedSocket>::create(fragmented, *context, "localhost");
        require(secured.has_value());
        auto result = co_await secured->handshake(options);
        CHECK(result.has_value());
        if (!result) co_return;
        CHECK(secured->negotiated_protocol() == "h2");
        co_await query(*secured, results, options);
        co_return;
    }
#endif
    co_await query(fragmented, results, options);
}
Task<void> scenario(EventLoop& loop
#ifdef MIRA_HTTP2_TEST_TLS
    , const tls::Context* client, const tls::Context* server
#endif
) {
    auto listener = tcp::Listener::bind(loop, Endpoint::loopback(0));
    require(listener.has_value());
    Results results;
    OperationOptions options{.deadline = Clock::now() + 15s};
    TaskScope tasks;
    tasks.spawn(server_task(*listener, results, options
#ifdef MIRA_HTTP2_TEST_TLS
        , server
#endif
    ));
    tasks.spawn(client_task(loop, listener->local_endpoint(), results, options
#ifdef MIRA_HTTP2_TEST_TLS
        , client
#endif
    ));
    co_await tasks.join();
    CHECK(results.server && results.client);
}
} // namespace

int main() {
    auto loop = EventLoop::create();
    require(loop.has_value());
    auto plain_result = loop->run_until_complete(scenario(*loop
#ifdef MIRA_HTTP2_TEST_TLS
        , nullptr, nullptr
#endif
    ));
    CHECK(plain_result.has_value());
#ifdef MIRA_HTTP2_TEST_TLS
    CertificateFiles files;
    const std::array<std::string_view, 2> client_protocols{"http/1.1", "h2"};
    const std::array<std::string_view, 2> server_protocols{"h2", "http/1.1"};
    auto client = tls::Context::client_alpn(files.certificate, client_protocols);
    auto server = tls::Context::server_alpn(files.certificate, files.key, server_protocols);
    require(client.has_value() && server.has_value());
    CHECK(loop->run_until_complete(scenario(*loop, &*client, &*server)).has_value());
#endif
    return test::summary();
}
