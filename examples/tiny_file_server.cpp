// A tiny file server, in the shape Mira intends.
//
// This example exists because "hello world" proves the library compiles and
// not much else. A file server is the smallest program that makes three
// things matter at once:
//
//   * streaming request bodies — an upload must not be buffered whole in
//     memory (that is the difference between an `auto&` third handler
//     parameter and `std::span<const std::byte>`; here it is a
//     `RequestBodyReader` piping slices straight to disk);
//   * streaming responses — a download goes out chunked via
//     `send_head_chunked` / `write` / `finish` when only the filesystem
//     knows the length, and via `send` when the handler does;
//   * refusing work — traversal attempts and oversized uploads are
//     answered with 4xx, never trusted, never fatal.
//
// Scope, deliberately: no ranges, no caching, no conditional GET, plaintext
// HTTP only, and a MIME table short enough to read. The examples directory
// is teaching material; this file teaches the streaming contracts.
//
// Usage: mira_tiny_file_server [port] [root-directory] [--allow-upload]
// Uploads are disabled unless explicitly enabled; do not expose this demo publicly.
//   port             0 (the default) binds an ephemeral loopback port
//   root-directory   "." (the default); everything resolves under it
// Interruption uses the default signal behavior, not graceful shutdown.

#include <mira/core/event_loop.hpp>
#include <mira/core/task.hpp>
#include <mira/core/task_scope.hpp>
#include <mira/http/connection.hpp>
#include <mira/transport/tcp.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

using Mira::EventLoop;
using Mira::Result;
using Mira::Task;
using Mira::TaskScope;
using Mira::http::Method;
using Mira::http::Request;
using Mira::http::Response;
using Mira::http::serve_connection;
namespace tcp = Mira::transport::tcp;

namespace fs = std::filesystem;

namespace {

constexpr std::size_t k_io_slice = 64 * 1024;
constexpr std::uint64_t k_max_upload = 128ULL * 1024 * 1024;

template <typename Integer>
bool parse_number(std::string_view text, Integer& value) {
    if (text.empty()) {
        return false;
    }
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc{} && end == text.data() + text.size();
}

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::span<const std::byte>{reinterpret_cast<const std::byte*>(text.data()),
                                      text.size()};
}

/// Percent-decode `%XX` escapes; a malformed escape passes through literally.
std::string percent_decode(std::string_view text) {
    static constexpr std::string_view hex = "0123456789abcdef";
    std::string out;
    out.reserve(text.size());
    for (std::size_t at = 0; at < text.size(); ++at) {
        if (text[at] == '%' && at + 2 < text.size()) {
            const auto hi = hex.find(static_cast<char>(std::tolower(text[at + 1])));
            const auto lo = hex.find(static_cast<char>(std::tolower(text[at + 2])));
            if (hi != std::string_view::npos && lo != std::string_view::npos) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                at += 2;
                continue;
            }
        }
        out.push_back(text[at]);
    }
    return out;
}

/// Resolve the request target under `root`; nothing when it escapes.
///
/// Both sides go through `weakly_canonical`, so `..` walks and planted
/// symlinks cannot leave the root. A leading `/` is stripped — request
/// targets are root-relative by definition.
std::optional<fs::path> resolve_under_root(const fs::path& root, std::string_view target) {
    std::string decoded = percent_decode(target);
    // Strip query and fragment — a file server ignores both.
    if (const auto q = decoded.find('?'); q != std::string::npos) {
        decoded.resize(q);
    }
    while (!decoded.empty() && decoded.front() == '/') {
        decoded.erase(decoded.begin());
    }
    if (decoded.empty()) {
        decoded = ".";
    }
    const fs::path wanted{decoded};

    std::error_code ec;
    const fs::path base = fs::weakly_canonical(root, ec);
    if (ec || base.empty()) {
        return std::nullopt;
    }
    const fs::path anchored = fs::weakly_canonical(root / wanted, ec);
    if (ec || anchored.empty()) {
        return std::nullopt;
    }

    // `anchored` must begin with the whole of `base`.
    if (const auto mismatched = std::mismatch(base.begin(), base.end(), anchored.begin(),
                                              anchored.end());
        mismatched.first != base.end()) {
        return std::nullopt;
    }
    return anchored;
}

std::string_view mime_for(const fs::path& path) {
    const std::string ext = path.extension().string();
    if (ext == ".html" || ext == ".htm") return "text/html; charset=utf-8";
    if (ext == ".css") return "text/css";
    if (ext == ".js") return "text/javascript";
    if (ext == ".json") return "application/json";
    if (ext == ".png") return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".svg") return "image/svg+xml";
    if (ext == ".txt" || ext == ".md") return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

/// A streaming download: chunked framing, one buffer of heap at a time.
Task<Result<void>> stream_file(auto& writer, const fs::path& path) {
    std::ifstream file{path, std::ios::binary};
    if (!file) {
        co_return Mira::fail(Mira::Errc::not_supported);
    }

    Response response;
    response.status = 200;
    response.headers.append("Content-Type", std::string{mime_for(path)});
    const Result<void> head = co_await writer.send_head_chunked(response);
    if (!head) {
        co_return head;
    }

    std::array<char, k_io_slice> chunk{};
    while (file) {
        file.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const std::streamsize got = file.gcount();
        if (got > 0) {
            const Result<void> written = co_await writer.write(
                std::span{reinterpret_cast<const std::byte*>(chunk.data()),
                          static_cast<std::size_t>(got)});
            if (!written) {
                co_return written;
            }
        }
    }
    co_return co_await writer.finish();
}

/// A streaming upload: pull slices from the network to disk. Peak memory is
/// one buffer, not the file size.
Task<Result<void>> receive_upload(auto& body_reader, const fs::path& path) {
    std::ofstream file{path, std::ios::binary | std::ios::trunc};
    if (!file) {
        co_return Mira::fail(Mira::Errc::not_supported);
    }

    std::array<std::byte, k_io_slice> buf{};
    std::uint64_t total = 0;
    for (;;) {
        const Result<std::size_t> got = co_await body_reader.read(buf);
        if (!got) {
            co_return Mira::fail(got.error());
        }
        if (*got == 0) {
            co_return Result<void>{};
        }
        total += *got;
        if (total > k_max_upload) {
            co_return Mira::fail(Mira::Errc::limit_exceeded);
        }
        file.write(reinterpret_cast<const char*>(buf.data()),
                   static_cast<std::streamsize>(*got));
        if (!file) {
            co_return Mira::fail(Mira::Errc::internal);
        }
    }
}

/// Directory listing for GET on a directory — plain HTML, no template engine.
Task<Result<void>> list_directory(auto& writer, const fs::path& path) {
    Response response;
    response.status = 200;
    response.headers.append("Content-Type", "text/html; charset=utf-8");

    std::string page{"<!doctype html><html><body><ul>"};
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(path, ec)) {
        page += "<li>";
        for (const char c : entry.path().filename().string()) {
            switch (c) {
            case '&': page += "&amp;"; break;
            case '<': page += "&lt;"; break;
            case '>': page += "&gt;"; break;
            case '"': page += "&quot;"; break;
            case '\'': page += "&#39;"; break;
            default: page.push_back(c); break;
            }
        }
        page += "</li>";
    }
    page += "</ul></body></html>";
    co_return co_await writer.send(response, bytes_of(page));
}

/// Route by method; stream in both directions where it matters.
Task<Result<void>> handle(const Request& request, auto& writer, auto& body_reader,
                          const fs::path& root, bool allow_upload) {
    const auto resolved = resolve_under_root(root, request.target);
    if (!resolved) {
        Response r;
        r.status = 400;
        co_return co_await writer.send(r, bytes_of("target escapes the root"));
    }

    if (request.method == Method::put || request.method == Method::post) {
        if (!allow_upload) {
            Response r;
            r.status = 405;
            r.headers.append("Connection", "close");
            co_return co_await writer.send(r, bytes_of("uploads are disabled"));
        }
        const Result<void> stored = co_await receive_upload(body_reader, *resolved);
        if (!stored) {
            const bool too_big =
                stored.error() == Mira::make_error_code(Mira::Errc::limit_exceeded);
            Response r;
            r.status = too_big ? 413 : 500;
            co_return co_await writer.send(r, bytes_of("upload refused"));
        }
        Response r;
        r.status = 201;
        co_return co_await writer.send(r);
    }

    if (request.method == Method::get || request.method == Method::head) {
        std::error_code ec;
        if (fs::is_directory(*resolved, ec)) {
            co_return co_await list_directory(writer, *resolved);
        }
        if (!fs::is_regular_file(*resolved, ec)) {
            Response r;
            r.status = 404;
            co_return co_await writer.send(r, bytes_of("not found"));
        }
        co_return co_await stream_file(writer, *resolved);
    }

    Response r;
    r.status = 405;
    co_return co_await writer.send(r, bytes_of("method not allowed"));
}

/// `serve_connection` yields `Task<Result<void>>`; `TaskScope::spawn` takes
/// `Task<void>`. Wrap, log, discard: a file server should outlive one sick
/// connection.
Task<void> serve_one(tcp::Socket socket, const fs::path& root, bool allow_upload) {
    Mira::http::ServerOptions options;
    options.limits.max_body_size = k_max_upload;
    const Result<void> served = co_await serve_connection(
        socket,
        [&root, allow_upload](const Request& request, auto& writer, auto& body_reader) -> Task<Result<void>> {
            co_return co_await handle(request, writer, body_reader, root, allow_upload);
        }, options);
    if (!served && served.error() != Mira::Errc::eof) {
        std::fprintf(stderr, "connection ended: %s\n", served.error().message().c_str());
    }
    co_return;
}

Task<void> serve(tcp::Listener& listener, const fs::path& root, bool allow_upload) {
    TaskScope scope;
    for (;;) {
        Result<tcp::Socket> accepted = co_await listener.accept();
        if (!accepted) {
            scope.request_stop();
            break;
        }
        scope.spawn(serve_one(std::move(*accepted), root, allow_upload));
    }
    co_await scope.join();
}

}  // namespace

int main(int argc, char** argv) {
    std::uint16_t port = 0;
    fs::path root{"."};
    const bool allow_upload = argc == 4 && std::string_view(argv[3]) == "--allow-upload";
    if (argc > 4 || (argc == 4 && !allow_upload) || (argc > 1 && !parse_number(argv[1], port))) {
        std::fprintf(stderr, "usage: %s [port] [root-directory] [--allow-upload]\n", argv[0]);
        return 2;
    }
    if (argc > 2) {
        root = fs::path{argv[2]};
    }

#ifdef SIGPIPE
    if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        std::fprintf(stderr, "fileserver: could not ignore SIGPIPE\n");
        return 1;
    }
#endif

    Result<EventLoop> created = EventLoop::create();
    if (!created) {
        std::fprintf(stderr, "event loop: %s\n", created.error().message().c_str());
        return 1;
    }
    EventLoop& loop = created.value();

    Result<tcp::Listener> listener =
        tcp::Listener::bind(loop, Mira::transport::Endpoint::loopback(port));
    if (!listener) {
        std::fprintf(stderr, "bind: %s\n", listener.error().message().c_str());
        return 1;
    }

    std::error_code ec;
    const fs::path resolved_root = fs::weakly_canonical(root, ec);
    if (ec) {
        std::fprintf(stderr, "root directory: %s\n", ec.message().c_str());
        return 1;
    }

    std::printf("tiny file server listening on %s (root: %s)\n",
                listener->local_endpoint().to_string().c_str(),
                resolved_root.string().c_str());
    std::fflush(stdout);

    const Result<void> ran = loop.run_until_complete(serve(*listener, resolved_root, allow_upload));
    if (!ran) {
        std::fprintf(stderr, "run: %s\n", ran.error().message().c_str());
        return 1;
    }
    return 0;
}
