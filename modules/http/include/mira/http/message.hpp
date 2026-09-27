#pragma once

// Mira/http/message.hpp — HTTP/1.1 message types.
//
// Deliberately plain: a request is a method, a target, a version, and headers.
// The body is **not** here. A body is a stream, and materialising it into a
// `std::string` on the message is how a library ends up unable to handle an
// upload larger than memory. The parser hands body bytes out in slices; the
// caller decides whether to accumulate them.
//
// This module includes no OS headers and knows nothing about sockets — the
// layering check enforces that, which is what keeps the parser testable over
// an in-memory pipe.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Mira::http {

/// Request methods with defined semantics in RFC 9110.
///
/// `other` covers extension methods: they are parsed and preserved, because
/// rejecting an unknown-but-well-formed token is a policy decision that
/// belongs to the application, not the parser.
enum class Method {
    get,
    head,
    post,
    put,
    delete_,
    connect,
    options,
    trace,
    patch,
    other,
};

/// Canonical spelling of a method.
[[nodiscard]] std::string_view to_string(Method method) noexcept;

/// Parse a method token; `Method::other` for anything well-formed but unknown.
[[nodiscard]] Method method_from_token(std::string_view token) noexcept;

/// Protocol version. HTTP/0.9 is not supported and never will be.
enum class Version {
    http_1_0,
    http_1_1,
};

[[nodiscard]] std::string_view to_string(Version version) noexcept;

/// Ordered, case-insensitive, duplicate-preserving header collection.
///
/// All three properties are required rather than nice to have: order matters
/// for `Set-Cookie`, lookup is case-insensitive per RFC 9110, and duplicates
/// must survive because collapsing them is exactly the ambiguity that request
/// smuggling exploits.
class HeaderMap {
public:
    using Entry = std::pair<std::string, std::string>;

    void append(std::string name, std::string value) {
        if (!spare_.empty()) {
            // Move the pooled entry's strings back into service: moving out
            // of a string keeps its heap buffer, so a name/value of similar
            // size reuses the allocation instead of making a new one.
            auto& reused = spare_.back();
            entries_.emplace_back(std::move(reused.first), std::move(reused.second));
            spare_.pop_back();
            entries_.back().first = std::move(name);
            entries_.back().second = std::move(value);
            return;
        }
        entries_.emplace_back(std::move(name), std::move(value));
    }

    /// First value for `name`, or nullopt.
    [[nodiscard]] std::optional<std::string_view> get(std::string_view name) const noexcept;

    /// Every value for `name`, in order of appearance.
    [[nodiscard]] std::vector<std::string_view> get_all(std::string_view name) const;

    /// How many times `name` appears.
    [[nodiscard]] std::size_t count(std::string_view name) const noexcept;

    [[nodiscard]] bool contains(std::string_view name) const noexcept { return count(name) > 0; }

    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

    [[nodiscard]] auto begin() const noexcept { return entries_.begin(); }
    [[nodiscard]] auto end() const noexcept { return entries_.end(); }

    /// Reset for reuse without paying for the capacity again.
    ///
    /// A server parses thousands of requests into one `Request` object;
    /// `entries_.clear()` alone throws away every header string's heap
    /// buffer, so the next request re-allocates from zero — exactly the
    /// realloc churn keep-alive serving exists to avoid. Drained entries go
    /// to a spare pool and `append` reuses the last one, moving the old
    /// contents out (which leaves the string's capacity intact) before
    /// storing the new value.
    void clear() {
        spare_ = std::move(entries_);
        entries_.clear();
    }

    /// Case-insensitive comparison of two field names.
    [[nodiscard]] static bool names_equal(std::string_view a, std::string_view b) noexcept;

private:
    std::vector<Entry> entries_{};
    /// Drained entries kept for capacity reuse across `clear()` cycles.
    /// Only the most recent drain is kept: one message's worth of headers,
    /// bounded, and the common cadence is clear-then-fill-anyway.
    std::vector<Entry> spare_{};
};

/// How a message body is delimited, decided from the headers per RFC 9112 §6.
enum class BodyKind {
    /// No body: no framing headers present.
    none,
    /// `Content-Length: n`
    length,
    /// `Transfer-Encoding: chunked`
    chunked,
    /// The response body extends to transport EOF; the connection cannot be
    /// reused.
    close_delimited,
};

/// A parsed request head.
struct Request {
    Method method{Method::get};
    /// Request target exactly as received — not decoded, not normalised.
    /// Normalisation is routing policy and belongs above the parser.
    std::string target{};
    Version version{Version::http_1_1};
    HeaderMap headers{};

    /// Framing decided by the parser from the headers.
    BodyKind body_kind{BodyKind::none};
    /// Declared length when `body_kind == length`.
    std::uint64_t content_length{0};

    void clear() {
        method = Method::get;
        target.clear();
        version = Version::http_1_1;
        headers.clear();
        body_kind = BodyKind::none;
        content_length = 0;
    }
};

/// A parsed response head.
struct Response {
    Version version{Version::http_1_1};
    unsigned status{200};
    std::string reason{};
    HeaderMap headers{};

    BodyKind body_kind{BodyKind::none};
    std::uint64_t content_length{0};

    void clear() {
        version = Version::http_1_1;
        status = 200;
        reason.clear();
        headers.clear();
        body_kind = BodyKind::none;
        content_length = 0;
    }
};

/// Default reason phrase for a status code, or an empty view if unknown.
[[nodiscard]] std::string_view default_reason(unsigned status) noexcept;

}  // namespace Mira::http
