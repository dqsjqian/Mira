#pragma once

#include "mira/core/error.hpp"
#include "mira/core/operation.hpp"
#include "mira/http/message.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <list>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Mira::client {

struct RequestOrigin {
    std::string scheme;
    std::string host;
    std::uint16_t port = 0;
    bool operator==(const RequestOrigin&) const = default;
};

struct CookieOptions {
    std::size_t max_cookies = 256;
    std::size_t max_bytes = 256 * 1024;
    std::size_t max_cookie_bytes = 4096;
    std::chrono::seconds max_lifetime = std::chrono::hours(24 * 30);
};

struct ResponseCacheOptions {
    std::size_t max_entries = 128;
    std::size_t max_bytes = 8 * 1024 * 1024;
    std::size_t max_entry_bytes = 1024 * 1024;
    std::chrono::seconds max_freshness = std::chrono::hours(1);
};

struct RequestStateOptions {
    std::optional<CookieOptions> cookies{};
    std::optional<ResponseCacheOptions> cache{};
};

struct CachedResponse {
    http::Response head;
    std::vector<std::byte> body;
};

namespace state_detail {

inline std::string lower(std::string_view value) {
    std::string out{value};
    for (char& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}
inline std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    return value;
}
inline bool token(std::string_view value) {
    if (value.empty()) return false;
    for (char c : value) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) continue;
        if (std::string_view{"!#$%&'*+-.^_`|~"}.find(c) == std::string_view::npos) return false;
    }
    return true;
}
inline std::optional<std::uint64_t> number(std::string_view text) {
    if (text.empty()) return {};
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) return {};
    return value;
}

// IMF-fixdate；不依赖 locale 或平台 timegm，先以秒保存，避免远期日期溢出纳秒时钟。
inline std::optional<std::chrono::sys_seconds> date(std::string_view text) {
    if (text.size() != 29 || text.substr(3, 2) != ", " || text[7] != ' ' || text[11] != ' ' ||
        text[16] != ' ' || text[19] != ':' || text[22] != ':' || text.substr(25) != " GMT") return {};
    const auto day = number(text.substr(5, 2)), year = number(text.substr(12, 4));
    const auto hour = number(text.substr(17, 2)), minute = number(text.substr(20, 2)), second = number(text.substr(23, 2));
    constexpr std::string_view months = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const auto month = months.find(text.substr(8, 3));
    if (!day || !year || !hour || !minute || !second || month == std::string_view::npos || month % 3 != 0 ||
        *year < 1601 || *year > 9999 || *day > 31 || *hour > 23 || *minute > 59 || *second > 59) return {};
    const std::chrono::year_month_day value{std::chrono::year{static_cast<int>(*year)},
        std::chrono::month{static_cast<unsigned>(month / 3 + 1)}, std::chrono::day{static_cast<unsigned>(*day)}};
    if (!value.ok()) return {};
    return std::chrono::sys_days{value} + std::chrono::hours{*hour} +
        std::chrono::minutes{*minute} + std::chrono::seconds{*second};
}
inline Clock::time_point expires_after(Clock::time_point now, std::chrono::seconds seconds) {
    const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(Clock::time_point::max() - now);
    return seconds >= remaining ? Clock::time_point::max() : now + seconds;
}
inline std::size_t origin_bytes(const RequestOrigin& origin) { return origin.scheme.size() + origin.host.size() + 2; }
inline std::size_t header_bytes(const http::HeaderMap& headers) {
    std::size_t size = 0;
    for (const auto& [name, value] : headers) size += name.size() + value.size() + 4;
    return size;
}
inline bool path_matches(std::string_view request_path, std::string_view cookie_path) {
    return request_path.starts_with(cookie_path) && (request_path.size() == cookie_path.size() ||
        cookie_path.back() == '/' || request_path[cookie_path.size()] == '/');
}
inline bool same_headers(const http::HeaderMap& a, const http::HeaderMap& b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin(), [](const auto& left, const auto& right) {
        return http::HeaderMap::names_equal(left.first, right.first) && left.second == right.second;
    });
}

}  // namespace state_detail

/// 显式、内存内、单事件循环的请求状态；通过 RedirectOptions::state 启用。
/// 每个身份/租户应拥有独立实例，clear() 清除所有状态。默认两个功能均关闭。
/// Cookie 按 scheme/host/port 严格隔离，只接受 host-only 或与主机完全一致的
/// Domain（没有公共后缀表时不放宽子域）；非浏览器 API，不实现脚本或跨站上下文。
/// 支持 Secure、Path、Max-Age、IMF-fixdate Expires 和安全前缀；会话 Cookie
/// 也受 max_lifetime 限制。过期惰性清除，超出计数/字节上限按 LRU 淘汰。
/// 缓存只保存无凭据、无条件/Range/缓存指令、无请求体 GET 的显式 max-age 200；
/// 完整请求头参与变体匹配。拒绝 Set-Cookie、Vary:*、no-cache/no-store/private，
/// 不做启发式缓存、304 重验证或离线陈旧回退。新鲜度扣除 Age/Date/网络延迟，
/// 受 max_freshness 限制；成功的不安全方法使整个 origin 缓存失效，包括在途写入。
/// 字节预算包含 origin、目标、请求/响应头和 body；对象固定开销由计数预算约束。
class RequestState {
public:
    [[nodiscard]] static Result<std::shared_ptr<RequestState>> create(RequestStateOptions options = {}) {
        if (options.cookies) {
            const auto& c = *options.cookies;
            if (!c.max_cookies || !c.max_bytes || !c.max_cookie_bytes || c.max_cookie_bytes > c.max_bytes ||
                c.max_lifetime <= std::chrono::seconds::zero()) return fail(Errc::invalid_argument);
        }
        if (options.cache) {
            const auto& c = *options.cache;
            if (!c.max_entries || !c.max_bytes || !c.max_entry_bytes || c.max_entry_bytes > c.max_bytes ||
                c.max_freshness <= std::chrono::seconds::zero()) return fail(Errc::invalid_argument);
        }
        return std::shared_ptr<RequestState>{new RequestState{std::move(options)}};
    }
    RequestState(const RequestState&) = delete;
    RequestState& operator=(const RequestState&) = delete;
    void clear() { cookies_.clear(); cache_.clear(); cookie_bytes_ = cache_bytes_ = 0; ++generation_; }
    [[nodiscard]] std::size_t cookie_count() const noexcept { return cookies_.size(); }
    [[nodiscard]] std::size_t cache_count() const noexcept { return cache_.size(); }
    [[nodiscard]] std::size_t cookie_bytes() const noexcept { return cookie_bytes_; }
    [[nodiscard]] std::size_t cache_bytes() const noexcept { return cache_bytes_; }
    [[nodiscard]] std::uint64_t generation() const noexcept { return generation_; }

    /// 调用者提供的 Cookie 完全优先，不合并、不覆盖；自动值仅属于本次 hop。
    void prepare(const RequestOrigin& origin, http::Request& request, Clock::time_point now = Clock::now()) {
        prune(now);
        if (!options_.cookies || request.headers.contains("Cookie")) return;
        const auto path = std::string_view{request.target}.substr(0, request.target.find('?'));
        std::vector<typename std::list<Cookie>::iterator> matches;
        for (auto it = cookies_.begin(); it != cookies_.end(); ++it)
            if (it->origin == origin && state_detail::path_matches(path, it->path)) matches.push_back(it);
        std::sort(matches.begin(), matches.end(), [](const auto& a, const auto& b) {
            return a->path.size() != b->path.size() ? a->path.size() > b->path.size() : a->created < b->created;
        });
        std::string value;
        for (auto it : matches) {
            if (!value.empty()) value += "; ";
            value += it->name + "=" + it->value;
            cookies_.splice(cookies_.end(), cookies_, it);
        }
        if (!value.empty()) request.headers.append("Cookie", std::move(value));
    }

    [[nodiscard]] std::optional<CachedResponse> lookup(const RequestOrigin& origin, const http::Request& request,
        bool empty_body, Clock::time_point now = Clock::now()) {
        prune(now);
        if (!options_.cache || !cacheable_request(request, empty_body)) return {};
        for (auto it = cache_.begin(); it != cache_.end(); ++it) {
            if (!(it->origin == origin) || it->target != request.target || it->version != request.version ||
                !state_detail::same_headers(it->request_headers, request.headers)) continue;
            auto response = it->response;
            http::HeaderMap headers;
            for (const auto& [name, value] : response.head.headers)
                if (!http::HeaderMap::names_equal(name, "Age")) headers.append(name, value);
            const auto elapsed = std::max(std::chrono::seconds::zero(),
                std::chrono::ceil<std::chrono::seconds>(now - it->stored));
            headers.append("Age", std::to_string((it->initial_age + elapsed).count()));
            response.head.headers = std::move(headers);
            cache_.splice(cache_.end(), cache_, it);
            return response;
        }
        return {};
    }

    void remember(const RequestOrigin& origin, const http::Request& request, bool empty_body,
        const http::Response& response, std::span<const std::byte> body, std::uint64_t generation,
        Clock::time_point started, Clock::time_point now = Clock::now(),
        std::chrono::system_clock::time_point wall = std::chrono::system_clock::now()) {
        if (generation != generation_) return;
        prune(now);
        if (options_.cookies)
            for (const auto& [name, value] : response.headers)
                if (http::HeaderMap::names_equal(name, "Set-Cookie")) store_cookie(origin, request.target, value, now, wall);
        if (!options_.cache) return;
        if (request.method != http::Method::get && request.method != http::Method::head &&
            request.method != http::Method::options && request.method != http::Method::trace && response.status < 400) {
            ++generation_;
            for (auto it = cache_.begin(); it != cache_.end();) {
                if (it->origin == origin) { cache_bytes_ -= it->size; it = cache_.erase(it); }
                else ++it;
            }
            return;
        }
        if (generation != generation_ || request.method != http::Method::get) return;
        // 包括显式 reload、凭据及 no-store 请求，不能让旧响应在下一次请求复活。
        // 新的网络结果不能留下该 URL 的旧变体（包括 no-store 或失败响应）。
        for (auto it = cache_.begin(); it != cache_.end();) {
            if (it->origin == origin && it->target == request.target) {
                cache_bytes_ -= it->size; it = cache_.erase(it);
            } else ++it;
        }
        if (!cacheable_request(request, empty_body)) return;
        if (response.status != 200 || response.headers.contains("Set-Cookie") ||
            response.headers.contains("WWW-Authenticate") || response.headers.contains("Proxy-Authenticate")) return;
        std::optional<std::uint64_t> lifetime;
        for (const auto& [name, value] : response.headers) {
            if (http::HeaderMap::names_equal(name, "Vary") && value.find('*') != std::string::npos) return;
            if (!http::HeaderMap::names_equal(name, "Cache-Control")) continue;
            std::string_view remaining{value};
            while (!remaining.empty()) {
                std::size_t comma = std::string_view::npos;
                bool quoted = false, escaped = false;
                for (std::size_t i = 0; i < remaining.size(); ++i) {
                    const char c = remaining[i];
                    if (escaped) { escaped = false; continue; }
                    if (quoted && c == '\\') { escaped = true; continue; }
                    if (c == '"') quoted = !quoted;
                    if (c == ',' && !quoted) { comma = i; break; }
                }
                if (quoted || escaped) return;
                const auto part = state_detail::trim(remaining.substr(0, comma));
                const auto equal = part.find('=');
                const auto directive = state_detail::lower(state_detail::trim(part.substr(0, equal)));
                if (directive == "no-cache" || directive == "no-store" || directive == "private") return;
                if (directive == "max-age") {
                    if (lifetime || equal == std::string_view::npos) return;
                    auto arg = state_detail::trim(part.substr(equal + 1));
                    if (arg.size() >= 2 && arg.front() == '"' && arg.back() == '"') arg = arg.substr(1, arg.size() - 2);
                    lifetime = state_detail::number(arg);
                    if (!lifetime) return;
                }
                if (comma == std::string_view::npos) break;
                remaining.remove_prefix(comma + 1);
            }
        }
        if (!lifetime || !*lifetime) return;
        const auto lifetime_seconds = std::chrono::seconds{static_cast<std::int64_t>(std::min(*lifetime,
            static_cast<std::uint64_t>(options_.cache->max_freshness.count())))};
        auto age = std::chrono::seconds::zero();
        if (response.headers.count("Age") > 1 || response.headers.count("Date") > 1) return;
        if (auto value = response.headers.get("Age")) {
            const auto parsed = state_detail::number(state_detail::trim(*value));
            if (!parsed || *parsed >= static_cast<std::uint64_t>(lifetime_seconds.count())) return;
            age = std::chrono::seconds{*parsed};
        }
        // 向上取整网络延迟，宁可提前过期，不晚用一秒。
        const auto delay = std::max(std::chrono::seconds::zero(), std::chrono::ceil<std::chrono::seconds>(now - started));
        if (delay >= lifetime_seconds - age) return;
        age += delay;
        if (auto value = response.headers.get("Date")) {
            const auto parsed = state_detail::date(*value);
            if (!parsed) return;
            age = std::max(age, std::chrono::ceil<std::chrono::seconds>(wall) - *parsed);
        }
        if (age >= lifetime_seconds) return;
        const auto limit = options_.cache->max_entry_bytes;
        if (body.size() > limit) return;
        const auto metadata = state_detail::origin_bytes(origin) + request.target.size() + response.reason.size() +
            state_detail::header_bytes(request.headers) + state_detail::header_bytes(response.headers);
        if (metadata > limit - body.size()) return;
        const auto size = metadata + body.size();
        while (cache_.size() >= options_.cache->max_entries || cache_bytes_ > options_.cache->max_bytes - size) {
            cache_bytes_ -= cache_.front().size; cache_.pop_front();
        }
        cache_.push_back(CacheEntry{origin, request.target, request.version, request.headers,
            CachedResponse{response, {body.begin(), body.end()}}, now,
            state_detail::expires_after(now, lifetime_seconds - age), age, size});
        cache_bytes_ += size;
    }

private:
    struct Cookie {
        RequestOrigin origin;
        std::string name, value, path;
        Clock::time_point expires;
        std::uint64_t created;
        std::size_t size;
    };
    struct CacheEntry {
        RequestOrigin origin;
        std::string target;
        http::Version version;
        http::HeaderMap request_headers;
        CachedResponse response;
        Clock::time_point stored, expires;
        std::chrono::seconds initial_age;
        std::size_t size;
    };
    explicit RequestState(RequestStateOptions options) : options_(std::move(options)) {}
    static bool cacheable_request(const http::Request& request, bool empty_body) {
        if (request.method != http::Method::get || !empty_body || !request.method_token.empty()) return false;
        for (const auto& [name, value] : request.headers) {
            static_cast<void>(value);
            const auto lower = state_detail::lower(name);
            if (lower == "authorization" || lower == "proxy-authorization" || lower == "cookie" ||
                lower == "range" || lower == "cache-control" || lower == "pragma" || lower.starts_with("if-")) return false;
        }
        return true;
    }
    void prune(Clock::time_point now) {
        for (auto it = cookies_.begin(); it != cookies_.end();) {
            if (now >= it->expires) { cookie_bytes_ -= it->size; it = cookies_.erase(it); }
            else ++it;
        }
        for (auto it = cache_.begin(); it != cache_.end();) {
            if (now >= it->expires) { cache_bytes_ -= it->size; it = cache_.erase(it); }
            else ++it;
        }
    }
    void store_cookie(const RequestOrigin& origin, std::string_view target, std::string_view field,
        Clock::time_point now, std::chrono::system_clock::time_point wall) {
        const auto& options = *options_.cookies;
        if (field.size() > options.max_cookie_bytes) return;
        for (char c : field) if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) >= 0x7f) return;
        const auto first = state_detail::trim(field.substr(0, field.find(';')));
        const auto equals = first.find('=');
        if (equals == std::string_view::npos) return;
        const auto name = state_detail::trim(first.substr(0, equals));
        const auto value = state_detail::trim(first.substr(equals + 1));
        if (!state_detail::token(name)) return;
        auto content = value;
        if (content.size() >= 2 && content.front() == '"' && content.back() == '"') content = content.substr(1, content.size() - 2);
        for (char c : content)
            if (c <= 0x20 || c == '"' || c == ',' || c == ';' || c == '\\' || static_cast<unsigned char>(c) >= 0x7f) return;
        auto base = target.substr(0, target.find('?'));
        const auto slash = base.rfind('/');
        std::string path = slash == std::string_view::npos || slash == 0 ? "/" : std::string{base.substr(0, slash)};
        bool secure = false, domain_seen = false, explicit_root = false;
        std::optional<std::chrono::seconds> max_age;
        std::optional<std::chrono::sys_seconds> expires;
        auto pos = field.find(';');
        while (pos != std::string_view::npos) {
            field.remove_prefix(pos + 1);
            pos = field.find(';');
            const auto attr = state_detail::trim(field.substr(0, pos));
            const auto equal = attr.find('=');
            const auto key = state_detail::lower(state_detail::trim(attr.substr(0, equal)));
            const auto arg = equal == std::string_view::npos ? std::string_view{} : state_detail::trim(attr.substr(equal + 1));
            if (key == "secure") secure = true;
            else if (key == "domain") {
                domain_seen = true;
                auto domain = state_detail::lower(arg);
                if (domain.starts_with('.')) domain.erase(0, 1);
                if (domain != origin.host) return;
            } else if (key == "path" && arg.starts_with('/')) { path = arg; explicit_root = arg == "/"; }
            else if (key == "max-age") {
                auto digits = arg;
                const bool negative = digits.starts_with('-');
                if (negative) digits.remove_prefix(1);
                if (digits.empty() || !std::all_of(digits.begin(), digits.end(), [](char c) { return c >= '0' && c <= '9'; })) continue;
                const auto parsed = state_detail::number(digits);
                max_age = negative ? std::chrono::seconds::zero() : std::chrono::seconds{static_cast<std::int64_t>(
                    std::min(parsed.value_or(UINT64_MAX), static_cast<std::uint64_t>(options.max_lifetime.count())))};
            } else if (key == "expires") expires = state_detail::date(arg);
        }
        if (secure && origin.scheme != "https") return;
        if (name.starts_with("__Secure-") && (!secure || origin.scheme != "https")) return;
        if (name.starts_with("__Host-") && (!secure || origin.scheme != "https" || domain_seen || !explicit_root)) return;
        auto lifetime = options.max_lifetime;
        if (max_age) lifetime = *max_age;
        else if (expires) lifetime = std::min(lifetime, *expires - std::chrono::ceil<std::chrono::seconds>(wall));
        const auto size = state_detail::origin_bytes(origin) + name.size() + value.size() + path.size();
        if (size > options.max_cookie_bytes) return;
        auto created = created_++;
        for (auto it = cookies_.begin(); it != cookies_.end(); ++it)
            if (it->origin == origin && it->name == name && it->path == path) {
                created = it->created; cookie_bytes_ -= it->size; cookies_.erase(it); break;
            }
        if (lifetime <= std::chrono::seconds::zero()) return;
        while (cookies_.size() >= options.max_cookies || cookie_bytes_ > options.max_bytes - size) {
            cookie_bytes_ -= cookies_.front().size; cookies_.pop_front();
        }
        cookies_.push_back(Cookie{origin, std::string{name}, std::string{value}, std::move(path),
            state_detail::expires_after(now, lifetime), created, size});
        cookie_bytes_ += size;
    }
    RequestStateOptions options_;
    std::list<Cookie> cookies_;
    std::list<CacheEntry> cache_;
    std::size_t cookie_bytes_ = 0, cache_bytes_ = 0;
    std::uint64_t created_ = 0, generation_ = 0;
};

}  // namespace Mira::client
