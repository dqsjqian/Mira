#include "check.hpp"
#include "mira/client/request_state.hpp"

#include <string>

using namespace Mira;
using namespace Mira::client;
using namespace std::chrono_literals;

namespace {

const RequestOrigin origin{"https", "a.test", 443};
const Clock::time_point now{100s};
const auto wall = std::chrono::sys_days{std::chrono::year{2025}/1/1};

http::Request get(std::string path = "/") {
    http::Request request;
    request.target = std::move(path);
    return request;
}
http::Response response(std::string_view cache_control = "max-age=60") {
    http::Response result;
    result.headers.append("Cache-Control", std::string{cache_control});
    return result;
}
void store_cookie(RequestState& state, std::string value, std::string path = "/", RequestOrigin site = origin) {
    http::Response head;
    head.headers.append("Set-Cookie", std::move(value));
    state.remember(site, get(std::move(path)), true, head, {}, state.generation(), now, now, wall);
}
std::string cookie(RequestState& state, std::string path = "/", RequestOrigin site = origin,
    Clock::time_point time = now) {
    auto request = get(std::move(path));
    state.prepare(site, request, time);
    return std::string{request.headers.get("Cookie").value_or("")};
}
void store_cache(RequestState& state, const http::Request& request, const http::Response& head,
    std::string_view body = "body", Clock::time_point time = now) {
    state.remember(origin, request, true, head, std::as_bytes(std::span{body.data(), body.size()}),
        state.generation(), time, time, wall);
}

void cookies() {
    test::section("Cookie 显式开关、作用域、路径和手动值优先");
    auto disabled = *RequestState::create();
    store_cookie(*disabled, "id=off");
    CHECK(cookie(*disabled).empty());
    auto state = *RequestState::create({.cookies = CookieOptions{}});
    store_cookie(*state, "id=root; Secure; HttpOnly; Path=/");
    store_cookie(*state, "id=deep; Path=/dir", "/dir/page");
    CHECK(cookie(*state, "/dir/page") == "id=deep; id=root");
    CHECK(cookie(*state, "/directory") == "id=root");
    CHECK(cookie(*state, "/dir?x=1") == "id=deep; id=root");
    CHECK(cookie(*state, "/", {"https", "b.test", 443}).empty());
    CHECK(cookie(*state, "/", {"https", "a.test", 8443}).empty());
    CHECK(cookie(*state, "/", {"http", "a.test", 443}).empty());
    auto manual = get();
    manual.headers.append("Cookie", "manual=yes");
    state->prepare(origin, manual, now);
    CHECK(manual.headers.count("Cookie") == 1 && manual.headers.get("Cookie") == "manual=yes");
    state->clear();
    store_cookie(*state, "dir=default", "/dir/page");
    CHECK(cookie(*state, "/dir/next") == "dir=default");
    CHECK(cookie(*state).empty());

    test::section("Cookie 拒绝跨域、注入、错误 Secure 前缀");
    state->clear();
    for (const auto value : {"a=x; Domain=test", "a=x; Domain=b.test", "a=x; Domain=",
        "a=x\r\nInjected: yes", "a=x,y", "bad name=x", "__Secure-a=x", "__Host-a=x; Secure",
        "__Host-a=x; Secure; Path=/; Domain=a.test", "__Host-a=x; Secure; Path=/dir"})
        store_cookie(*state, value);
    CHECK(state->cookie_count() == 0);
    store_cookie(*state, "a=x; Secure", "/", {"http", "a.test", 80});
    CHECK(state->cookie_count() == 0);
    store_cookie(*state, "__Host-a=x; Secure; Path=/");
    store_cookie(*state, "b=y; Domain=.A.TEST");
    CHECK(cookie(*state) == "__Host-a=x; b=y");
    CHECK(cookie(*state, "/", {"https", "child.a.test", 443}).empty());

    test::section("Cookie Max-Age 优先、删除、Expires 与惰性过期");
    state->clear();
    store_cookie(*state, "a=x; Max-Age=2; Expires=Wed, 01 Jan 2020 00:00:00 GMT");
    CHECK(cookie(*state, "/", origin, now + 1s) == "a=x");
    CHECK(cookie(*state, "/", origin, now + 2s).empty());
    store_cookie(*state, "a=x");
    store_cookie(*state, "a=x; Max-Age=0");
    CHECK(cookie(*state).empty());
    store_cookie(*state, "a=x");
    store_cookie(*state, "a=x; Max-Age=-9999999999999999999999");
    CHECK(cookie(*state).empty());
    store_cookie(*state, "a=x; Expires=Wed, 01 Jan 2020 00:00:00 GMT");
    CHECK(cookie(*state).empty());
    store_cookie(*state, "a=x; Expires=Wed, 01 Jan 2025 00:00:02 GMT");
    CHECK(cookie(*state, "/", origin, now + 1s) == "a=x");
    CHECK(cookie(*state, "/", origin, now + 2s).empty());
    store_cookie(*state, "a=x; Expires=Wed, 01 Jan 9999 00:00:02 GMT");
    CHECK(cookie(*state) == "a=x");
    state->clear();

    test::section("clear 后在途旧响应不得恢复 Cookie 或失效新缓存");
    state = *RequestState::create({.cookies = CookieOptions{}, .cache = ResponseCacheOptions{}});
    const auto old_generation = state->generation();
    state->clear();
    auto late = response(); late.headers.append("Set-Cookie", "old=session; Path=/");
    state->remember(origin, get(), true, late, {}, old_generation, now, now, wall);
    CHECK(state->cookie_count() == 0 && state->cache_count() == 0);
    store_cache(*state, get("/new"), response());
    auto old_write = get(); old_write.method = http::Method::post;
    state->remember(origin, old_write, true, late, {}, old_generation, now, now, wall);
    CHECK(state->cookie_count() == 0);
    CHECK(state->lookup(origin, get("/new"), true, now).has_value());

    test::section("Cookie 计数、字节、单条限制与 LRU");
    CookieOptions options;
    options.max_cookies = 2;
    options.max_cookie_bytes = 64;
    options.max_bytes = 64;
    options.max_lifetime = 2s;
    state = *RequestState::create({.cookies = options});
    store_cookie(*state, "a=1; Path=/a");
    store_cookie(*state, "b=2; Path=/b");
    CHECK(cookie(*state, "/a") == "a=1");
    store_cookie(*state, "c=3; Path=/c");
    CHECK(cookie(*state, "/b").empty());
    CHECK(cookie(*state, "/a") == "a=1");
    CHECK(state->cookie_count() == 2 && state->cookie_bytes() <= 64);
    store_cookie(*state, "huge=" + std::string(100, 'x'));
    CHECK(state->cookie_count() == 2);
    CHECK(cookie(*state, "/a", origin, now + 2s).empty());
    CHECK(state->cookie_count() == 0 && state->cookie_bytes() == 0);
    options.max_cookies = 10;
    options.max_bytes = 64;
    state = *RequestState::create({.cookies = options});
    for (int i = 0; i < 10; ++i) store_cookie(*state, "a" + std::to_string(i) + "=1234567890");
    CHECK(state->cookie_count() < 10 && state->cookie_bytes() <= 64);
}

void cache() {
    test::section("缓存默认关闭、完整请求变体和 origin 隔离");
    auto disabled = *RequestState::create();
    store_cache(*disabled, get(), response());
    CHECK(!disabled->lookup(origin, get(), true, now));
    auto state = *RequestState::create({.cache = ResponseCacheOptions{}});
    auto request = get("/item?x=1");
    request.headers.append("Accept-Language", "en");
    store_cache(*state, request, response());
    auto hit = state->lookup(origin, request, true, now + 1s);
    CHECK(hit && hit->body.size() == 4 && hit->head.headers.get("Age") == "1");
    auto variant = get("/item?x=1");
    variant.headers.append("Accept-Language", "fr");
    CHECK(!state->lookup(origin, variant, true, now));
    CHECK(!state->lookup({"http", "a.test", 443}, request, true, now));
    CHECK(!state->lookup({"https", "b.test", 443}, request, true, now));
    CHECK(!state->lookup({"https", "a.test", 8443}, request, true, now));
    CHECK(!state->lookup(origin, get("/item?x=2"), true, now));
    CHECK(!state->lookup(origin, request, false, now));
    CHECK(!state->lookup(origin, request, true, now + 60s));

    test::section("缓存拒绝敏感、部分、条件、强制网络请求和不安全响应");
    for (const auto header : {"Authorization", "Proxy-Authorization", "Cookie", "Range", "If-None-Match", "If-Modified-Since", "Cache-Control", "Pragma"}) {
        auto secret = get();
        secret.headers.append(header, "x");
        store_cache(*state, secret, response());
        CHECK(!state->lookup(origin, secret, true, now));
    }
    auto post = get(); post.method = http::Method::post;
    store_cache(*state, post, response());
    CHECK(!state->lookup(origin, post, true, now));
    for (const auto directive : {"no-store, max-age=60", "max-age=60, no-cache", "private, max-age=60",
        "max-age=60, max-age=90", "max-age=-1", "max-age=abc", "max-age=0", "public",
        "extension=\"ignored,max-age=60,other\"", "max-age=60,extension=\"unclosed"}) {
        store_cache(*state, get(), response(directive));
        CHECK(!state->lookup(origin, get(), true, now));
    }
    for (const auto header : {"Set-Cookie", "Vary", "WWW-Authenticate", "Proxy-Authenticate"}) {
        auto head = response(); head.headers.append(header, "*");
        store_cache(*state, get(), head);
        CHECK(!state->lookup(origin, get(), true, now));
    }
    auto partial = response(); partial.status = 206;
    store_cache(*state, get(), partial);
    CHECK(!state->lookup(origin, get(), true, now));
    store_cache(*state, get(), response("extension=\"ignored,max-age=0,other\", max-age=\"60\""));
    CHECK(state->lookup(origin, get(), true, now).has_value());
    auto vary = response(); vary.headers.append("Vary", "Accept-Language");
    store_cache(*state, request, vary);
    CHECK(state->lookup(origin, request, true, now).has_value());

    test::section("缓存新鲜度扣除 Age、Date 和请求延迟，不返回过期值");
    auto aged = response(); aged.headers.append("Age", "59");
    store_cache(*state, get(), aged);
    CHECK(state->lookup(origin, get(), true, now).has_value());
    CHECK(!state->lookup(origin, get(), true, now + 1s));
    for (const auto value : {"60", "99999999999999999999999", "invalid", "-1"}) {
        aged = response(); aged.headers.append("Age", value);
        store_cache(*state, get(), aged);
        CHECK(!state->lookup(origin, get(), true, now));
    }
    aged = response(); aged.headers.append("Date", "Tue, 31 Dec 2024 23:59:00 GMT");
    store_cache(*state, get(), aged);
    CHECK(!state->lookup(origin, get(), true, now));
    aged = response(); aged.headers.append("Date", "not a date");
    store_cache(*state, get(), aged);
    CHECK(!state->lookup(origin, get(), true, now));
    state->remember(origin, get(), true, response(), {}, state->generation(), now - 60s, now, wall);
    CHECK(!state->lookup(origin, get(), true, now));

    test::section("缓存成功写操作失效及在途 GET 防止复活旧响应");
    store_cache(*state, get("/a"), response());
    store_cache(*state, get("/b"), response());
    const auto generation = state->generation();
    state->remember(origin, post, true, response(), {}, generation, now, now, wall);
    CHECK(state->cache_count() == 0);
    state->remember(origin, get("/a"), true, response(), {}, generation, now, now, wall);
    CHECK(state->cache_count() == 0);
    store_cache(*state, get(), response());
    auto reload = response("no-store");
    store_cache(*state, get(), reload);
    CHECK(!state->lookup(origin, get(), true, now));
    store_cache(*state, get(), response());
    auto forced = get(); forced.headers.append("Cache-Control", "no-cache");
    store_cache(*state, forced, response("no-store"));
    CHECK(!state->lookup(origin, get(), true, now));

    test::section("缓存 LRU、条目/总字节预算以及新鲜度上限");
    ResponseCacheOptions options;
    options.max_entries = 2;
    options.max_entry_bytes = 256;
    options.max_bytes = 300;
    options.max_freshness = 2s;
    state = *RequestState::create({.cache = options});
    store_cache(*state, get("/a"), response());
    store_cache(*state, get("/b"), response());
    CHECK(state->lookup(origin, get("/a"), true, now).has_value());
    store_cache(*state, get("/c"), response());
    CHECK(!state->lookup(origin, get("/b"), true, now));
    CHECK(state->lookup(origin, get("/a"), true, now).has_value());
    store_cache(*state, get("/large"), response(), std::string(257, 'x'));
    CHECK(!state->lookup(origin, get("/large"), true, now));
    auto large_headers = response(); large_headers.headers.append("X-Large", std::string(257, 'x'));
    store_cache(*state, get("/large-head"), large_headers);
    CHECK(!state->lookup(origin, get("/large-head"), true, now));
    CHECK(state->cache_count() == 2 && state->cache_bytes() <= 300);
    CHECK(!state->lookup(origin, get("/a"), true, now + 2s));
    CHECK(state->cache_count() == 0 && state->cache_bytes() == 0);
    options.max_entries = 100;
    state = *RequestState::create({.cache = options});
    for (int i = 0; i < 10; ++i) store_cache(*state, get("/" + std::to_string(i)), response(), std::string(80, 'x'));
    CHECK(state->cache_count() < 10 && state->cache_bytes() <= 300);
    const auto before_clear = state->generation();
    state->clear();
    CHECK(state->cache_count() == 0 && state->cache_bytes() == 0 && state->generation() != before_clear);
}

}  // namespace

int main() {
    CookieOptions invalid_cookie; invalid_cookie.max_cookies = 0;
    CHECK(!RequestState::create({.cookies = invalid_cookie}));
    ResponseCacheOptions invalid_cache; invalid_cache.max_entry_bytes = invalid_cache.max_bytes + 1;
    CHECK(!RequestState::create({.cache = invalid_cache}));
    cookies();
    cache();
    return test::summary();
}
