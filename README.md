<div align="center">

# 🌐 Mira

**C++23 协程网络库 · 传输为基，协议其上** · TCP / UDP / TLS / WebSocket / HTTP/1.1 / HTTP/2 / QUIC / HTTP/3 / SOCKS5 / DoH / MQTT

一套完成式 I/O 接口连接 kqueue、epoll 与 IOCP，让协议不必认识套接字。

[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/dqsjqian/Mira/actions/workflows/ci.yml/badge.svg)](https://github.com/dqsjqian/Mira/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20iOS%20%7C%20Android-lightgrey.svg)](#-平台矩阵)

[English](README.en.md) | 简体中文

</div>

---

> *Mira* —— 网络软件的这一层基础：持续在底层托住所有协议与业务，不是又一个包办一切的 HTTP 框架。

**完成式 I/O 一个接口打通 kqueue / epoll / IOCP；从 TCP 到 HTTP/3，验证按提交与配置记录。C++23 是基线，不是卖点 —— 协程、`std::expected`、`stop_token` 都是一等公民。**

本页描述所在提交的能力。源码版本、兼容策略和发布包消费方式统一见[版本与发布指南](docs/RELEASES.md)；历史 CI 与当前提交的验收结果分别记录。

## 🚀 30 秒看懂 Mira

一个 TCP echo，就是整个库的世界观：**你 `co_await` 一个完成，库负责跨平台**。

```cpp
Mira::Task<Mira::Result<void>>
echo_tcp(Mira::transport::tcp::Socket& socket) {
    std::array<std::byte, 4096> buffer{};
    for (;;) {
        auto read = co_await socket.read_some(buffer);   // kqueue/epoll/IOCP 都长这样
        if (!read) {
            if (read.error() == Mira::Errc::eof) co_return Mira::Result<void>{};
            co_return Mira::fail(read.error());
        }
        auto written = co_await Mira::write_all(
            socket, std::span<const std::byte>{buffer}.first(*read));
        if (!written) co_return Mira::fail(written.error());
    }
}
```

HTTP 服务长同一个样子 —— 处理函数是模板自由函数，**换成 TLS 流，代码一个字不用改**：

```cpp
template<Mira::AsyncStream Stream>
Mira::Task<Mira::Result<void>> hello(
    const Mira::http::Request&,
    Mira::http::ResponseWriter<Stream>& writer,
    std::span<const std::byte>) {
    Mira::http::Response response;
    response.status = 200;
    response.headers.append("Content-Type", "text/plain; charset=utf-8");
    std::string_view body = "hello, Mira\n";
    co_return co_await writer.send(response, {
        reinterpret_cast<const std::byte*>(body.data()), body.size()});
}

// TCP 上：co_await Mira::http::serve_connection(socket, &hello<tcp::Socket>);
// TLS 上：co_await Mira::http::serve_connection(tls_stream, &hello<tls::Stream<tcp::Socket>>);
```

## 🎯 为什么是 Mira

| 设计抉择 | 一句话 |
|---|---|
| **网络库，而非兼容层** | 独立设计，不以兼容任何既有 HTTP 库或宿主框架为目标 |
| **等待完成，而非等待就绪** | `co_await read_some(buffer)` 返回读取结果；就绪/完成的平台差异留在后端 |
| **组合，而非绑定** | 协议只认 `AsyncStream`；TLS 不硬编码 HTTP，HTTP 不依赖 OpenSSL |
| **错误与边界说清楚** | `Result<T>` = `std::expected<T, std::error_code>`；取消、截止时间、资源上限是设计标准 |

不以功能数量或未测量的性能排名定义质量。先把生命周期、跨平台语义和协议正确性做扎实，再扩展能力。

## 🏗 模块架构

```mermaid
flowchart TB
    App[应用：组合模块与管理生命周期]
    App -.-> HTTP[http · HTTP/1.1]
    App -.-> TLS[tls · 可选 OpenSSL 3]
    App -.-> TCP[transport · TCP / UDP / Resolver]
    App -.-> H2[http2 · 可选 nghttp2]
    App -.-> H3[http3 · nghttp3]
    App -.-> WS[ws · WebSocket / WSS / RFC7692]
    App -.-> Client[client · HTTP/1 连接池 / SOCKS5 拨号组合]
    App -.-> ClientTLS[client_tls · HTTPS 组合]
    App -.-> SOCKS[socks · SOCKS5]
    App -.-> DNS[dns · DNS 报文 / DoH]
    App -.-> MQTT[mqtt · MQTT 3.1.1 / 5.0]
    Client --> HTTP
    Client --> SOCKS
    Client --> TCP
    SOCKS --> Core
    DNS --> HTTP
    MQTT --> Core
    ClientTLS --> Client
    ClientTLS --> TLS
    WS --> Crypto[crypto · OpenSSL Crypto]
    WS --> Zlib[zlib · raw DEFLATE]
    Crypto --> Core
    WS --> Core
    HTTP --> Core[core · Task / TaskScope / Result / AsyncStream / Executor / Buffer / EventLoop]
    H2 --> Core
    H3 --> QUIC[quic · ngtcp2 / QUIC TLS]
    QUIC --> TCP
    TLS --> Core
    TCP --> Core
    Core --> Backends[kqueue · epoll · IOCP]
```

实线是依赖方向，虚线是应用层组合。HTTP 与 TLS 通过 core 的流契约工作，**不直接依赖 TCP 模块**：运行时可以组合 HTTP → TLS → TCP，也可以是自定义流协议 → TCP。

| 模块 | 职责 |
|---|---|
| `Mira::core` | 协程与任务作用域、流与执行器接口、有界投递、独立线程 `LoopGroup`、共享资源预算 |
| `Mira::transport` | TCP/UDP、本地流、有界系统解析器、交错候选 `tcp::dial`、受管服务生命周期 |
| `Mira::tls` | 同事件循环全双工 TLS 流、独立请求期限、证书与主机名验证、mTLS、多协议 ALPN |
| `Mira::ws` / `Mira::crypto` | WebSocket/WSS、子协议、RFC7692 有界压缩、安全 nonce/mask、Extended CONNECT 字段协商 |
| `Mira::http` | HTTP/1 解析、序列化、单连接服务、流式请求/响应、`Expect: 100-continue` 双工交换；仅依赖流契约 |
| `Mira::client` / `Mira::client_tls` | 独立 HTTP/1 / HTTPS 连接池组合与 `dial_via_socks5`，拥有 DNS/TCP/可选 TLS 与会话生命周期 |
| `Mira::http2` | 可选 nghttp2 Session、多流、Extended CONNECT 与 `ConnectStream` |
| `Mira::quic` / `Mira::http3` | QUIC v1、显式迁移/会话恢复、nghttp3/QPACK、Extended CONNECT、HTTP/3 0-RTT（票据域绑定 SETTINGS） |
| `Mira::socks` | SOCKS5（RFC 1928/1929）客户端与代理握手，按报文精确读长，跑在任意有界流上 |
| `Mira::dns` | DNS 报文编解码（RFC 1035/6891，含 EDNS(0)）与 DoH 映射（RFC 8484） |
| `Mira::mqtt` | MQTT 3.1.1/5.0 全报文编解码、无套接字客户端 `Session`、双工 `Client<Stream>` |

分层由 `tools/ci/check_layering.py` 强制检查：禁止反向依赖与宿主框架头文件，平台识别集中在 `platform.hpp`，协议模块不包含 OS 头文件。

## 📖 API 速览

<details>
<summary><b>TaskScope：结构化并发，显式生命周期</b></summary>

```cpp
Mira::Task<int> count_after_delay(Mira::EventLoop& loop) {
    int count = 0;
    Mira::TaskScope scope;
    scope.spawn(delayed_increment(loop, scope.get_stop_token(), count));
    co_await scope.join();          // 等所有子任务清完才返回
    co_return count;                // count 就在父帧里，不会悬空
}
```

- `join()` 只能调用一次，调用即关闭接纳；第一个子任务异常触发 `request_stop()`，join 收齐后重抛
- 用过未 join 的 scope 析构会 `std::terminate()` —— 这是 fail-fast，不是隐式清理
- await 空 `Task` 抛 `std::logic_error`；传空任务抛 `std::invalid_argument`
</details>

<details>
<summary><b>取消与截止时间：给单个操作加预算</b></summary>

```cpp
co_return co_await loop.read(handle, into,
    {.stop    = std::move(stop),
     .deadline = Mira::EventLoop::Clock::now() + 5s});
```

| 情形 | 结果 |
|---|---|
| 提交时 token 已 stop | `Errc::cancelled`，不提交 |
| 提交时已过截止时间 | `Errc::timed_out`，不提交 |
| 两者同时命中 | `cancelled` —— 显式请求压过被动耗尽 |
| 同批既有真实完成又有取消/超时 | 真实完成优先 |

**绝对时间点，不是时长**：交给 `tls::Stream` 的 `{.deadline = T}` 由该请求独立的事件循环定时器管理，握手或一次读写共享这一绝对期限。底层密文 I/O 不携带请求 deadline，不会为了更新期限而取消、重放密文操作。请求到期或取消会令整个 TLS 会话失效并唤醒另一方向，且在返回前排空相关操作。取消不回滚已发生的 I/O；IOCP 上被取消的读可能丢弃内核已搬运的字节，该连接不能复用。
</details>

<details>
<summary><b>TLS：验证、ALPN 与 mTLS</b></summary>

```cpp
// 服务端：证书 + 私钥，可选强制客户端证书（mTLS）与最低协议版本
auto ctx = Mira::tls::Context::server({
    .cert_file = "server.pem", .key_file = "server-key.pem",
    .client_ca_file = "ca.pem",      // 非空 = 强制 mTLS
    .min_version = "1.2",            // "1.2" / "1.3"
});

// 客户端：验证证书链与主机名；可选出示客户端证书
auto client = Mira::tls::Context::client({
    .ca_file = "ca.pem", .cert_file = "client.pem", .key_file = "client-key.pem",
});
```

- `tls::Stream<T>::create(loop, transport, ctx, "localhost")` → `co_await stream.handshake()` → 正常读写
- 无不安全的验证绕过开关；TLS 1.0/1.1 永远被拒绝
- ALPN 协商后必须检查 `negotiated_protocol()` 再选择 H1/H2 —— 库不自动切换协议
</details>

<details open>
<summary><b>HTTP：两个时长，而不是一个截止时间</b></summary>

`ServerOptions` 收 `idle_timeout`（请求之间的空等）与 `request_timeout`（首字节到响应写完），`serve_connection` 每轮换算成新的绝对时间点 —— 第 100 个 keep-alive 请求和第 1 个享有同样预算。

| 何时到期 | 结果 |
|---|---|
| 请求之间空等超时 | **成功**返回 —— 安静连接被关掉是它正常的结束方式 |
| 请求进行中超时 | `Errc::timed_out` 并关闭连接 |

不发 408：宣告超时就得再要一份调用方从未授予的预算。两个窗口默认关闭，公网服务应当显式设置。
</details>

## 📋 平台矩阵

| 平台 | 后端 | 验证范围 |
|---|---|---|
| macOS | kqueue | 桌面运行测试，含 TLS / HTTPS |
| Linux | epoll | 桌面运行 CI，独立 TLS 矩阵 |
| Windows | IOCP | 桌面 loopback 运行 CI，独立 TLS 矩阵 |
| iOS | kqueue | 宿主 smoke 与无签名交叉编译通过；缺少签名 profile，未完成真机运行 |
| Android | epoll | core / transport / HTTP1 交叉编译，需 **NDK 29+**；无真机运行证据 |

历史 CI 覆盖三桌面基础/TLS/WSS、MinGW H2、sanitizers、HTTP/WebSocket fuzz、Autobahn 双端及 Linux/macOS H2/H3；Windows MSVC 已实跑 QUIC/H3、多客户端与双工 TLS。Linux 使用固定源码构建的 HTTP/3 curl 做独立互操作；其它平台缺少 HTTP3 curl 时明确跳过，不计为通过。新增 Windows 独立 H3 / MinGW 验证入口仅有参数单测 3/3，通过不代表入口已实跑。

验证按快照计量：2026-09-29 阶段源码（H3 0-RTT、MQTT 及文档同步）在本机 AppleClang Release / GCC 16 / ASan+UBSan 各 **97 项：95 通过、2 项外部 HTTP/3 curl 互操作因本机 curl 无 HTTP3 跳过、0 失败**；GCC 13 基础配置 49/49，GCC 14 协议全配置 95 通过 + 2 跳过，MinGW 交叉编译 MQTT 全部目标通过，安装消费与分层检查通过；MQTT 互操作 25 例（其中 mosquitto 2.1.2 8 例），MQTT 模糊测试 ASan+UBSan 91 秒 14.5 万次无崩溃。macOS 未运行 LeakSanitizer。历史提交 [`21322d6` 的 CI](https://github.com/dqsjqian/Mira/actions/runs/36537285723) 为 17/17；本轮新提交的跨平台结果须单独查看顶部 CI，不能借用旧结果。

## ✨ 能力全景

| 领域 | 能力 |
|---|---|
| 执行与生命周期 | 惰性 `Task`、`TaskScope` join、可靠 continuation 投递、有界应用投递、独立线程 `LoopGroup` |
| 取消与截止时间 | `OperationOptions` 贯穿 `EventLoop` → TCP → TLS → HTTP 全栈 |
| TCP | IPv4/IPv6、交错候选 `dial`、短读写、独占绑定、grace drain / cancel / join |
| UDP | IPv4/IPv6、零长数据报、截断报错并消费整包、取消与 deadline |
| DNS | 有界工作线程、系统 getaddrinfo、结果去重、总 deadline；独立 DNS 报文编解码与 DoH GET/POST |
| TLS | OpenSSL 3、证书链与 DNS/IP 验证、mTLS、多协议 ALPN、关闭通知 |
| WebSocket/WSS | 子协议协商、分片与控制帧、UTF-8、可选 permessage-deflate、TCP/TLS 同 loop 双工 |
| 本地传输 / SSE | POSIX Unix-domain socket；基于 HTTP/1 chunked 的 SSE 与 Last-Event-ID 示例 |
| HTTP/1 | 增量解析、keep-alive、HEAD、chunked、流式上传/响应、`Expect: 100-continue` 与提前响应双工、独立 HTTP/HTTPS 池组合 |
| HTTP/2 | nghttp2、HPACK、多流、消费驱动窗口、显式 Extended CONNECT |
| QUIC/H3 | ngtcp2 + nghttp3 + OpenSSL ossl；validated migration、QUIC 会话恢复/显式 0-RTT、HTTP/3 0-RTT（0.5-RTT 应答、拒绝后同流 ID 重提、不安全方法自动 425）、QPACK、Extended CONNECT、两阶段 GOAWAY |
| SOCKS5 | CONNECT 客户端与代理、用户名/密码、握手后流恰好停在隧道首字节、域名目标不在本地解析 |
| MQTT | 3.1.1 / 5.0、QoS 0/1/2 双向流程、CONNACK 限额、主题别名、keep-alive 监督、增强认证、会话恢复重发 |
| 安全与资源 | 协议级限额、有界 TLS BIO、跨 loop 共享预算；非进程 RSS 上限 |

`stop()` 只请求 `run()` 返回；逐操作取消是 `OperationOptions` 的职责 —— 每一层职责清晰、互不越界。

2026-09-30 的审核修复、逐项问题处置与本机验证结果见[审核记录](docs/AUDIT-2026-09-30.md)。历史版本测试数不替代当前源码的验证；Windows 交叉编译与原生运行分别记录。

生产依赖应使用包含安全修复的 OpenSSL：截至 2026-09-30，3.5 LTS 为 **3.5.9**、3.6 分支为 **3.6.5**，也可使用已回移相应修复的供应商包。仅满足 API 最低版本不代表包含这些补丁；其中 [CVE-2026-35189](https://openssl-library.org/news/vulnerabilities/#CVE-2026-35189) 可由对端 TLS 证书触发。CI 源码构建已固定到带哈希校验的 3.5.9。

## 🚀 快速开始

需要 **CMake 3.21+、C++23 编译器**。已验证配置使用 **GCC 14+ / Clang 19+（Linux）/ AppleClang / MSVC v143**；这不是当前工作区所有组合均通过的声明：

- **GCC 14+**：GCC 13 的协程优化器存在已知内部错误（GCC 14 修复）。
- **Linux 上 Clang 19+**：clang-18 的 `__cpp_concepts` 宏版本过旧，libstdc++ 据此隐藏 `std::expected`。

基础 core / transport / HTTP/1 构建零第三方依赖；TLS、WebSocket、HTTP/2、QUIC/HTTP/3 的可选依赖仅在启用对应模块时引入。

```bash
git clone https://github.com/dqsjqian/Mira.git
cd Mira
cmake -S . -B build/debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug -j
ctest --test-dir build/debug --output-on-failure
```

启用 TLS（需要 OpenSSL 3）：

```bash
cmake -S . -B build/tls -DCMAKE_BUILD_TYPE=Debug -DMIRA_ENABLE_TLS=ON
cmake --build build/tls -j && ctest --test-dir build/tls --output-on-failure
```

可选高版本协议：`MIRA_ENABLE_HTTP2=ON` / `MIRA_ENABLE_HTTP3=ON`（默认关闭，不自动联网下载；依赖版本由 `tools/ci/build_protocol_deps.py` SHA256 固定）。

### 最小 client / server 示例

每行先在终端 A 启动 server，再在终端 B 运行 client。全部绑定 loopback，客户端带总 deadline、错误退出码和响应校验；不是只打印成功的伪示例。

| 协议 | 终端 A：server | 终端 B：client |
|---|---|---|
| TCP echo | `build/debug/mira_echo_server 8080` | `build/debug/mira_tcp_client 8080 hello` |
| UDP echo | `build/debug/mira_udp_server 8081` | `build/debug/mira_udp_client 8081 hello` |
| HTTP/1.1 | `build/debug/mira_hello_world_server 8082` | `build/debug/mira_http1_client 8082` |
| HTTP/2 prior knowledge | `build/protocols/mira_h2_prior_knowledge_server 8083` | `build/protocols/mira_h2_client 8083` |
| HTTP/3 | `build/protocols/mira_h3_server 8443 cert.pem key.pem` | `build/protocols/mira_h3_client 8443 cert.pem` |

UDP 客户端传 `""` 可测零字节报文。HTTP1 在同一连接执行两次 keep-alive 请求；H2/H3 提交两个不同流。H2 示例为明文 prior knowledge，不是 TLS/ALPN 示例。H3 示例是单连接多请求，不冒充按 CID 分发的多客户端 listener；生产证书和私钥由调用方管理。

构建 H2/H3（先准备 OpenSSL 3.5+，将 `OPENSSL_ROOT_DIR` 设为其安装路径）：

```bash
python3 tools/ci/build_protocol_deps.py --openssl-root "$OPENSSL_ROOT_DIR"
cmake -S . -B build/protocols -DMIRA_ENABLE_TLS=ON -DMIRA_ENABLE_HTTP2=ON -DMIRA_ENABLE_HTTP3=ON -DCMAKE_PREFIX_PATH="$PWD/build/protocol-deps/prefix" -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR"
cmake --build build/protocols -j
ctest --test-dir build/protocols --output-on-failure
"$OPENSSL_ROOT_DIR/bin/openssl" req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost
```

最后一条命令仅生成本地演示用证书；客户端验证该 CA 与 `localhost`，没有关闭验证。H3 可独立开启而无需 H2/nghttp2。所有成对示例都有进程外自动测试；独立 curl 互操作与同库双端测试分开计量。

### 📦 在自己的项目中使用

版本来源、兼容策略及带 SHA256 校验的源码包消费示例统一见[版本与发布指南](docs/RELEASES.md)。选择 Release 时请阅读对应 tag 下的文档。

已校验并解压的源码可直接加入构建：

```cmake
set(MIRA_BUILD_TESTS OFF)
set(MIRA_BUILD_EXAMPLES OFF)
add_subdirectory(vendor/Mira)
target_link_libraries(my_app PRIVATE Mira::transport Mira::http)
# TLS：同时 set(MIRA_ENABLE_TLS ON) 并额外链接 Mira::tls
```

安装消费使用 `find_package(Mira REQUIRED COMPONENTS core transport http)`，需要 TLS 时加 `tls` 组件；精确版本由消费方的依赖锁定文件指定，见统一指南。

拥有式客户端组合使用 `find_package(Mira REQUIRED COMPONENTS client)` / `Mira::client`；HTTPS 使用 `client_tls` / `Mira::client_tls`，构建时需 `MIRA_ENABLE_TLS=ON`。基础 `client` 不引入 OpenSSL；`http` 本身仍不依赖 transport。协议组件 `socks`、`dns`、`mqtt` 对应 `Mira::socks` / `Mira::dns` / `Mira::mqtt`，均不引入 OpenSSL，TLS 由调用方组合。

Android 需 **NDK 29 或更新**：NDK 27/28 的 libc++ 把 `std::stop_token` 门控关闭了；NDK 29（clang 21）在 API 24 上实测可构建。

## 已落地的生产组合能力

- **单端口多客户端 QUIC/H3**：`quic::Dispatcher` 按实际 DCID 路由（含新 CID），`http3::make_server` 组合 H3；准入、payload 与队列预留有界；默认 `fixed_peer` 拒绝来源变化，显式 `MigrationPolicy::validated` 才允许经路径验证的 migration/NAT rebinding。多个 dispatcher 可共享 `ResourceBudget`。连接终止释放应用预算，保留全部已签发 CID 至少三个 PTO；本地主动关闭按匹配入包限频重发，对端 draining 静默丢弃。关闭槽在准入时预留，不驱逐尚受保护的 CID；显式 `remove()` 才强制清除。这是可核算资源上限，不冒充进程 RSS 的硬限制，也不是完整重放/洪泛防护。
- **QUIC Retry / 来源地址验证**：向 `http3::make_server` / `quic::Listener::create` 传入 `RetryOptions{.policy = RetryPolicy::required}`，在 token 验证前不创建连接、不占连接预算。token 使用 ngtcp2 官方 AEAD，绑定地址、端口、版本、Retry CID、服务作用域与本地端点；过期、未来时间、篡改或来源变化静默拒绝。默认独立随机密钥，可显式轮转并保留一代旧密钥。`ingest().reply` 由调用方即时发送或丢弃，没有内部 Retry 队列。默认每 listener 每个固定 1 秒窗口最多 128 个 Retry，跨窗口边界可突发 256 个；这不是任意滑动秒限额或完整 DDoS 防护，也不提供一次性 token / 防重放保证。默认策略仍为 disabled，公网入口需显式 required。共享密钥要求相同作用域、本地端点、ALPN 与单调时钟基准。
- **H2/H3 出站流式 body**：`request_stream` / `respond_stream` → `write_body` → `finish_body`；预算满返回 `would_block` 且不污染连接。H3 chunk 保留到 ACK，QUIC 双向流轮转避免长流饿死短流。
- **连接生命周期**：`client::HttpClient` / `HttpsClient` 组合解析、`tcp::dial` 与每 origin 有界连接池，客户端实例及固定 TLS 配置彼此隔离；`Session::recycle()` 要求响应完全 drain、连接可复用且无留存 session task，否则拒绝。默认析构丢弃，不自动重放业务请求；`tcp::connect_with_retry` 也只重试建连。`tcp::serve(loop, ...)` 停止接入并关闭 listener，先给 `grace_period` 排空，再协作 cancel 与 join；grace 只限定何时请求取消，不保证不合作 handler 的返回时限。
- **WebSocket/WSS**：`MIRA_ENABLE_WEBSOCKET=ON`，独立 `Mira::ws` + OpenSSL Crypto（安全 nonce/mask、RFC6455 SHA-1 握手）+ zlib；分片、增量 UTF-8、ping/pong/close、消息限额、双向独立互操作。TCP 和 TLS/WSS 均支持同一事件循环上一读一写并行，握手与关闭独占；每个 TLS 请求有独立期限，取消或超时令整个 TLS 会话永久失效并唤醒同伴，不取消后重放密文。`Stream::create` 显式接收事件循环，`close()` 终止包装器但不拥有底层流。支持可选子协议协商与 permessage-deflate，并可经显式协商的 H2/H3 Extended CONNECT 承载；隧道适配器的并发契约与 TCP/TLS 双工不同，见下文。
- **SSE / 本地流**：`mira_sse_server` 演示 chunked SSE、事件 ID 与 Last-Event-ID 恢复；`transport::local` 提供 POSIX filesystem Unix-domain socket，Windows 显式 `not_supported`，不自动删除调用方路径。
- **HTTP/3 0-RTT**：两端 `EarlyDataPolicy::replay_safe`。持票客户端创建即 `early_ready()`，GET/HEAD/OPTIONS 整体请求随 0-RTT 发出；服务端接受后在握手完成前以 0.5-RTT 应答，实测一个往返完成。服务端拒绝时，TLS 保证其未处理任何早期数据，引擎按原顺序重提安全请求并复现相同流 ID，调用方只看到一次正常响应。早期请求在事件上带 `early_data` 标记，不安全方法由引擎直接答 `425 Too Early` 且不上交应用。票据域通过 `early_data_context` 绑定服务端 SETTINGS，SETTINGS 不一致的服务端无法创建。无防重放存储，详见下文。
- **HTTP/1 `Expect: 100-continue` 与双工上传**：`ClientConnection::exchange` 边上传边读取 1xx/最终响应；先等 100、最终响应或 `continue_timeout`，中途收到 ≥300 或关闭即停发剩余 body，提前 2xx 且保持连接则允许上传完成；进行中的写不会为提前响应被取消（TLS 下取消会毁掉会话）。服务端对缓冲 handler 立即答 100，流式 handler 首次读取时答 100，拒收时关闭而不排空，未知期望答 417。
- **SOCKS5 / DoH**：`Mira::socks` 为 CONNECT 客户端与代理提供 RFC 1929 认证与严格地址处理，`client::dial_via_socks5` 一个 deadline 贯穿拨号与握手；`Mira::dns` 以“字节皆不可信”解码 DNS 报文，DoH 双向映射 GET/POST，`doh::query` 可跑在 HTTP/1 over TLS 上。示例与 curl、独立 Python 对端互通。
- **MQTT 3.1.1 / 5.0**：编解码器覆盖全部 15 种报文与两种角色，绝不编出自身解码器会拒收的字节；`Session` 无套接字实现 QoS 1/2 收发、CONNACK 限额、入站主题别名、PINGRESP 监督、增强认证与按原顺序重发的会话恢复；`Client<Stream>` 借用调用方的流，一个读者与串行写者并发，`keep_alive(loop)` 是定时写者，不依赖会毁掉 TLS 会话的读超时。`mira_mqtt_client` 与独立 Python broker 及 mosquitto 互通，CI 强制 mosquitto 用例并对编解码器做模糊测试。

```bash
cmake -S . -B build/ws -DMIRA_ENABLE_WEBSOCKET=ON -DMIRA_ENABLE_TLS=ON
cmake --build build/ws -j
ctest --test-dir build/ws --output-on-failure
# 两个终端分别运行：mira_ws_server 8080 / mira_ws_client 8080
# SSE：mira_sse_server 8081；客户端 GET /events
# 多客户端 H3 + Retry：mira_h3_multi_server cert.pem key.pem 8443 --retry
# SOCKS5：mira_socks5_server 1080 / mira_socks5_client 1080 example.com 80
# DoH：mira_doh_client 1.1.1.1 443 example.com AAAA
# MQTT（本机 mosquitto -p 1883）：mira_mqtt_client 127.0.0.1 1883 echo mira/demo hello --qos 2
```

真实网络基准：`python3 tools/bench/network_bench.py --server build/release/mira_managed_echo_server --clients 8 --requests 1000 --slow-clients 4`，输出吞吐、p50/p99、峰值 RSS 采样和环境 JSON。负载发生器使用独立进程 Python sockets；loopback 数字不是跨库性能排名，也不是公网性能。

### 主线 API 的使用边界

- **QUIC 路径与早期数据**：validated 模式必须使用带 `quic::Path` 的 `receive` 与 `poll_datagram` / `close_datagram`；客户端 `initiate_migration()` 发起验证，应用须保留验证期间所需的两条路径并按返回路径发送。CID 命中不等于通过地址验证。有界内存 `SessionCache` 限制条目、字节、单 ticket 大小与存活期，`ServerContext` 显式共享服务端 ticket 域。普通 `open_stream` / `write` 不发送早期数据；只有 `EarlyDataPolicy::replay_safe` 加 `open_early_stream` / `write_early` 才尝试原始 QUIC 0-RTT。调用方负责保证操作可安全重放；库不提供防重放保证，原始 QUIC 层拒绝后不自动重放。HTTP/3 0-RTT 的契约见下文专节。
- **拨号与上传**：`tcp::dial` 对解析后的去重候选交错 IPv4/IPv6，在总 deadline 内错峰、有界并发建连，返回前取消并 join 落败尝试；系统 `getaddrinfo` 仍在线程池完成，不是独立异步 A/AAAA 查询。HTTP/1 `begin` → `send_body` → `finish` 支持 content-length/chunked 上传、逐块背压与贯穿上传/生产者停顿/响应的预算；这一组是 **send-first**；需要 `Expect: 100-continue` 或上传同时读取提前响应时改用双工 `exchange`，它要求流允许一读一写同时在途（Mira TCP/TLS/本地流均满足），既不读也不关闭的对端仍由 deadline 或 stop 兜底。
- **执行与预算**：`EventLoop::post` 保留可靠 continuation 通道；应用准入走 `try_post` / `BoundedExecutor`，满额返回 `would_block`，后者故意不满足 `Executor`。投递配额在调用前释放，不约束回调新建的异步任务。`LoopGroup` 每 worker 拥有独立线程亲和 loop，配额覆盖排队及未完成根任务；socket 必须在所属 worker 创建/使用，不迁移已关联 socket。共享 `ResourceBudget` 是计量配额，不覆盖全部分配器、第三方状态或进程 RSS。
- **TLS 管理服务示例**：同时启用 TLS/H2 后运行 `build/protocols/mira_https_managed_server cert.pem key.pem 8444 64 16 5000 1000 1000`。它分别限制连接/握手、设置握手 deadline、按协商后的 ALPN 分发 H1/H2、拒绝缺失/未知 ALPN，并演示 grace drain / cancel / join；每连接处理一个 H1 请求或一批 H2 请求，不是通用生产服务器。

QUIC 会话恢复与 0-RTT 要求显式 `ca_file`：缓存键绑定 OpenSSL 实际加载的信任材料摘要（证书、AUX 信任/拒绝用途及 CRL），同路径更换 CA 或信任属性不能复用旧票据。摘要直接取已加载 store，不二次读取路径。`ca_file` 为空时默认系统信任可能包含懒加载来源，因此不保存或恢复票据，只进行完整认证握手；已有连接不会被文件变更追溯撤销。

### H2/H3 Extended CONNECT

在 `http2::Limits` / `http3::Limits` 中显式设置 `enable_connect_protocol = true`；客户端须等实际对端 `SETTINGS_ENABLE_CONNECT_PROTOCOL`，再以 `request_stream` 提交 `:method = CONNECT`、`:protocol`、`:scheme`、`:authority`、`:path`。服务端以 `respond_stream` 接受，只有成功的 2xx 才成为隧道；**204 返回 `not_supported`**，因为当前固定版本的引擎依赖把它视为无 body。普通 CONNECT 代理不在此能力范围。

`http2::ConnectStream<Driver>` / `http3::ConnectStream<Driver>` 借用已接受流；driver 的 `progress(OperationOptions)` / `flush(OperationOptions)` 必须串行驱动连接并遵守取消与 deadline。**每个适配器同一时刻只允许一个操作**，跨流调度和对象/缓冲区存活由调用方负责，不能混用直接 body 操作；`finish()` 半关闭本地输出，`close()`/取消仅 reset 该流，不保证底层 driver 的连接级故障只影响单流。

WebSocket 用 `extended_connect_request` / `accept_extended_connect` / `validate_extended_connect` 校验字段并协商子协议与 PMD，再把 `Negotiated` 交给 `Connection::adopt_extended_connect`；不执行 HTTP/1 Upgrade 或 nonce 握手。`ws.connect_network` 最新实跑 TCP H2 / UDP H3 × 压缩关闭/开启共 4 场景通过。这是同库真实网络证据，不是第三方 Extended CONNECT 互操作；该用例已移除首个 Initial flight 丢包设置，不能作为 PTO 恢复证据。

### WebSocket 子协议与压缩

向 `ws::Connection` 的第四个构造参数传入 `HandshakeOptions`：`subprotocols` 指定有序协议列表，服务端按自身偏好选择交集；`require_subprotocol` 可要求必须达成协商。握手后用 `subprotocol()` 读取选择结果。协议名大小写敏感，客户端拒绝未提议协议、多重选择和重复响应头。

`compression.enabled = true` 才提议/接受 RFC7692 permessage-deflate，默认关闭。支持双向 context takeover、no-context-takeover、窗口协商、压缩分片与穿插控制帧；`read_frame` / `read_message` 返回已解压明文，文本在解压后增量验证 UTF-8。`Limits::max_frame` 同时约束 wire 帧及该帧解压输出，`max_message` 分别约束压缩累计与明文累计。发送窗口支持 9–15，接收支持 8–15；zlib 无法可靠发送 8 位窗口，协商不虚报该能力。压缩状态按方向独立，错误后不再复用。

`compression_parameters()` 返回 wire 协商结果；客户端仍在本地遵守 offer 中更小的窗口及 no-context 承诺。压缩会引入大小侧信道，不应在同一压缩上下文混合秘密与攻击者可控内容；敏感数据默认保持压缩关闭。启用 ws 构建需要 zlib，但基础模块和只用 Crypto 的安装消费不强制查找 zlib。

独立 Python socket/zlib 双向互操作：`python3 tools/ci/check_ws_interop.py --extensions-peer build/ws/mira_ws_extensions_peer`。提交 `d3424f0` 的官方 Autobahn 25.10.1 全量（含压缩）已验：每端 517 项，514 OK + 3 INFORMATIONAL；双端 1,034 项 = 1,028 OK + 6 INFORMATIONAL，零失败、零 NON-STRICT、零缺项、零排除。信息项不冒充严格 OK；后续改动仍须重新验证。完整压缩模式以 `run_autobahn.py --compression` 启动。

### HTTP/3 0-RTT

```cpp
// 服务端：ServerContext 创建前绑定本端 H3 SETTINGS，票据域与 SETTINGS 一一对应
Mira::http3::Limits limits;
server_options.service_scope = "api";
server_options.early_data = Mira::quic::EarlyDataPolicy::replay_safe;
server_options.early_data_context = Mira::http3::early_data_context(limits);
server_options.server_context = Mira::quic::ServerContext::create(server_options).value();

// 客户端：显式 ca_file + 同一 SessionCache；持票时 connect 不发包即返回
client_options.service_scope = "api";
client_options.session_cache = cache;
client_options.early_data = Mira::quic::EarlyDataPolicy::replay_safe;
auto h3 = co_await H3::connect(loop, client_options, limits, io);
auto get = co_await h3->request(get_fields);             // 安全方法：随 0-RTT 发出
auto post = co_await h3->request(post_fields, body, io); // 其他：先完成握手（受 io 约束）再 1-RTT
```

客户端不记忆服务端 SETTINGS，早期请求一律按默认值（QPACK 动态表 0、无 Extended CONNECT），RFC 9114 §7.2.4.2 允许且任何合规服务端都能接受。兼容性判断落在服务端：`http3::Engine::create` / `make_server` 拒绝 SETTINGS 与票据域不一致的配置，而其他 `ServerContext` 签发的票据本就无法解密。服务端应用对带 `early_data` 的安全方法请求仍须自行判断能否执行两次（RFC 8470，不能则答 425）；没有防重放存储，截获的 0-RTT 首包可被重放到共享票据域的任一服务端。

### MQTT

```cpp
Mira::mqtt::ClientOptions options;                        // 默认 5.0；options.version 可选 v311
options.client_id = "sensor-7";
options.keep_alive = 30;
auto client = co_await Mira::mqtt::Client<tcp::Socket>::connect(socket, options, io);
auto sub = co_await client->subscribe({{"sensors/+/temp", Mira::mqtt::QoS::at_least_once}});
auto granted = co_await client->wait_for(*sub);           // SUBACK，其余事件留给 receive
auto id = co_await client->publish("sensors/7/temp", payload, Mira::mqtt::QoS::exactly_once);
auto events = co_await client->receive();                 // 消息、发布完成、服务端 DISCONNECT……
// keep_alive(loop) 是定时写者：与 receive 在同一 loop 并发，TLS 下同样安全
```

流由调用方拥有并在客户端之后销毁；客户端从不关闭它。超出服务端 Receive Maximum、包标识耗尽或输出预算满时返回 `would_block`，不暗中排队；对端违规时 5.0 以带原因的 DISCONNECT 关闭会话。收到的 QoS 1 消息在上交时即确认。断线后在新流上 `reconnect`：`clean_start = false` 且服务端报告会话仍在时，未确认的 PUBLISH（DUP）与 PUBREL 按原顺序重发，否则以 `discarded` 事件报告。不含 broker、MQTT over WebSocket、出站主题别名、会话持久化与重连策略。

### Retry 真实 UDP 故障验收

启用 `MIRA_ENABLE_HTTP3=ON` 与 `MIRA_BUILD_BENCH=ON` 后，可复现有界丢包、重复、延迟、重排与连接 churn：

```bash
python3 tools/bench/run_h3_soak.py --binary build/protocols/bench/bench_h3_soak \
  --duration-seconds 600 --seed 20260929 --output build/h3-soak.json
```

每轮验证二进制内容、慢响应期间新短流的进展、关闭保护槽与最终预算归零；超时或内容错误非零退出。默认是 3 客户端、每轮各 4 条流，128 KiB 大 body 经 16 KiB 协议缓冲流式传输。固定 seed 固定故障选择策略，不保证实际调度或随机 CID 逐包一致；这是单机 loopback 持续验收，不是多机或长时稳定性认证。初始正常关闭包不注入故障，RSS 仅采样不设硬上限。运行期间需保持机器唤醒，合盖休眠导致的超时仍判失败。

已记录的 600 秒报告 `build/all-main/sustained-600.json`：13,548/13,548 请求成功，10,161/10,161 短流在慢响应重叠期间完成；最终 connections、routes、tombstones、queued_bytes、reserved_payload_bytes 均为 0。报告为单机真实 UDP loopback，不代表多机/WAN、所有后续源码或进程 RSS 硬上限。

## 接下来：仍需验证的边界

1. iOS 已通过宿主 smoke 和无签名交叉编译，真机缺签名 profile；Android 真机尚无证据。Windows MSVC H3、WSS 全双工及 TLS 1.3 KeyUpdate 已有运行回归；新增 Windows 独立 H3 / MinGW 入口只有参数单测 3/3，仍待实跑。
2. 本轮新提交的跨平台 CI、更长时故障注入、真实多机/WAN 与进程内存治理仍待验；2026-09-28 历史快照的三套本机矩阵曾各通过 85/85，此数字不代表当前源码。官方 Autobahn 全量含压缩仅有上述 `d3424f0` 的完整报告；可用 `python3 tools/ci/run_autobahn.py --server build/ws/mira_ws_autobahn_server --client build/ws/mira_ws_autobahn_client --runtime docker --compression` 在 Linux 复现，完整报告由 CI 保存。
3. QUIC validated migration/NAT rebinding、显式原始 QUIC 0-RTT、HTTP/3 0-RTT 与 H2/H3 Extended CONNECT 已在主线实现，但完整防重放保证与第三方 Extended CONNECT 互操作未交付/未验证；HTTP/3 0-RTT 目前只有同库引擎与真实 UDP 证据，尚无第三方 0-RTT 互操作。Retry 不保证 token 一次性使用，listener 不是互联网抗洪泛防护系统。
4. **2026-09-29 阶段已交付**：HTTP/3 0-RTT、HTTP/1 `Expect: 100-continue` / 提前响应双工，以及独立 SOCKS5、DNS/DoH、MQTT 模块。仍开放：0-RTT 防重放存储、客户端记忆服务端 SETTINGS、打包好的 DoH over H2/H3 查询、MQTT over WebSocket 与会话持久化。gRPC/Redis/WebRTC 保持生态层边界，不将专业子系统全部塞进网络内核。

设计依据与验收要求见[架构文档](docs/ARCHITECTURE.md)。

## 🤝 贡献

欢迎从一个可复现问题、一条明确契约或一个针对性测试开始。修改请保持模块单向依赖，说明所有权与平台差异，并运行相关测试与 `tools/ci/check_layering.py`。性能改进请附可复现的环境与测量方法。

## 🙏 致谢

- [nghttp2](https://github.com/nghttp2/nghttp2) —— HTTP/2 引擎（可选）
- [ngtcp2](https://github.com/ngtcp2/ngtcp2) / [nghttp3](https://github.com/ngtcp2/nghttp3) —— QUIC / HTTP/3 引擎
- [OpenSSL](https://www.openssl.org/) —— TLS 1.2/1.3 与 QUIC TLS（可选）

## 📄 License

[MIT](LICENSE) © 2026 Mira contributors

---

<div align="center">

**📖 其他语言**

[English](README.en.md)

</div>
