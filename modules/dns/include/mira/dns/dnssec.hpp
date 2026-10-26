#pragma once

#include "mira/dns/message.hpp"
#include "mira/core/operation.hpp"
#include "mira/core/task.hpp"

#include <functional>

namespace Mira::dns::dnssec {

inline constexpr std::uint16_t ds_type = 43, rrsig_type = 46, dnskey_type = 48;

struct Dnskey {
    std::uint16_t flags = 0;
    std::uint8_t protocol = 3, algorithm = 0;
    std::vector<std::byte> public_key{};
};
struct Ds {
    std::uint16_t key_tag = 0;
    std::uint8_t algorithm = 0, digest_type = 2;
    std::vector<std::byte> digest{};
};
struct Rrsig {
    std::uint16_t type_covered = 0;
    std::uint8_t algorithm = 0, labels = 0;
    std::uint32_t original_ttl = 0, expiration = 0, inception = 0;
    std::uint16_t key_tag = 0;
    Name signer{};
    std::vector<std::byte> signature{};
};

[[nodiscard]] Result<Dnskey> parse_dnskey(const Record& record);
[[nodiscard]] Result<Ds> parse_ds(const Record& record);
[[nodiscard]] Result<Rrsig> parse_rrsig(const Record& record);
[[nodiscard]] std::uint16_t key_tag(const Dnskey& key);
[[nodiscard]] Result<Ds> make_ds(const Name& owner, const Dnskey& key);
/// RFC 4034 规范序列：小写名称、原始 TTL、RDATA 排序并去重；拒绝未实现规范化的类型。
/// 不接受 wildcard 展开（labels 不等于 owner 标签数），因为需要额外否定证明。
[[nodiscard]] Result<std::vector<std::byte>> signed_data(std::span<const Record> rrset,
    const Rrsig& signature, std::size_t max_bytes = 1024 * 1024);

struct TrustAnchor {
    Name zone{};
    Ds ds{};
    /// 外部可信时间的 Unix 秒，半开有效区间；轮转通过重叠窗口的多个 DS 显式配置。
    std::uint64_t valid_from = 0, valid_until = UINT64_MAX;
};
struct ValidationOptions {
    std::size_t max_records = 2048;
    std::size_t max_bytes = 1024 * 1024;
    std::size_t max_depth = 32;
    std::size_t max_signature_checks = 128;
    std::size_t max_queries = 64;
    Clock::duration timeout = std::chrono::seconds(10);
};
struct VerifiedAnswer {
    /// 仅返回问题对应、已验签 RRset；绝不将未验证 additional/authority 标记为安全。
    std::vector<Record> records{};
    /// 已限制到 RR/RRSIG TTL、签名及整条信任链/锚的剩余有效期。
    std::uint32_t ttl = 0;
};
using Exchange = std::function<Task<Result<Message>>(Message, OperationOptions)>;

/// 显式 DNSSEC 正向回答验证，普通 DNS 查询语义不变；AD 位没有任何信任意义。
/// 算法 13（ECDSA P-256/SHA-256）、15（Ed25519），DS SHA-256；不提供弱算法回退。
/// 从外部配置 DS 信任锚出发验 DNSKEY 自签、父区 DS 委派及目标 RRset。
/// 锚不从网络自动导入：replace_anchors 原子更新并保留失败前配置，调用者负责
/// 带外可信分发和轮转窗口；不声称 RFC5011 自动锚维护。时间由调用者可信时钟给出。
/// 支持 A/AAAA/NS/CNAME/PTR/MX/TXT/SOA/DNSKEY/DS 的规范化与正向验签；
/// NXDOMAIN/NODATA、NSEC/NSEC3、wildcard 展开、CNAME 自动追踪均 fail closed
/// 为 not_supported（可单独验证 CNAME RRset）。不缓存结果、不采用 AD 作为证据。
/// 单事件循环使用；网络 query 独占其 Exchange，Exchange 应由 UDP/TCP/DoH 映射组成。
class Validator {
public:
    [[nodiscard]] static Result<Validator> create(std::vector<TrustAnchor> anchors,
        ValidationOptions options = {});
    [[nodiscard]] Result<void> replace_anchors(std::vector<TrustAnchor> anchors);
    /// evidence 包含相同交换/调用者收集的 DNSKEY、RRSIG、DS。全量有界，验证不触网。
    [[nodiscard]] Result<VerifiedAnswer> validate(const Message& response, const Question& question,
        std::span<const Record> evidence, std::uint64_t unix_seconds) const;
    /// 实际查询及证据收集：开启 DO/CD，从回答签名者逐级取 DNSKEY/DS 至配置锚。
    /// 共享截止时间、查询/字节/记录/深度/验签上限；任何缺证明或验证失败不返回原回答。
    /// 调用当下即复制配置；随后可销毁或轮转原 Validator，不改变已创建任务的信任锚。
    /// Exchange 按值保留，但其捕获的外部资源仍须存活到任务完成。
    [[nodiscard]] Task<Result<VerifiedAnswer>> query(Exchange exchange, Question question,
        std::uint64_t unix_seconds, OperationOptions io = {}) const;
private:
    static Task<Result<VerifiedAnswer>> query_impl(Validator snapshot, Exchange exchange, Question question,
        std::uint64_t unix_seconds, OperationOptions io);
    Validator(std::vector<TrustAnchor> anchors, ValidationOptions options)
        : anchors_(std::move(anchors)), options_(options) {}
    std::vector<TrustAnchor> anchors_;
    ValidationOptions options_;
};

}  // namespace Mira::dns::dnssec
