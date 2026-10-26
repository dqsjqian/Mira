#include "check.hpp"
#include "mira/dns/dnssec.hpp"
#include "mira/crypto/crypto.hpp"
#include "mira/core/event_loop.hpp"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <algorithm>
#include <memory>

using namespace Mira;
using namespace Mira::dns;
using namespace Mira::dns::dnssec;

namespace {
using Bytes = std::vector<std::byte>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
constexpr std::uint64_t now = 1'750'000'000;
Name name(std::string_view text) { return *Name::parse(text); }
void u16(Bytes& out, std::uint16_t v) { out.push_back(std::byte(v >> 8)); out.push_back(std::byte(v & 255)); }
void u32(Bytes& out, std::uint32_t v) { u16(out, static_cast<std::uint16_t>(v >> 16)); u16(out, static_cast<std::uint16_t>(v)); }
void put_name(Bytes& out, const Name& n) {
    for (const auto& label : n.labels()) {
        out.push_back(std::byte(label.size()));
        for (char c : label) out.push_back(std::byte(static_cast<unsigned char>(c >= 'A' && c <= 'Z' ? c + 32 : c)));
    }
    out.push_back(std::byte{0});
}
Bytes hex(std::string_view text) {
    Bytes out;
    const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (std::size_t i = 0; i + 1 < text.size(); i += 2) out.push_back(std::byte(digit(text[i]) * 16 + digit(text[i + 1])));
    return out;
}
Key generate(std::uint8_t algorithm) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx{
        EVP_PKEY_CTX_new_from_name(nullptr, algorithm == 15 ? "ED25519" : "EC", nullptr), EVP_PKEY_CTX_free};
    CHECK(ctx && EVP_PKEY_keygen_init(ctx.get()) == 1);
    if (algorithm == 13) CHECK(EVP_PKEY_CTX_set_group_name(ctx.get(), "prime256v1") == 1);
    EVP_PKEY* value = nullptr;
    CHECK(EVP_PKEY_generate(ctx.get(), &value) == 1);
    return Key{value, EVP_PKEY_free};
}
Dnskey public_key(EVP_PKEY* private_key, std::uint8_t algorithm) {
    Dnskey result{257, 3, algorithm, {}};
    std::array<unsigned char, 65> bytes{};
    std::size_t size = bytes.size();
    if (algorithm == 15) {
        CHECK(EVP_PKEY_get_raw_public_key(private_key, bytes.data(), &size) == 1);
        const auto view = std::as_bytes(std::span{bytes}.first(size));
        result.public_key.assign(view.begin(), view.end());
    } else {
        CHECK(EVP_PKEY_get_octet_string_param(private_key, OSSL_PKEY_PARAM_PUB_KEY, bytes.data(), bytes.size(), &size) == 1);
        CHECK(size == 65 && bytes[0] == 4);
        const auto view = std::as_bytes(std::span{bytes}.subspan(1));
        result.public_key.assign(view.begin(), view.end());
    }
    return result;
}
Bytes sign(EVP_PKEY* key, std::uint8_t algorithm, std::span<const std::byte> data) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    CHECK(EVP_DigestSignInit(ctx.get(), nullptr, algorithm == 13 ? EVP_sha256() : nullptr, nullptr, key) == 1);
    std::size_t size = 0;
    CHECK(EVP_DigestSign(ctx.get(), nullptr, &size, reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1);
    std::vector<unsigned char> out(size);
    CHECK(EVP_DigestSign(ctx.get(), out.data(), &size, reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1);
    out.resize(size);
    if (algorithm == 13) {
        const auto* cursor = out.data();
        std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig{d2i_ECDSA_SIG(nullptr, &cursor, static_cast<long>(size)), ECDSA_SIG_free};
        CHECK(sig != nullptr);
        const BIGNUM *r = nullptr, *s = nullptr;
        ECDSA_SIG_get0(sig.get(), &r, &s);
        out.resize(64);
        CHECK(BN_bn2binpad(r, out.data(), 32) == 32 && BN_bn2binpad(s, out.data() + 32, 32) == 32);
    }
    const auto view = std::as_bytes(std::span{out});
    return {view.begin(), view.end()};
}
Record key_record(const Name& zone, const Dnskey& key) {
    Bytes wire; u16(wire, key.flags); wire.push_back(std::byte(key.protocol)); wire.push_back(std::byte(key.algorithm));
    wire.insert(wire.end(), key.public_key.begin(), key.public_key.end());
    return {zone, dnskey_type, class_in, 300, RawData{std::move(wire)}};
}
Record ds_record(const Name& zone, const Ds& ds) {
    Bytes wire; u16(wire, ds.key_tag); wire.push_back(std::byte(ds.algorithm)); wire.push_back(std::byte(ds.digest_type));
    wire.insert(wire.end(), ds.digest.begin(), ds.digest.end());
    return {zone, ds_type, class_in, 300, RawData{std::move(wire)}};
}
Record sig_record(std::span<const Record> set, const Name& signer, const Dnskey& key, EVP_PKEY* secret,
    std::uint32_t inception = static_cast<std::uint32_t>(now - 100), std::uint32_t expiration = static_cast<std::uint32_t>(now + 100)) {
    Rrsig sig{set.front().type, key.algorithm, static_cast<std::uint8_t>(set.front().name.labels().size()),
        300, expiration, inception, key_tag(key), signer, {}};
    auto data = signed_data(set, sig);
    CHECK(data.has_value());
    sig.signature = sign(secret, key.algorithm, *data);
    Bytes wire; u16(wire, sig.type_covered); wire.push_back(std::byte(sig.algorithm)); wire.push_back(std::byte(sig.labels));
    u32(wire, sig.original_ttl); u32(wire, sig.expiration); u32(wire, sig.inception); u16(wire, sig.key_tag); put_name(wire, signer);
    wire.insert(wire.end(), sig.signature.begin(), sig.signature.end());
    return {set.front().name, rrsig_type, class_in, 300, RawData{std::move(wire)}};
}
struct Fixture {
    Name zone = name("example");
    Question question{name("www.example"), type::a, class_in};
    Key secret;
    Dnskey key;
    Record dnskey;
    Message response;
    std::vector<Record> evidence;
    TrustAnchor anchor;
    explicit Fixture(std::uint8_t algorithm = 15) : secret(generate(algorithm)), key(public_key(secret.get(), algorithm)), dnskey(key_record(zone, key)) {
        response.header.qr = true; response.header.ad = true;
        response.questions.push_back(question);
        response.answers.push_back({question.name, type::a, class_in, 300, AData{{192, 0, 2, 1}}});
        response.answers.push_back(sig_record(std::span{response.answers}, zone, key, secret.get()));
        evidence.push_back(dnskey);
        evidence.push_back(sig_record(std::span{evidence}, zone, key, secret.get()));
        anchor = {zone, *make_ds(zone, key), now - 1000, now + 1000};
    }
    Validator validator() const { return *Validator::create({anchor}); }
};

void primitive_vectors() {
    test::section("RFC8032 Ed25519 独立向量及 SHA256 已知摘要");
    const auto pub = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    auto sig = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    auto valid = crypto::verify_signature(crypto::SignatureAlgorithm::ed25519, pub, {}, sig);
    CHECK(valid && *valid);
    sig[0] ^= std::byte{1};
    valid = crypto::verify_signature(crypto::SignatureAlgorithm::ed25519, pub, {}, sig);
    CHECK(valid && !*valid);
    CHECK(!crypto::verify_signature(crypto::SignatureAlgorithm::ed25519, {}, {}, sig));
    const auto digest = crypto::sha256({});
    const auto expected = hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(digest && std::equal(digest->begin(), digest->end(), expected.begin()));
}

void basic_validation() {
    for (auto algorithm : {std::uint8_t{13}, std::uint8_t{15}}) {
        test::section(algorithm == 13 ? "P256 正向验签和拒绝路径" : "Ed25519 正向验签和拒绝路径");
        Fixture f{algorithm}; auto validator = f.validator();
        auto result = validator.validate(f.response, f.question, f.evidence, now);
        CHECK(result && result->records.size() == 1 && result->ttl == 100);
        auto wire = encode(f.response);
        CHECK(wire.has_value());
        auto decoded = decode(*wire);
        CHECK(decoded && validator.validate(*decoded, f.question, f.evidence, now).has_value());
        auto altered = f.response;
        std::get<AData>(altered.answers[0].data).address[3] = 9;
        CHECK(!validator.validate(altered, f.question, f.evidence, now));
        altered = f.response;
        std::get<RawData>(altered.answers[1].data).bytes.back() ^= std::byte{1};
        CHECK(!validator.validate(altered, f.question, f.evidence, now));
        altered = f.response; altered.answers.resize(1);
        CHECK(!validator.validate(altered, f.question, f.evidence, now));
        altered = f.response; altered.header.ad = false;
        CHECK(validator.validate(altered, f.question, f.evidence, now).has_value());
        CHECK(!validator.validate(f.response, f.question, {}, now));
        CHECK(!validator.validate(f.response, f.question, f.evidence, now + 100));
        CHECK(!validator.validate(f.response, f.question, f.evidence, now - 101));
        altered = f.response; altered.questions[0].name = name("wrong.example");
        CHECK(!validator.validate(altered, f.question, f.evidence, now));
        altered = f.response; altered.header.rcode = rcode::nxdomain;
        CHECK(validator.validate(altered, f.question, f.evidence, now).error() == Errc::not_supported);
        altered = f.response; altered.answers.clear();
        CHECK(validator.validate(altered, f.question, f.evidence, now).error() == Errc::not_supported);
        altered = f.response;
        std::get<RawData>(altered.answers[1].data).bytes[3] = std::byte{1};
        CHECK(!validator.validate(altered, f.question, f.evidence, now));
        auto malformed_then_valid = f.response;
        auto invalid_signature = malformed_then_valid.answers[1];
        std::get<RawData>(invalid_signature.data).bytes[2] = std::byte{8};
        malformed_then_valid.answers.insert(malformed_then_valid.answers.begin() + 1, invalid_signature);
        CHECK(validator.validate(malformed_then_valid, f.question, f.evidence, now).has_value());
        auto unknown_key = f.evidence;
        std::get<RawData>(unknown_key[0].data).bytes[3] = std::byte{8};
        CHECK(!validator.validate(f.response, f.question, unknown_key, now));
        auto revoked_key = f.evidence;
        std::get<RawData>(revoked_key[0].data).bytes[1] |= std::byte{0x80};
        CHECK(!validator.validate(f.response, f.question, revoked_key, now));
        auto limited = *Validator::create({f.anchor}, {.max_signature_checks = 1});
        CHECK(limited.validate(f.response, f.question, f.evidence, now).error() == Errc::limit_exceeded);
        limited = *Validator::create({f.anchor}, {.max_records = 3});
        CHECK(limited.validate(f.response, f.question, f.evidence, now).error() == Errc::limit_exceeded);
        limited = *Validator::create({f.anchor}, {.max_bytes = 512});
        auto oversized = f.evidence;
        oversized.push_back({f.zone, 65000, class_in, 0, RawData{Bytes(1024, std::byte{0})}});
        CHECK(limited.validate(f.response, f.question, oversized, now).error() == Errc::limit_exceeded);
        auto wrong_signer = f.response;
        auto another = name("unrelated");
        wrong_signer.answers[1] = sig_record(std::span{&wrong_signer.answers[0], 1}, another, f.key, f.secret.get());
        CHECK(!validator.validate(wrong_signer, f.question, f.evidence, now));
    }
}

void anchors_and_chain() {
    test::section("带外锚轮转有效窗与错误配置原子保留");
    Fixture old_key, new_key;
    auto validator = old_key.validator();
    CHECK(!validator.validate(new_key.response, new_key.question, new_key.evidence, now));
    CHECK(validator.replace_anchors({old_key.anchor, new_key.anchor}).has_value());
    CHECK(validator.validate(old_key.response, old_key.question, old_key.evidence, now).has_value());
    CHECK(validator.validate(new_key.response, new_key.question, new_key.evidence, now).has_value());
    auto invalid = new_key.anchor; invalid.valid_until = invalid.valid_from;
    CHECK(!validator.replace_anchors({invalid}));
    CHECK(validator.validate(old_key.response, old_key.question, old_key.evidence, now).has_value());
    CHECK(validator.replace_anchors({new_key.anchor}).has_value());
    CHECK(!validator.validate(old_key.response, old_key.question, old_key.evidence, now));
    auto expired = new_key.anchor; expired.valid_until = now;
    CHECK(validator.replace_anchors({expired}).has_value());
    CHECK(!validator.validate(new_key.response, new_key.question, new_key.evidence, now));
    expired.valid_until = now + 10;
    CHECK(validator.replace_anchors({expired}).has_value());
    auto bounded = validator.validate(new_key.response, new_key.question, new_key.evidence, now);
    CHECK(bounded && bounded->ttl == 10);

    test::section("RRSIG 32位序列时间回卷保持有效区间");
    Fixture wrapped;
    constexpr std::uint64_t wrap_now = 0x1'00000010ULL;
    wrapped.anchor.valid_from = wrap_now - 1000; wrapped.anchor.valid_until = wrap_now + 1000;
    wrapped.response.answers[1] = sig_record(std::span{&wrapped.response.answers[0], 1}, wrapped.zone,
        wrapped.key, wrapped.secret.get(), 0xfffffff0U, 0x00000030U);
    wrapped.evidence[1] = sig_record(std::span{&wrapped.evidence[0], 1}, wrapped.zone,
        wrapped.key, wrapped.secret.get(), 0xfffffff0U, 0x00000030U);
    auto wrap_validator = wrapped.validator();
    auto wrap_result = wrap_validator.validate(wrapped.response, wrapped.question, wrapped.evidence, wrap_now);
    CHECK(wrap_result && wrap_result->ttl == 32);
    CHECK(!wrap_validator.validate(wrapped.response, wrapped.question, wrapped.evidence, wrap_now + 32));

    test::section("父区 DS 委派链到根锚，篡改和缺失证明拒绝");
    Fixture child;
    auto parent_secret = generate(13);
    auto parent_key = public_key(parent_secret.get(), 13);
    const Name root;
    const auto parent = key_record(root, parent_key);
    std::vector<Record> evidence = child.evidence;
    evidence.push_back(parent);
    evidence.push_back(sig_record(std::span{&parent, 1}, root, parent_key, parent_secret.get()));
    const auto ds = ds_record(child.zone, *make_ds(child.zone, child.key));
    evidence.push_back(ds);
    evidence.push_back(sig_record(std::span{&ds, 1}, root, parent_key, parent_secret.get()));
    auto chain = *Validator::create({TrustAnchor{root, *make_ds(root, parent_key), 0, now + 1000}});
    auto verified = chain.validate(child.response, child.question, evidence, now);
    CHECK(verified && verified->ttl == 100);
    auto tampered = evidence;
    std::get<RawData>(tampered[tampered.size() - 2].data).bytes.back() ^= std::byte{1};
    CHECK(!chain.validate(child.response, child.question, tampered, now));
    evidence.pop_back();
    CHECK(!chain.validate(child.response, child.question, evidence, now));
}

void canonical_and_malformed() {
    test::section("RRset 规范名称、RDATA 字节排序、去重及原始 TTL");
    const Name owner = name("WWW.Example");
    Rrsig sig{type::a, 15, 2, 300, 2000, 1000, 0x1234, name("Example"), {}};
    Record a{owner, type::a, class_in, 10, AData{{192, 0, 2, 1}}};
    Record b{owner, type::a, class_in, 20, AData{{192, 0, 2, 2}}};
    std::array set{b, a, a};
    auto canonical = signed_data(set, sig);
    Bytes expected; u16(expected, type::a); expected.push_back(std::byte{15}); expected.push_back(std::byte{2});
    u32(expected, 300); u32(expected, 2000); u32(expected, 1000); u16(expected, 0x1234); put_name(expected, name("example"));
    for (unsigned char last : {static_cast<unsigned char>(1), static_cast<unsigned char>(2)}) {
        put_name(expected, name("www.example")); u16(expected, type::a); u16(expected, class_in); u32(expected, 300); u16(expected, 4);
        for (auto byte : {192, 0, 2, static_cast<int>(last)}) expected.push_back(std::byte(byte));
    }
    CHECK(canonical && *canonical == expected);
    CHECK(signed_data(set, sig, 32).error() == Errc::limit_exceeded);
    sig.labels = 1;
    CHECK(signed_data(set, sig).error() == Errc::not_supported);
    Fixture f;
    auto raw = std::get<RawData>(f.response.answers[1].data).bytes;
    for (std::size_t i = 0; i < 19; ++i) {
        auto record = f.response.answers[1]; std::get<RawData>(record.data).bytes.resize(i);
        CHECK(!parse_rrsig(record));
    }
    auto compressed = f.response.answers[1];
    std::get<RawData>(compressed.data).bytes[18] = std::byte{0xc0};
    CHECK(!parse_rrsig(compressed));
    auto key = f.dnskey; std::get<RawData>(key.data).bytes.resize(3);
    CHECK(!parse_dnskey(key));
    auto invalid = f.anchor; invalid.ds.algorithm = 8;
    CHECK(!Validator::create({invalid}));
    invalid = f.anchor; invalid.ds.digest_type = 1;
    CHECK(!Validator::create({invalid}));
}

Task<void> query_integration() {
    test::section("显式查询收集 DNSKEY 并密码学验证，DO/CD/截止时间和失败不旁路");
    Fixture f;
    auto validator = f.validator();
    std::size_t calls = 0;
    bool tamper = false;
    Exchange exchange = [&](Message request, OperationOptions io) -> Task<Result<Message>> {
        ++calls;
        CHECK(request.edns && request.edns->dnssec_ok && request.header.cd && io.deadline.has_value());
        Message response;
        if (request.questions.front().type == type::a) {
            response = f.response;
            if (tamper) std::get<AData>(response.answers[0].data).address[0] = 1;
        } else {
            CHECK(request.questions.front().type == dnskey_type && request.questions.front().name == f.zone);
            response.header.qr = true; response.questions = request.questions; response.answers = f.evidence;
        }
        response.header.id = request.header.id;
        auto wire = encode(response);
        CHECK(wire.has_value());
        co_return decode(*wire);
    };
    auto result = co_await validator.query(exchange, f.question, now);
    CHECK(result && result->records.size() == 1 && calls == 2);
    test::section("任务创建后销毁或轮转 Validator 不影响既定信任快照");
    Fixture other;
    const auto delayed = [&] {
        auto temporary = f.validator();
        return temporary.query(exchange, f.question, now);
    };
    auto owned_task = delayed();
    result = co_await std::move(owned_task);
    CHECK(result.has_value());
    auto before_rotation = validator.query(exchange, f.question, now);
    CHECK(validator.replace_anchors({other.anchor}).has_value());
    result = co_await std::move(before_rotation);
    CHECK(result.has_value());
    result = co_await validator.query(exchange, f.question, now);
    CHECK(!result);
    CHECK(validator.replace_anchors({f.anchor}).has_value());
    bool rotated = false;
    Exchange rotate_during_query = [&](Message request, OperationOptions io) -> Task<Result<Message>> {
        if (!rotated) {
            rotated = true;
            CHECK(validator.replace_anchors({other.anchor}).has_value());
        }
        co_return co_await exchange(std::move(request), io);
    };
    result = co_await validator.query(rotate_during_query, f.question, now);
    CHECK(result && rotated);
    CHECK(validator.replace_anchors({f.anchor}).has_value());
    tamper = true;
    result = co_await validator.query(exchange, f.question, now);
    CHECK(!result);
    auto limited = *Validator::create({f.anchor}, {.max_queries = 1});
    result = co_await limited.query(exchange, f.question, now);
    CHECK(!result && result.error() == Errc::limit_exceeded);
    const auto before = calls;
    std::stop_source stop; stop.request_stop();
    result = co_await validator.query(exchange, f.question, now, {.stop = stop.get_token()});
    CHECK(!result && result.error() == Errc::cancelled && calls == before);
    result = co_await validator.query(exchange, f.question, now, {.deadline = Clock::now()});
    CHECK(!result && result.error() == Errc::timed_out && calls == before);

    test::section("查询集成收集父区 DS 与根 DNSKEY，并拒绝伪造委派");
    auto root_secret = generate(13);
    auto root_key = public_key(root_secret.get(), 13);
    const Name root;
    const auto root_record = key_record(root, root_key);
    const auto root_signature = sig_record(std::span{&root_record, 1}, root, root_key, root_secret.get());
    const auto delegation = ds_record(f.zone, *make_ds(f.zone, f.key));
    const auto delegation_signature = sig_record(std::span{&delegation, 1}, root, root_key, root_secret.get());
    auto chained = *Validator::create({TrustAnchor{root, *make_ds(root, root_key), 0, now + 1000}});
    bool corrupt_ds = false;
    calls = 0;
    Exchange delegated = [&](Message request, OperationOptions) -> Task<Result<Message>> {
        ++calls;
        const auto& q = request.questions.front();
        Message answer; answer.header.qr = true; answer.questions = request.questions;
        if (q.type == type::a) answer = f.response;
        else if (q.type == dnskey_type && q.name == f.zone) answer.answers = f.evidence;
        else if (q.type == ds_type && q.name == f.zone) {
            answer.answers = {delegation, delegation_signature};
            if (corrupt_ds) std::get<RawData>(answer.answers[0].data).bytes.back() ^= std::byte{1};
        } else if (q.type == dnskey_type && q.name.is_root()) answer.answers = {root_record, root_signature};
        else CHECK(false);
        co_return answer;
    };
    result = co_await chained.query(delegated, f.question, now);
    CHECK(result && calls == 4);
    corrupt_ds = true;
    result = co_await chained.query(delegated, f.question, now);
    CHECK(!result);
}

}  // namespace

int main() {
    primitive_vectors();
    basic_validation();
    anchors_and_chain();
    canonical_and_malformed();
    auto loop = EventLoop::create();
    CHECK(loop.has_value());
    if (loop) CHECK(loop->run_until_complete(query_integration()).has_value());
    return test::summary();
}
