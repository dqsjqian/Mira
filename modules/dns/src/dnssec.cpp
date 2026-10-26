#include "mira/dns/dnssec.hpp"
#include "mira/crypto/crypto.hpp"

#include <algorithm>
#include <limits>
#include <set>

namespace Mira::dns::dnssec {
namespace {
using Bytes = std::vector<std::byte>;
Error denied() { return std::make_error_code(std::errc::permission_denied); }
void u16(Bytes& out, std::uint16_t value) {
    out.push_back(std::byte(value >> 8)); out.push_back(std::byte(value & 255U));
}
void u32(Bytes& out, std::uint32_t value) { u16(out, static_cast<std::uint16_t>(value >> 16)); u16(out, static_cast<std::uint16_t>(value)); }
void name_wire(Bytes& out, const Name& name) {
    for (const auto& label : name.labels()) {
        out.push_back(std::byte(label.size()));
        for (char value : label) {
            auto c = static_cast<unsigned char>(value);
            if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + 32);
            out.push_back(std::byte(c));
        }
    }
    out.push_back(std::byte{0});
}
bool within(const Name& child, const Name& parent) {
    if (parent.labels().size() > child.labels().size()) return false;
    auto suffix = Name::from_labels({child.labels().end() - static_cast<std::ptrdiff_t>(parent.labels().size()), child.labels().end()});
    return suffix && *suffix == parent;
}
struct Reader {
    std::span<const std::byte> data;
    std::size_t pos = 0;
    std::uint8_t u8() { return std::to_integer<std::uint8_t>(data[pos++]); }
    std::uint16_t u16() { const auto high = u8(); return static_cast<std::uint16_t>((high << 8) | u8()); }
    std::uint32_t u32() { const auto high = u16(); return (std::uint32_t{high} << 16) | u16(); }
    Result<Name> name() {
        std::vector<std::string> labels;
        std::size_t length = 1;
        for (;;) {
            if (pos == data.size()) return fail(DnsError::bad_rdata);
            const auto size = u8();
            if (!size) return Name::from_labels(std::move(labels));
            if (size > 63 || size > data.size() - pos || length + size + 1 > 255) return fail(DnsError::bad_rdata);
            labels.emplace_back(reinterpret_cast<const char*>(data.data() + pos), size);
            pos += size; length += size + 1;
        }
    }
};
Bytes key_wire(const Dnskey& key) {
    Bytes out;
    u16(out, key.flags); out.push_back(std::byte(key.protocol)); out.push_back(std::byte(key.algorithm));
    out.insert(out.end(), key.public_key.begin(), key.public_key.end());
    return out;
}
bool supported_key(const Dnskey& key) {
    return key.protocol == 3 && (key.flags & 0x100U) && !(key.flags & 0x80U) &&
        ((key.algorithm == 13 && key.public_key.size() == 64) || (key.algorithm == 15 && key.public_key.size() == 32));
}
Result<Bytes> canonical_rdata(const Record& record) {
    Bytes out;
    switch (record.type) {
    case type::a:
        if (const auto* a = std::get_if<AData>(&record.data)) { for (auto b : a->address) out.push_back(std::byte{b}); return out; }
        break;
    case type::aaaa:
        if (const auto* a = std::get_if<AaaaData>(&record.data)) { for (auto b : a->address) out.push_back(std::byte{b}); return out; }
        break;
    case type::ns: case type::cname: case type::ptr:
        if (const auto* n = std::get_if<NameData>(&record.data)) { name_wire(out, n->name); return out; }
        break;
    case type::mx:
        if (const auto* m = std::get_if<MxData>(&record.data)) { u16(out, m->preference); name_wire(out, m->exchange); return out; }
        break;
    case type::soa:
        if (const auto* s = std::get_if<SoaData>(&record.data)) {
            name_wire(out, s->mname); name_wire(out, s->rname);
            for (const auto v : {s->serial, s->refresh, s->retry, s->expire, s->minimum}) u32(out, v);
            return out;
        }
        break;
    case type::txt:
        if (const auto* t = std::get_if<TxtData>(&record.data)) {
            for (const auto& part : t->strings) {
                if (part.size() > 255) return fail(DnsError::bad_rdata);
                out.push_back(std::byte(part.size()));
                const auto bytes = std::as_bytes(std::span{part.data(), part.size()});
                out.insert(out.end(), bytes.begin(), bytes.end());
            }
            return out;
        }
        break;
    case dnskey_type: case ds_type:
        if (const auto* raw = std::get_if<RawData>(&record.data)) return raw->bytes;
        break;
    default: return fail(Errc::not_supported);
    }
    return fail(DnsError::bad_rdata);
}
Result<void> valid_anchors(std::span<const TrustAnchor> anchors, const ValidationOptions& options) {
    if (anchors.empty() || anchors.size() > options.max_records) return fail(Errc::invalid_argument);
    for (const auto& anchor : anchors)
        if (anchor.valid_from >= anchor.valid_until || anchor.ds.digest_type != 2 || anchor.ds.digest.size() != 32 ||
            (anchor.ds.algorithm != 13 && anchor.ds.algorithm != 15)) return fail(Errc::invalid_argument);
    return {};
}
Result<std::uint32_t> remaining(const Rrsig& sig, std::uint64_t now) {
    const auto span = static_cast<std::uint32_t>(sig.expiration - sig.inception);
    const auto elapsed = static_cast<std::uint32_t>(static_cast<std::uint32_t>(now) - sig.inception);
    if (!span || span >= 0x80000000U || elapsed >= span) return fail(denied());
    return span - elapsed;
}

struct Validation {
    const std::vector<TrustAnchor>& anchors;
    const ValidationOptions& options;
    std::uint64_t now;
    std::vector<Record> records;
    std::size_t signature_checks = 0;
    std::size_t zone_checks = 0;
    struct Keys { Name zone; std::vector<Record> keys; std::uint32_t ttl; };
    std::vector<Keys> authenticated;

    std::vector<Record> rrset(const Name& owner, std::uint16_t type_value) const {
        std::vector<Record> out;
        for (const auto& record : records)
            if (record.name == owner && record.type == type_value && record.klass == class_in &&
                std::find(out.begin(), out.end(), record) == out.end()) out.push_back(record);
        return out;
    }
    std::vector<std::pair<Rrsig, std::uint32_t>> signatures(const Name& owner, std::uint16_t type_value) const {
        std::vector<std::pair<Rrsig, std::uint32_t>> out;
        for (const auto& record : records) {
            if (record.name != owner || record.type != rrsig_type || record.klass != class_in) continue;
            auto signature = parse_rrsig(record);
            if (signature && signature->type_covered == type_value) out.emplace_back(std::move(*signature), record.ttl);
        }
        return out;
    }
    Result<std::uint32_t> verify(std::span<const Record> set, const Rrsig& signature,
        std::uint32_t signature_ttl, std::span<const Record> keys) {
        if (set.empty()) return fail(denied());
        auto ttl = remaining(signature, now);
        if (!ttl) return ttl;
        if (!within(set.front().name, signature.signer)) return fail(denied());
        auto data = signed_data(set, signature, options.max_bytes);
        if (!data) return fail(data.error());
        bool supported = false;
        for (const auto& record : keys) {
            auto key = parse_dnskey(record);
            if (!key || !supported_key(*key) || record.name != signature.signer ||
                key->algorithm != signature.algorithm || key_tag(*key) != signature.key_tag) continue;
            supported = true;
            if (++signature_checks > options.max_signature_checks) return fail(Errc::limit_exceeded);
            const auto algorithm = key->algorithm == 13 ? crypto::SignatureAlgorithm::ecdsa_p256_sha256 : crypto::SignatureAlgorithm::ed25519;
            auto valid = crypto::verify_signature(algorithm, key->public_key, *data, signature.signature);
            if (!valid || !*valid) continue;
            auto result = std::min({*ttl, signature.original_ttl, signature_ttl});
            for (const auto& rr : set) result = std::min(result, rr.ttl);
            return result;
        }
        return fail(supported ? denied() : make_error_code(Errc::not_supported));
    }
    bool matches(const Record& record, const Ds& ds) const {
        auto key = parse_dnskey(record);
        if (!key || !supported_key(*key) || ds.digest_type != 2 || key->algorithm != ds.algorithm || key_tag(*key) != ds.key_tag) return false;
        auto calculated = make_ds(record.name, *key);
        return calculated && calculated->digest == ds.digest;
    }
    Result<Keys> zone_keys(const Name& zone, std::size_t depth) {
        if (depth > options.max_depth) return fail(Errc::limit_exceeded);
        for (const auto& cached : authenticated) if (cached.zone == zone) return cached;
        if (++zone_checks > options.max_signature_checks) return fail(Errc::limit_exceeded);
        auto keys = rrset(zone, dnskey_type);
        if (keys.empty()) return fail(denied());
        std::vector<Record> trusted;
        std::uint32_t trust_ttl = UINT32_MAX;
        bool configured = false;
        for (const auto& anchor : anchors) {
            if (anchor.zone != zone) continue;
            configured = true;
            if (now < anchor.valid_from || now >= anchor.valid_until) continue;
            for (const auto& key : keys) if (matches(key, anchor.ds)) {
                trusted.push_back(key);
                trust_ttl = std::min(trust_ttl, static_cast<std::uint32_t>(std::min<std::uint64_t>(UINT32_MAX, anchor.valid_until - now)));
            }
        }
        if (!configured) {
            auto delegation = rrset(zone, ds_type);
            if (delegation.empty()) return fail(denied());
            bool validated = false;
            for (const auto& [signature, ttl] : signatures(zone, ds_type)) {
                if (signature.signer == zone || !within(zone, signature.signer)) continue;
                auto parent = zone_keys(signature.signer, depth + 1);
                if (!parent) {
                    if (parent.error() == Errc::limit_exceeded) return fail(parent.error());
                    continue;
                }
                auto valid = verify(delegation, signature, ttl, parent->keys);
                if (!valid) {
                    if (valid.error() == Errc::limit_exceeded) return fail(valid.error());
                    continue;
                }
                trust_ttl = std::min(*valid, parent->ttl);
                validated = true;
                break;
            }
            if (!validated) return fail(denied());
            for (const auto& record : delegation) {
                auto ds = parse_ds(record);
                if (ds) for (const auto& key : keys) if (matches(key, *ds)) trusted.push_back(key);
            }
        }
        if (trusted.empty()) return fail(denied());
        for (const auto& [signature, ttl] : signatures(zone, dnskey_type)) {
            if (signature.signer != zone) continue;
            auto valid = verify(keys, signature, ttl, trusted);
            if (!valid) {
                if (valid.error() == Errc::limit_exceeded) return fail(valid.error());
                continue;
            }
            Keys result{zone, std::move(keys), std::min(trust_ttl, *valid)};
            authenticated.push_back(result);
            return result;
        }
        return fail(denied());
    }
};

Result<void> record_budget(std::span<const Record> records, const ValidationOptions& options, std::size_t& count, std::size_t& bytes) {
    if (records.size() > options.max_records - std::min(count, options.max_records)) return fail(Errc::limit_exceeded);
    const auto charge = [&](std::size_t size) {
        if (size > options.max_bytes - std::min(bytes, options.max_bytes)) return false;
        bytes += size;
        return true;
    };
    for (const auto& record : records) {
        if (!charge(record.name.wire_size() + 10)) return fail(Errc::limit_exceeded);
        const bool fits = std::visit([&](const auto& data) {
            using T = std::decay_t<decltype(data)>;
            if constexpr (std::same_as<T, RawData>) return data.bytes.size() <= 65535 && charge(data.bytes.size());
            else if constexpr (std::same_as<T, AData>) return charge(4);
            else if constexpr (std::same_as<T, AaaaData>) return charge(16);
            else if constexpr (std::same_as<T, NameData>) return charge(data.name.wire_size());
            else if constexpr (std::same_as<T, MxData>) return charge(data.exchange.wire_size() + 2);
            else if constexpr (std::same_as<T, SoaData>) return charge(data.mname.wire_size() + data.rname.wire_size() + 20);
            else {
                for (const auto& part : data.strings) if (part.size() > 255 || !charge(part.size() + 1)) return false;
                return true;
            }
        }, record.data);
        if (!fits) return fail(Errc::limit_exceeded);
    }
    count += records.size();
    return {};
}
Result<void> message_budget(const Message& message, const ValidationOptions& options, std::size_t& count, std::size_t& bytes) {
    if (message.questions.size() != 1) return fail(DnsError::mismatched_response);
    const auto overhead = 12 + message.questions.front().name.wire_size() + 4;
    if (overhead > options.max_bytes - std::min(bytes, options.max_bytes)) return fail(Errc::limit_exceeded);
    bytes += overhead;
    if (message.edns) {
        for (const auto& option : message.edns->options) {
            if (option.data.size() > 65535 || option.data.size() + 4 > options.max_bytes - std::min(bytes, options.max_bytes))
                return fail(Errc::limit_exceeded);
            bytes += option.data.size() + 4;
        }
    }
    if (auto result = record_budget(message.answers, options, count, bytes); !result) return result;
    if (auto result = record_budget(message.authorities, options, count, bytes); !result) return result;
    return record_budget(message.additionals, options, count, bytes);
}
Result<void> append_records(std::vector<Record>& out, const Message& response, const ValidationOptions& options) {
    std::size_t count = 0, bytes = 0;
    if (auto result = record_budget(out, options, count, bytes); !result) return result;
    if (auto result = message_budget(response, options, count, bytes); !result) return result;
    out.insert(out.end(), response.answers.begin(), response.answers.end());
    out.insert(out.end(), response.authorities.begin(), response.authorities.end());
    out.insert(out.end(), response.additionals.begin(), response.additionals.end());
    return {};
}

}  // namespace

Result<Dnskey> parse_dnskey(const Record& record) {
    const auto* raw = std::get_if<RawData>(&record.data);
    if (record.type != dnskey_type || record.klass != class_in || !raw || raw->bytes.size() < 4 || raw->bytes.size() > 65535)
        return fail(DnsError::bad_rdata);
    Reader reader{raw->bytes};
    Dnskey key;
    key.flags = reader.u16(); key.protocol = reader.u8(); key.algorithm = reader.u8();
    key.public_key.assign(raw->bytes.begin() + 4, raw->bytes.end());
    return key;
}
Result<Ds> parse_ds(const Record& record) {
    const auto* raw = std::get_if<RawData>(&record.data);
    if (record.type != ds_type || record.klass != class_in || !raw || raw->bytes.size() < 4 || raw->bytes.size() > 65535)
        return fail(DnsError::bad_rdata);
    Reader reader{raw->bytes};
    Ds ds;
    ds.key_tag = reader.u16(); ds.algorithm = reader.u8(); ds.digest_type = reader.u8();
    ds.digest.assign(raw->bytes.begin() + 4, raw->bytes.end());
    return ds;
}
Result<Rrsig> parse_rrsig(const Record& record) {
    const auto* raw = std::get_if<RawData>(&record.data);
    if (record.type != rrsig_type || record.klass != class_in || !raw || raw->bytes.size() < 19 || raw->bytes.size() > 65535)
        return fail(DnsError::bad_rdata);
    Reader reader{raw->bytes};
    Rrsig signature;
    signature.type_covered = reader.u16(); signature.algorithm = reader.u8(); signature.labels = reader.u8();
    signature.original_ttl = reader.u32(); signature.expiration = reader.u32(); signature.inception = reader.u32();
    signature.key_tag = reader.u16();
    auto signer = reader.name();
    if (!signer) return fail(signer.error());
    signature.signer = std::move(*signer);
    signature.signature.assign(raw->bytes.begin() + static_cast<std::ptrdiff_t>(reader.pos), raw->bytes.end());
    if (signature.signature.empty()) return fail(DnsError::bad_rdata);
    return signature;
}
std::uint16_t key_tag(const Dnskey& key) {
    const auto wire = key_wire(key);
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < wire.size(); ++i) sum += std::to_integer<std::uint32_t>(wire[i]) << (i % 2 == 0 ? 8 : 0);
    sum += sum >> 16;
    return static_cast<std::uint16_t>(sum);
}
Result<Ds> make_ds(const Name& owner, const Dnskey& key) {
    if (!supported_key(key)) return fail(Errc::not_supported);
    Bytes wire; name_wire(wire, owner);
    const auto key_bytes = key_wire(key);
    wire.insert(wire.end(), key_bytes.begin(), key_bytes.end());
    auto digest = crypto::sha256(wire);
    if (!digest) return fail(digest.error());
    return Ds{key_tag(key), key.algorithm, 2, {digest->begin(), digest->end()}};
}
Result<Bytes> signed_data(std::span<const Record> rrset, const Rrsig& signature, std::size_t max_bytes) {
    if (rrset.empty() || max_bytes < 19 || max_bytes > 64 * 1024 * 1024) return fail(Errc::invalid_argument);
    ValidationOptions limits; limits.max_bytes = max_bytes; limits.max_records = 65536;
    std::size_t count = 0, bytes = 0;
    if (auto budget = record_budget(rrset, limits, count, bytes); !budget) return fail(budget.error());
    const auto& owner = rrset.front().name;
    if (signature.labels != owner.labels().size()) return fail(Errc::not_supported);
    Bytes out;
    u16(out, signature.type_covered); out.push_back(std::byte(signature.algorithm)); out.push_back(std::byte(signature.labels));
    u32(out, signature.original_ttl); u32(out, signature.expiration); u32(out, signature.inception); u16(out, signature.key_tag);
    name_wire(out, signature.signer);
    std::vector<Bytes> sorted;
    std::size_t total = out.size();
    for (const auto& record : rrset) {
        if (record.name != owner || record.type != signature.type_covered || record.klass != class_in) return fail(Errc::invalid_argument);
        auto rdata = canonical_rdata(record);
        if (!rdata) return fail(rdata.error());
        if (rdata->size() > 65535) return fail(DnsError::bad_rdata);
        const auto record_bytes = owner.wire_size() + 10 + rdata->size();
        if (record_bytes > max_bytes || total > max_bytes - record_bytes) return fail(Errc::limit_exceeded);
        total += record_bytes;
        sorted.push_back(std::move(*rdata));
    }
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());
    for (const auto& rdata : sorted) {
        name_wire(out, owner); u16(out, signature.type_covered); u16(out, class_in); u32(out, signature.original_ttl);
        u16(out, static_cast<std::uint16_t>(rdata.size())); out.insert(out.end(), rdata.begin(), rdata.end());
    }
    return out;
}
Result<Validator> Validator::create(std::vector<TrustAnchor> anchors, ValidationOptions options) {
    if (!options.max_records || options.max_records > 65536 || options.max_bytes < 512 || options.max_bytes > 64 * 1024 * 1024 ||
        !options.max_depth || options.max_depth > 128 || !options.max_signature_checks || options.max_signature_checks > 65536 ||
        !options.max_queries || options.max_queries > 1024 || options.timeout <= Clock::duration::zero() || options.timeout > std::chrono::hours(24))
        return fail(Errc::invalid_argument);
    if (auto valid = valid_anchors(anchors, options); !valid) return fail(valid.error());
    return Validator{std::move(anchors), options};
}
Result<void> Validator::replace_anchors(std::vector<TrustAnchor> anchors) {
    if (auto valid = valid_anchors(anchors, options_); !valid) return valid;
    anchors_ = std::move(anchors);
    return {};
}
Result<VerifiedAnswer> Validator::validate(const Message& response, const Question& question,
    std::span<const Record> evidence, std::uint64_t unix_seconds) const {
    if (!response.header.qr || response.header.opcode || response.header.tc || response.questions.size() != 1 ||
        response.questions.front() != question || question.klass != class_in) return fail(DnsError::mismatched_response);
    if (response.header.rcode != rcode::noerror) return fail(Errc::not_supported);
    if (evidence.size() > options_.max_records) return fail(Errc::limit_exceeded);
    std::size_t count = 0, bytes = 0;
    if (auto result = record_budget(evidence, options_, count, bytes); !result) return fail(result.error());
    if (auto result = message_budget(response, options_, count, bytes); !result) return fail(result.error());
    Validation validation{anchors_, options_, unix_seconds, {}, 0, 0, {}};
    validation.records.assign(evidence.begin(), evidence.end());
    if (auto result = append_records(validation.records, response, options_); !result) return fail(result.error());
    std::vector<Record> answer;
    for (const auto& record : response.answers)
        if (record.name == question.name && record.type == question.type && record.klass == question.klass) answer.push_back(record);
    if (answer.empty()) return fail(Errc::not_supported);
    bool unsupported = false;
    for (const auto& [signature, ttl] : validation.signatures(question.name, question.type)) {
        auto keys = validation.zone_keys(signature.signer, 0);
        if (!keys) {
            if (keys.error() == Errc::limit_exceeded) return fail(keys.error());
            continue;
        }
        auto verified = validation.verify(answer, signature, ttl, keys->keys);
        if (!verified) {
            if (verified.error() == Errc::limit_exceeded) return fail(verified.error());
            if (verified.error() == Errc::not_supported) unsupported = true;
            continue;
        }
        const auto valid_ttl = std::min(keys->ttl, *verified);
        for (auto& record : answer) record.ttl = std::min(record.ttl, valid_ttl);
        return VerifiedAnswer{std::move(answer), valid_ttl};
    }
    return fail(unsupported ? make_error_code(Errc::not_supported) : denied());
}
Task<Result<VerifiedAnswer>> Validator::query(Exchange exchange, Question question,
    std::uint64_t unix_seconds, OperationOptions io) const {
    return query_impl(*this, std::move(exchange), std::move(question), unix_seconds, std::move(io));
}
Task<Result<VerifiedAnswer>> Validator::query_impl(Validator snapshot, Exchange exchange, Question question,
    std::uint64_t unix_seconds, OperationOptions io) {
    // 非协程外层在调用时就复制配置，不把 this 留给延后启动的任务。
    if (!exchange || question.klass != class_in) co_return fail(Errc::invalid_argument);
    if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
    const auto started = Clock::now();
    if (io.deadline && *io.deadline <= started) co_return fail(Errc::timed_out);
    const auto deadline = started + snapshot.options_.timeout;
    if (!io.deadline || deadline < *io.deadline) io.deadline = deadline;
    std::size_t queries = 0, bytes = 0, records = 0;
    const auto fetch = [&](const Question& q) -> Task<Result<Message>> {
        if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (Clock::now() >= *io.deadline) co_return fail(Errc::timed_out);
        if (++queries > snapshot.options_.max_queries) co_return fail(Errc::limit_exceeded);
        auto request = make_query(q.name, q.type, {.dnssec_ok = true});
        if (!request) co_return fail(request.error());
        request->header.cd = true;
        const auto response = co_await exchange(std::move(*request), io);
        if (!response) co_return fail(response.error());
        if (io.stop.stop_requested()) co_return fail(Errc::cancelled);
        if (Clock::now() >= *io.deadline) co_return fail(Errc::timed_out);
        if (!response->header.qr || response->header.tc || response->header.opcode || response->questions.size() != 1 ||
            response->questions.front() != q) co_return fail(DnsError::mismatched_response);
        if (auto bounded = message_budget(*response, snapshot.options_, records, bytes); !bounded) co_return fail(bounded.error());
        co_return *response;
    };
    auto response = co_await fetch(question);
    if (!response) co_return fail(response.error());
    if (response->header.rcode != rcode::noerror) co_return fail(Errc::not_supported);
    std::vector<Record> evidence;
    std::vector<Name> zones;
    for (const auto& record : response->answers) {
        if (record.name != question.name || record.type != rrsig_type) continue;
        auto signature = parse_rrsig(record);
        if (signature && signature->type_covered == question.type) zones.push_back(signature->signer);
    }
    std::vector<Name> visited;
    for (std::size_t at = 0; at < zones.size(); ++at) {
        const auto zone = zones[at];
        if (std::find(visited.begin(), visited.end(), zone) != visited.end()) continue;
        if (visited.size() >= snapshot.options_.max_depth) co_return fail(Errc::limit_exceeded);
        visited.push_back(zone);
        auto keys = co_await fetch(Question{zone, dnskey_type, class_in});
        if (!keys) co_return fail(keys.error());
        if (auto r = append_records(evidence, *keys, snapshot.options_); !r) co_return fail(r.error());
        if (std::any_of(snapshot.anchors_.begin(), snapshot.anchors_.end(), [&](const auto& anchor) { return anchor.zone == zone; })) continue;
        auto ds = co_await fetch(Question{zone, ds_type, class_in});
        if (!ds) co_return fail(ds.error());
        if (auto r = append_records(evidence, *ds, snapshot.options_); !r) co_return fail(r.error());
        for (const auto& record : ds->answers) {
            auto signature = parse_rrsig(record);
            if (signature && signature->type_covered == ds_type && signature->signer != zone && within(zone, signature->signer))
                zones.push_back(signature->signer);
        }
    }
    const auto elapsed = std::chrono::ceil<std::chrono::seconds>(Clock::now() - started).count();
    if (elapsed < 0 || static_cast<std::uint64_t>(elapsed) > UINT64_MAX - unix_seconds) co_return fail(Errc::invalid_argument);
    co_return snapshot.validate(*response, question, evidence, unix_seconds + static_cast<std::uint64_t>(elapsed));
}

}  // namespace Mira::dns::dnssec
