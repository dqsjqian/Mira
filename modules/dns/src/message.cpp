#include "mira/dns/message.hpp"

#include <algorithm>
#include <limits>

namespace Mira::dns {

namespace {

class Category final : public std::error_category {
public:
    const char* name() const noexcept override { return "Mira.dns"; }
    std::string message(int value) const override {
        switch (static_cast<DnsError>(value)) {
        case DnsError::truncated: return "truncated DNS message";
        case DnsError::bad_pointer: return "invalid DNS compression pointer";
        case DnsError::name_too_long: return "DNS name exceeds 255 bytes";
        case DnsError::label_too_long: return "DNS label exceeds 63 bytes";
        case DnsError::bad_label: return "reserved DNS label type";
        case DnsError::too_many_records: return "too many DNS records";
        case DnsError::bad_rdata: return "malformed DNS RDATA";
        case DnsError::trailing_data: return "trailing bytes after DNS message";
        case DnsError::bad_opt: return "malformed EDNS OPT record";
        case DnsError::bad_name: return "malformed DNS name text";
        case DnsError::too_large: return "DNS message too large";
        case DnsError::bad_base64: return "invalid base64url";
        case DnsError::bad_media_type: return "not application/dns-message";
        case DnsError::bad_status: return "DoH server returned a non-2xx status";
        case DnsError::bad_request: return "malformed DoH request";
        case DnsError::bad_method: return "DoH requires GET or POST";
        case DnsError::mismatched_response: return "DNS response does not answer the query";
        }
        return "unknown DNS error";
    }
};

bool ascii_equal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        auto x = static_cast<unsigned char>(a[i]);
        auto y = static_cast<unsigned char>(b[i]);
        if (x >= 'A' && x <= 'Z') x = static_cast<unsigned char>(x + 32);
        if (y >= 'A' && y <= 'Z') y = static_cast<unsigned char>(y + 32);
        if (x != y) return false;
    }
    return true;
}

struct Reader {
    std::span<const std::byte> wire;
    const Limits& limits;
    std::size_t pos = 0;

    std::size_t left() const noexcept { return wire.size() - pos; }
    std::uint8_t byte_at(std::size_t at) const noexcept { return std::to_integer<std::uint8_t>(wire[at]); }
    Result<std::uint8_t> u8() {
        if (left() < 1) return fail(DnsError::truncated);
        return byte_at(pos++);
    }
    Result<std::uint16_t> u16() {
        if (left() < 2) return fail(DnsError::truncated);
        const auto value = static_cast<std::uint16_t>((byte_at(pos) << 8) | byte_at(pos + 1));
        pos += 2;
        return value;
    }
    Result<std::uint32_t> u32() {
        if (left() < 4) return fail(DnsError::truncated);
        const auto value = (std::uint32_t{byte_at(pos)} << 24) | (std::uint32_t{byte_at(pos + 1)} << 16) |
                           (std::uint32_t{byte_at(pos + 2)} << 8) | std::uint32_t{byte_at(pos + 3)};
        pos += 4;
        return value;
    }

    /// Decode a possibly compressed name at `pos`, not reading past `end`
    /// in the uncompressed part. Every pointer must target an offset
    /// strictly before the start of the segment containing it, and after the
    /// header, so the chain of segments strictly descends and terminates.
    Result<Name> name(std::size_t end) {
        std::vector<std::string> labels;
        std::size_t cursor = pos;
        std::size_t segment = pos;
        std::size_t resume = 0;
        bool jumped = false;
        std::size_t hops = 0;
        std::size_t length = 1;
        for (;;) {
            const std::size_t bound = jumped ? wire.size() : end;
            if (cursor >= bound) return fail(DnsError::truncated);
            const auto head = byte_at(cursor);
            const auto kind = head & 0xC0;
            if (kind == 0xC0) {
                if (cursor + 1 >= bound) return fail(DnsError::truncated);
                const std::size_t target = (std::size_t{head & 0x3Fu} << 8) | byte_at(cursor + 1);
                if (target < 12 || target >= segment || ++hops > limits.max_pointer_hops)
                    return fail(DnsError::bad_pointer);
                if (!jumped) resume = cursor + 2;
                jumped = true;
                cursor = segment = target;
                continue;
            }
            if (kind != 0) return fail(DnsError::bad_label);
            ++cursor;
            if (head == 0) break;
            if (cursor + head > bound) return fail(DnsError::truncated);
            length += std::size_t{head} + 1;
            if (length > 255) return fail(DnsError::name_too_long);
            labels.emplace_back(reinterpret_cast<const char*>(wire.data() + cursor), head);
            cursor += head;
        }
        pos = jumped ? resume : cursor;
        return Name::from_labels(std::move(labels));
    }
};

struct Writer {
    std::vector<std::byte> out;
    void u8(std::uint8_t value) { out.push_back(static_cast<std::byte>(value)); }
    void u16(std::uint16_t value) {
        u8(static_cast<std::uint8_t>(value >> 8));
        u8(static_cast<std::uint8_t>(value & 0xFF));
    }
    void u32(std::uint32_t value) {
        u16(static_cast<std::uint16_t>(value >> 16));
        u16(static_cast<std::uint16_t>(value & 0xFFFF));
    }
    void bytes(std::span<const std::byte> data) { out.insert(out.end(), data.begin(), data.end()); }
    void text(std::string_view data) { bytes(std::as_bytes(std::span{data.data(), data.size()})); }
    void name(const Name& value) {
        for (const auto& label : value.labels()) {
            u8(static_cast<std::uint8_t>(label.size()));
            text(label);
        }
        u8(0);
    }
};

Result<Rdata> decode_rdata(Reader& reader, std::uint16_t rtype, std::uint16_t klass, std::size_t size) {
    const std::size_t end = reader.pos + size;
    const auto finish = [&](Rdata value) -> Result<Rdata> {
        if (reader.pos != end) return fail(DnsError::bad_rdata);
        return value;
    };
    const auto name = [&]() -> Result<Name> {
        auto decoded = reader.name(end);
        if (!decoded && decoded.error() == make_error_code(DnsError::truncated))
            return fail(DnsError::bad_rdata);
        return decoded;
    };
    switch (rtype) {
    case type::a:
    case type::aaaa: {
        if (klass != class_in) break;
        const std::size_t width = rtype == type::a ? 4 : 16;
        if (size != width) return fail(DnsError::bad_rdata);
        if (rtype == type::a) {
            AData data;
            for (auto& octet : data.address) octet = reader.byte_at(reader.pos++);
            return finish(data);
        }
        AaaaData data;
        for (auto& octet : data.address) octet = reader.byte_at(reader.pos++);
        return finish(data);
    }
    case type::cname:
    case type::ns:
    case type::ptr: {
        auto target = name();
        if (!target) return fail(target.error());
        return finish(NameData{std::move(*target)});
    }
    case type::mx: {
        if (size < 3) return fail(DnsError::bad_rdata);
        auto preference = reader.u16();
        auto exchange = name();
        if (!exchange) return fail(exchange.error());
        return finish(MxData{*preference, std::move(*exchange)});
    }
    case type::txt: {
        if (size == 0) return fail(DnsError::bad_rdata);
        TxtData data;
        while (reader.pos < end) {
            const auto length = reader.byte_at(reader.pos++);
            if (reader.pos + length > end) return fail(DnsError::bad_rdata);
            data.strings.emplace_back(reinterpret_cast<const char*>(reader.wire.data() + reader.pos), length);
            reader.pos += length;
        }
        return finish(std::move(data));
    }
    case type::soa: {
        SoaData data;
        auto mname = name();
        if (!mname) return fail(mname.error());
        auto rname = name();
        if (!rname) return fail(rname.error());
        if (end - reader.pos != 20) return fail(DnsError::bad_rdata);
        data.mname = std::move(*mname);
        data.rname = std::move(*rname);
        data.serial = *reader.u32();
        data.refresh = *reader.u32();
        data.retry = *reader.u32();
        data.expire = *reader.u32();
        data.minimum = *reader.u32();
        return finish(std::move(data));
    }
    default: break;
    }
    RawData raw;
    raw.bytes.assign(reader.wire.begin() + static_cast<std::ptrdiff_t>(reader.pos),
                     reader.wire.begin() + static_cast<std::ptrdiff_t>(end));
    reader.pos = end;
    return raw;
}

Result<void> encode_rdata(Writer& writer, const Record& record) {
    const auto start = writer.out.size();
    writer.u16(0);  // RDLENGTH, patched below
    const auto matches = [&](std::initializer_list<std::uint16_t> types) {
        return std::find(types.begin(), types.end(), record.type) != types.end();
    };
    const bool ok = std::visit(
        [&](const auto& data) -> bool {
            using T = std::decay_t<decltype(data)>;
            if constexpr (std::is_same_v<T, RawData>) {
                writer.bytes(data.bytes);
                return true;
            } else if constexpr (std::is_same_v<T, AData>) {
                if (record.type != type::a) return false;
                for (const auto octet : data.address) writer.u8(octet);
                return true;
            } else if constexpr (std::is_same_v<T, AaaaData>) {
                if (record.type != type::aaaa) return false;
                for (const auto octet : data.address) writer.u8(octet);
                return true;
            } else if constexpr (std::is_same_v<T, NameData>) {
                if (!matches({type::cname, type::ns, type::ptr})) return false;
                writer.name(data.name);
                return true;
            } else if constexpr (std::is_same_v<T, MxData>) {
                if (record.type != type::mx) return false;
                writer.u16(data.preference);
                writer.name(data.exchange);
                return true;
            } else if constexpr (std::is_same_v<T, TxtData>) {
                if (record.type != type::txt || data.strings.empty()) return false;
                for (const auto& piece : data.strings) {
                    if (piece.size() > 255) return false;
                    writer.u8(static_cast<std::uint8_t>(piece.size()));
                    writer.text(piece);
                }
                return true;
            } else {
                if (record.type != type::soa) return false;
                writer.name(data.mname);
                writer.name(data.rname);
                for (const auto value : {data.serial, data.refresh, data.retry, data.expire, data.minimum})
                    writer.u32(value);
                return true;
            }
        },
        record.data);
    if (!ok) return fail(Errc::invalid_argument);
    const auto length = writer.out.size() - start - 2;
    if (length > 0xFFFF) return fail(DnsError::too_large);
    writer.out[start] = static_cast<std::byte>(length >> 8);
    writer.out[start + 1] = static_cast<std::byte>(length & 0xFF);
    return {};
}

std::size_t option_bytes(const Edns& edns) {
    std::size_t total = 0;
    for (const auto& option : edns.options) total += 4 + option.data.size();
    return total;
}

}  // namespace

const std::error_category& dns_category() noexcept {
    static const Category category;
    return category;
}

std::error_code make_error_code(DnsError error) noexcept {
    return {static_cast<int>(error), dns_category()};
}

Result<Name> Name::from_labels(std::vector<std::string> labels) {
    std::size_t length = 1;
    for (const auto& label : labels) {
        if (label.empty()) return fail(DnsError::bad_name);
        if (label.size() > 63) return fail(DnsError::label_too_long);
        length += label.size() + 1;
    }
    if (length > 255) return fail(DnsError::name_too_long);
    Name name;
    name.labels_ = std::move(labels);
    return name;
}

Result<Name> Name::parse(std::string_view text) {
    if (text == ".") return Name{};
    if (text.empty()) return fail(DnsError::bad_name);
    std::vector<std::string> labels;
    std::string label;
    bool pending = false;  // a label was started (possibly empty so far)
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '.') {
            if (label.empty()) return fail(DnsError::bad_name);
            labels.push_back(std::move(label));
            label.clear();
            pending = false;
            continue;
        }
        pending = true;
        if (c != '\\') {
            label.push_back(c);
            continue;
        }
        if (i + 1 >= text.size()) return fail(DnsError::bad_name);
        const char next = text[i + 1];
        if (next >= '0' && next <= '9') {
            if (i + 3 >= text.size()) return fail(DnsError::bad_name);
            unsigned value = 0;
            for (std::size_t k = 1; k <= 3; ++k) {
                const char digit = text[i + k];
                if (digit < '0' || digit > '9') return fail(DnsError::bad_name);
                value = value * 10 + static_cast<unsigned>(digit - '0');
            }
            if (value > 255) return fail(DnsError::bad_name);
            label.push_back(static_cast<char>(value));
            i += 3;
        } else {
            label.push_back(next);
            i += 1;
        }
    }
    if (pending) labels.push_back(std::move(label));
    return from_labels(std::move(labels));
}

std::size_t Name::wire_size() const noexcept {
    std::size_t size = 1;
    for (const auto& label : labels_) size += label.size() + 1;
    return size;
}

std::string Name::to_string() const {
    if (labels_.empty()) return ".";
    std::string text;
    for (std::size_t index = 0; index < labels_.size(); ++index) {
        if (index) text.push_back('.');
        for (const char c : labels_[index]) {
            const auto byte = static_cast<unsigned char>(c);
            if (c == '.' || c == '\\') {
                text.push_back('\\');
                text.push_back(c);
            } else if (byte < 0x21 || byte > 0x7E) {
                text.push_back('\\');
                text.push_back(static_cast<char>('0' + byte / 100));
                text.push_back(static_cast<char>('0' + byte / 10 % 10));
                text.push_back(static_cast<char>('0' + byte % 10));
            } else {
                text.push_back(c);
            }
        }
    }
    return text;
}

bool operator==(const Name& left, const Name& right) noexcept {
    if (left.labels_.size() != right.labels_.size()) return false;
    for (std::size_t i = 0; i < left.labels_.size(); ++i)
        if (!ascii_equal(left.labels_[i], right.labels_[i])) return false;
    return true;
}

Result<Message> decode(std::span<const std::byte> wire, const Limits& limits) {
    if (wire.size() > limits.max_message_size || wire.size() > 65535) return fail(DnsError::too_large);
    Reader reader{wire, limits};
    if (wire.size() < 12) return fail(DnsError::truncated);
    Message message;
    message.header.id = *reader.u16();
    const auto flags = *reader.u16();
    message.header.qr = (flags & 0x8000) != 0;
    message.header.opcode = static_cast<std::uint8_t>((flags >> 11) & 0x0F);
    message.header.aa = (flags & 0x0400) != 0;
    message.header.tc = (flags & 0x0200) != 0;
    message.header.rd = (flags & 0x0100) != 0;
    message.header.ra = (flags & 0x0080) != 0;
    message.header.ad = (flags & 0x0020) != 0;
    message.header.cd = (flags & 0x0010) != 0;
    message.header.rcode = static_cast<std::uint16_t>(flags & 0x000F);
    const std::size_t questions = *reader.u16();
    const std::size_t counts[3] = {*reader.u16(), *reader.u16(), *reader.u16()};
    const auto records = counts[0] + counts[1] + counts[2];
    if (questions + records > limits.max_records) return fail(DnsError::too_many_records);
    // Allocation is bounded by the bytes that could actually hold the records.
    if (questions * 5 + records * 11 > reader.left()) return fail(DnsError::truncated);

    message.questions.reserve(questions);
    for (std::size_t i = 0; i < questions; ++i) {
        auto name = reader.name(wire.size());
        if (!name) return fail(name.error());
        auto qtype = reader.u16();
        auto qclass = reader.u16();
        if (!qtype || !qclass) return fail(DnsError::truncated);
        message.questions.push_back({std::move(*name), *qtype, *qclass});
    }
    std::vector<Record>* sections[3] = {&message.answers, &message.authorities, &message.additionals};
    for (std::size_t section = 0; section < 3; ++section) {
        sections[section]->reserve(counts[section]);
        for (std::size_t i = 0; i < counts[section]; ++i) {
            auto name = reader.name(wire.size());
            if (!name) return fail(name.error());
            if (reader.left() < 10) return fail(DnsError::truncated);
            const auto rtype = *reader.u16();
            const auto klass = *reader.u16();
            const auto ttl = *reader.u32();
            const auto size = *reader.u16();
            if (size > reader.left()) return fail(DnsError::truncated);
            if (rtype == type::opt) {
                if (section != 2 || message.edns || !name->is_root()) return fail(DnsError::bad_opt);
                Edns edns;
                edns.udp_payload_size = klass;
                edns.version = static_cast<std::uint8_t>((ttl >> 16) & 0xFF);
                edns.dnssec_ok = (ttl & 0x8000) != 0;
                message.header.rcode = static_cast<std::uint16_t>(message.header.rcode | ((ttl >> 24) << 4));
                const std::size_t end = reader.pos + size;
                while (reader.pos < end) {
                    if (end - reader.pos < 4 || edns.options.size() >= limits.max_edns_options)
                        return fail(DnsError::bad_opt);
                    const auto code = *reader.u16();
                    const auto length = *reader.u16();
                    if (length > end - reader.pos) return fail(DnsError::bad_opt);
                    EdnsOption option{code, {}};
                    option.data.assign(wire.begin() + static_cast<std::ptrdiff_t>(reader.pos),
                                       wire.begin() + static_cast<std::ptrdiff_t>(reader.pos + length));
                    reader.pos += length;
                    edns.options.push_back(std::move(option));
                }
                message.edns = std::move(edns);
                continue;
            }
            auto data = decode_rdata(reader, rtype, klass, size);
            if (!data) return fail(data.error());
            sections[section]->push_back({std::move(*name), rtype, klass, ttl, std::move(*data)});
        }
    }
    if (reader.left() != 0) return fail(DnsError::trailing_data);
    return message;
}

Result<std::vector<std::byte>> encode(const Message& message) {
    const auto& header = message.header;
    if (header.opcode > 15 || header.rcode > 0xFFF || (header.rcode > 15 && !message.edns))
        return fail(Errc::invalid_argument);
    const auto additional = message.additionals.size() + (message.edns ? 1u : 0u);
    if (message.questions.size() > 0xFFFF || message.answers.size() > 0xFFFF ||
        message.authorities.size() > 0xFFFF || additional > 0xFFFF)
        return fail(DnsError::too_many_records);
    Writer writer;
    writer.u16(header.id);
    writer.u16(static_cast<std::uint16_t>((header.qr ? 0x8000 : 0) | (header.opcode << 11) |
                                          (header.aa ? 0x0400 : 0) | (header.tc ? 0x0200 : 0) |
                                          (header.rd ? 0x0100 : 0) | (header.ra ? 0x0080 : 0) |
                                          (header.ad ? 0x0020 : 0) | (header.cd ? 0x0010 : 0) |
                                          (header.rcode & 0x0F)));
    writer.u16(static_cast<std::uint16_t>(message.questions.size()));
    writer.u16(static_cast<std::uint16_t>(message.answers.size()));
    writer.u16(static_cast<std::uint16_t>(message.authorities.size()));
    writer.u16(static_cast<std::uint16_t>(additional));
    for (const auto& question : message.questions) {
        writer.name(question.name);
        writer.u16(question.type);
        writer.u16(question.klass);
    }
    for (const auto* section : {&message.answers, &message.authorities, &message.additionals}) {
        for (const auto& record : *section) {
            if (record.type == type::opt) return fail(DnsError::bad_opt);
            writer.name(record.name);
            writer.u16(record.type);
            writer.u16(record.klass);
            writer.u32(record.ttl);
            if (auto written = encode_rdata(writer, record); !written) return fail(written.error());
        }
    }
    if (message.edns) {
        const auto& edns = *message.edns;
        if (option_bytes(edns) > 0xFFFF) return fail(DnsError::too_large);
        writer.u8(0);
        writer.u16(type::opt);
        writer.u16(edns.udp_payload_size);
        writer.u32((static_cast<std::uint32_t>(header.rcode >> 4) << 24) |
                   (static_cast<std::uint32_t>(edns.version) << 16) | (edns.dnssec_ok ? 0x8000u : 0u));
        writer.u16(static_cast<std::uint16_t>(option_bytes(edns)));
        for (const auto& option : edns.options) {
            if (option.data.size() > 0xFFFF) return fail(DnsError::too_large);
            writer.u16(option.code);
            writer.u16(static_cast<std::uint16_t>(option.data.size()));
            writer.bytes(option.data);
        }
    }
    if (writer.out.size() > 65535) return fail(DnsError::too_large);
    return std::move(writer.out);
}

Result<Message> make_query(const Name& name, std::uint16_t qtype, const QueryOptions& options) {
    if (options.pad_to_block != 0 && options.udp_payload_size == 0) return fail(Errc::invalid_argument);
    if (options.pad_to_block > 4096) return fail(Errc::invalid_argument);
    Message query;
    query.header.id = options.id;
    query.header.rd = options.recursion_desired;
    query.questions.push_back({name, qtype, class_in});
    if (options.udp_payload_size != 0) {
        query.edns = Edns{};
        query.edns->udp_payload_size = std::max<std::uint16_t>(options.udp_payload_size, 512);
        query.edns->dnssec_ok = options.dnssec_ok;
        if (options.pad_to_block != 0) {
            auto unpadded = encode(query);
            if (!unpadded) return fail(unpadded.error());
            const auto base = unpadded->size() + 4;
            const auto padding = (options.pad_to_block - base % options.pad_to_block) % options.pad_to_block;
            query.edns->options.push_back({12, std::vector<std::byte>(padding)});
        }
    }
    return query;
}

Result<std::vector<std::byte>> encode_query(const Name& name, std::uint16_t qtype,
                                            const QueryOptions& options) {
    auto query = make_query(name, qtype, options);
    if (!query) return fail(query.error());
    return encode(*query);
}

bool answers(const Message& query, const Message& response) noexcept {
    return response.header.qr && response.header.id == query.header.id &&
           response.header.opcode == query.header.opcode && response.questions == query.questions;
}

std::optional<std::uint32_t> min_ttl(const Message& message) noexcept {
    std::optional<std::uint32_t> lowest;
    const auto consider = [&](std::uint32_t ttl) { lowest = lowest ? std::min(*lowest, ttl) : ttl; };
    for (const auto& record : message.answers) consider(record.ttl);
    for (const auto& record : message.authorities) {
        consider(record.ttl);
        if (const auto* soa = std::get_if<SoaData>(&record.data)) consider(soa->minimum);
    }
    return lowest;
}

}  // namespace Mira::dns
