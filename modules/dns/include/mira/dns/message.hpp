#pragma once

// Mira/dns/message.hpp — DNS message wire codec (RFC 1035, EDNS(0) RFC 6891).
//
// Decoding treats every byte as hostile: compression pointers must point
// strictly backwards past the header (so no loop can form), names stay within
// 255 wire bytes, record counts are checked against both a limit and the bytes
// that could possibly hold them before anything is allocated, fixed-size
// RDATA lengths are enforced, and trailing bytes are an error.
//
// Encoding never compresses names; that trades a few bytes for a codec whose
// output is trivially checkable. Unknown record types round-trip as raw RDATA.

#include "mira/core/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>
#include <vector>

namespace Mira::dns {

enum class DnsError {
    truncated = 1,
    bad_pointer,
    name_too_long,
    label_too_long,
    bad_label,
    too_many_records,
    bad_rdata,
    trailing_data,
    bad_opt,
    bad_name,
    too_large,
    /// DoH: invalid base64url.
    bad_base64,
    /// DoH: wrong or missing application/dns-message.
    bad_media_type,
    /// DoH: non-2xx HTTP status.
    bad_status,
    /// DoH: malformed request (missing/duplicate dns parameter...).
    bad_request,
    /// DoH: method other than GET/POST.
    bad_method,
    /// A response that does not answer the query (id, opcode or question).
    mismatched_response,
};

[[nodiscard]] const std::error_category& dns_category() noexcept;
[[nodiscard]] std::error_code make_error_code(DnsError error) noexcept;

namespace type {
inline constexpr std::uint16_t a = 1, ns = 2, cname = 5, soa = 6, ptr = 12, mx = 15, txt = 16,
                               aaaa = 28, opt = 41, svcb = 64, https = 65, any = 255;
}
namespace rcode {
inline constexpr std::uint16_t noerror = 0, formerr = 1, servfail = 2, nxdomain = 3, notimp = 4,
                               refused = 5, badvers = 16;
}
inline constexpr std::uint16_t class_in = 1;

/// Domain name as labels. Labels may hold any bytes; comparison is ASCII
/// case-insensitive (RFC 4343).
class Name {
public:
    Name() = default;
    /// Dotted text with master-file escapes (`\.`, `\\`, `\DDD`); a trailing
    /// dot is optional; "." is the root. Labels 1..63 bytes, wire form <= 255.
    [[nodiscard]] static Result<Name> parse(std::string_view dotted);
    [[nodiscard]] static Result<Name> from_labels(std::vector<std::string> labels);
    [[nodiscard]] const std::vector<std::string>& labels() const noexcept { return labels_; }
    [[nodiscard]] bool is_root() const noexcept { return labels_.empty(); }
    [[nodiscard]] std::size_t wire_size() const noexcept;
    /// Escaped dotted form without trailing dot; "." for the root.
    [[nodiscard]] std::string to_string() const;
    friend bool operator==(const Name& left, const Name& right) noexcept;

private:
    std::vector<std::string> labels_;
};

struct Question {
    Name name;
    std::uint16_t type = type::a;
    std::uint16_t klass = class_in;
    friend bool operator==(const Question&, const Question&) = default;
};

struct RawData {
    std::vector<std::byte> bytes;
    friend bool operator==(const RawData&, const RawData&) = default;
};
struct AData {
    std::array<std::uint8_t, 4> address{};
    friend bool operator==(const AData&, const AData&) = default;
};
struct AaaaData {
    std::array<std::uint8_t, 16> address{};
    friend bool operator==(const AaaaData&, const AaaaData&) = default;
};
/// CNAME, NS and PTR.
struct NameData {
    Name name;
    friend bool operator==(const NameData&, const NameData&) = default;
};
struct MxData {
    std::uint16_t preference = 0;
    Name exchange;
    friend bool operator==(const MxData&, const MxData&) = default;
};
struct TxtData {
    std::vector<std::string> strings;
    friend bool operator==(const TxtData&, const TxtData&) = default;
};
struct SoaData {
    Name mname, rname;
    std::uint32_t serial = 0, refresh = 0, retry = 0, expire = 0, minimum = 0;
    friend bool operator==(const SoaData&, const SoaData&) = default;
};
using Rdata = std::variant<RawData, AData, AaaaData, NameData, MxData, TxtData, SoaData>;

struct Record {
    Name name;
    std::uint16_t type = type::a;
    std::uint16_t klass = class_in;
    std::uint32_t ttl = 0;
    Rdata data;
    friend bool operator==(const Record&, const Record&) = default;
};

struct EdnsOption {
    std::uint16_t code = 0;
    std::vector<std::byte> data;
    friend bool operator==(const EdnsOption&, const EdnsOption&) = default;
};

struct Edns {
    std::uint16_t udp_payload_size = 1232;
    std::uint8_t version = 0;
    bool dnssec_ok = false;
    std::vector<EdnsOption> options;
    friend bool operator==(const Edns&, const Edns&) = default;
};

struct Header {
    std::uint16_t id = 0;
    bool qr = false;
    std::uint8_t opcode = 0;
    bool aa = false, tc = false, rd = true, ra = false, ad = false, cd = false;
    /// Full 12-bit RCODE; values above 15 require EDNS.
    std::uint16_t rcode = 0;
    friend bool operator==(const Header&, const Header&) = default;
};

struct Message {
    Header header;
    std::vector<Question> questions;
    std::vector<Record> answers;
    std::vector<Record> authorities;
    /// Excludes the OPT pseudo-record, which is decoded into `edns`.
    std::vector<Record> additionals;
    std::optional<Edns> edns;
    friend bool operator==(const Message&, const Message&) = default;
};

struct Limits {
    std::size_t max_message_size = 65535;
    /// Across all four sections.
    std::size_t max_records = 512;
    std::size_t max_pointer_hops = 32;
    std::size_t max_edns_options = 32;
};

struct QueryOptions {
    /// RFC 8484 §4.1 recommends 0 for DoH so responses cache well.
    std::uint16_t id = 0;
    bool recursion_desired = true;
    /// 0 omits EDNS(0).
    std::uint16_t udp_payload_size = 1232;
    bool dnssec_ok = false;
    /// EDNS padding (RFC 7830) to a multiple of this size (RFC 8467 suggests
    /// 128 for queries); 0 disables. Requires EDNS.
    std::size_t pad_to_block = 0;
};

[[nodiscard]] Result<std::vector<std::byte>> encode(const Message& message);
[[nodiscard]] Result<Message> decode(std::span<const std::byte> wire, const Limits& limits = {});
[[nodiscard]] Result<Message> make_query(const Name& name, std::uint16_t type,
                                         const QueryOptions& options = {});
[[nodiscard]] Result<std::vector<std::byte>> encode_query(const Name& name, std::uint16_t type,
                                                          const QueryOptions& options = {});
/// QR set, same id and opcode, identical question section (case-insensitive).
[[nodiscard]] bool answers(const Message& query, const Message& response) noexcept;
/// Smallest TTL over answer/authority records (the SOA minimum bounds a
/// negative answer); nullopt when there are none. For DoH Cache-Control.
[[nodiscard]] std::optional<std::uint32_t> min_ttl(const Message& message) noexcept;

}  // namespace Mira::dns

namespace std {
template<>
struct is_error_code_enum<Mira::dns::DnsError> : true_type {};
}  // namespace std
