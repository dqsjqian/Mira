#include "check.hpp"
#include "mira/dns/message.hpp"

#include <initializer_list>
#include <string>
#include <vector>

#define CHECK_VALUE(expr) CHECK(static_cast<bool>(expr))

using namespace Mira;
using namespace Mira::dns;

namespace {

std::vector<std::byte> wire(std::initializer_list<int> values) {
    std::vector<std::byte> out;
    for (const int v : values) out.push_back(static_cast<std::byte>(v));
    return out;
}
void append(std::vector<std::byte>& out, std::initializer_list<int> values) {
    for (const int v : values) out.push_back(static_cast<std::byte>(v));
}
void append_text(std::vector<std::byte>& out, std::string_view text) {
    for (const char c : text) out.push_back(static_cast<std::byte>(c));
}
bool fails_with(const Result<Message>& result, DnsError error) {
    return !result && result.error() == make_error_code(error);
}

/// www.example.com A response, hand-assembled with compression pointers.
std::vector<std::byte> captured() {
    auto out = wire({0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0});
    append(out, {3}); append_text(out, "www");        // offset 12
    append(out, {7}); append_text(out, "example");    // offset 16
    append(out, {3}); append_text(out, "com");        // offset 24
    append(out, {0, 0, 1, 0, 1});                     // offsets 28..32
    // Answer 1 at 33: www.example.com CNAME web.example.com
    append(out, {0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 1, 0x2C, 0, 6, 3});
    append_text(out, "web");                           // name at offset 45
    append(out, {0xC0, 0x10});
    // Answer 2: web.example.com A 93.184.216.34
    append(out, {0xC0, 0x2D, 0, 1, 0, 1, 0, 0, 0, 0x3C, 0, 4, 93, 184, 216, 34});
    return out;
}

void names() {
    test::section("names");
    const auto simple = Name::parse("Example.COM.");
    CHECK_VALUE(simple);
    CHECK(simple->labels().size() == 2);
    CHECK(*simple == *Name::parse("example.com"));
    CHECK(simple->to_string() == "Example.COM");
    CHECK(simple->wire_size() == 13);
    const auto root = Name::parse(".");
    CHECK(root && root->is_root() && root->to_string() == "." && root->wire_size() == 1);
    const auto escaped = Name::parse(R"(a\.b.c\\d.\000\255x)");
    CHECK_VALUE(escaped);
    if (escaped) {
        CHECK(escaped->labels()[0] == "a.b");
        CHECK(escaped->labels()[1] == "c\\d");
        CHECK(escaped->labels()[2] == std::string("\0\xFFx", 3));
        CHECK(escaped->to_string() == R"(a\.b.c\\d.\000\255x)");
        CHECK(*Name::parse(escaped->to_string()) == *escaped);
    }
    CHECK(Name::parse(std::string(63, 'a') + ".b").has_value());
    const auto long_label = Name::parse(std::string(64, 'a'));
    CHECK(!long_label && long_label.error() == make_error_code(DnsError::label_too_long));
    std::string max = std::string(63, 'a') + "." + std::string(63, 'b') + "." + std::string(63, 'c') +
                      "." + std::string(61, 'd');
    CHECK(Name::parse(max).has_value() && Name::parse(max)->wire_size() == 255);
    const auto too_long = Name::parse(max + "d");
    CHECK(!too_long && too_long.error() == make_error_code(DnsError::name_too_long));
    for (const std::string_view bad : {"", "..", "a..b", ".a", "a\\", "a\\25", "a\\256", "a\\2x5"})
        CHECK(!Name::parse(bad));
    CHECK(!(*Name::parse("a.b") == *Name::parse("a.c")));
}

void decode_captured() {
    test::section("decode hand-assembled response with compression");
    const auto bytes = captured();
    const auto message = decode(bytes);
    CHECK_VALUE(message);
    if (!message) return;
    CHECK(message->header.id == 0x1234 && message->header.qr && message->header.rd && message->header.ra);
    CHECK(!message->header.aa && message->header.rcode == rcode::noerror);
    CHECK(message->questions.size() == 1 && message->questions[0].name == *Name::parse("www.example.com"));
    CHECK(message->answers.size() == 2);
    CHECK(std::get<NameData>(message->answers[0].data).name == *Name::parse("web.example.com"));
    CHECK(message->answers[0].ttl == 300);
    CHECK(message->answers[1].name == *Name::parse("WEB.example.com"));
    CHECK((std::get<AData>(message->answers[1].data).address == std::array<std::uint8_t, 4>{93, 184, 216, 34}));
    CHECK(min_ttl(*message) == std::optional<std::uint32_t>{60});
    auto query = make_query(*Name::parse("WWW.Example.com"), type::a, {.id = 0x1234});
    CHECK(query && answers(*query, *message));
    query->header.id = 1;
    CHECK(!answers(*query, *message));
    // Re-encoding (uncompressed) decodes to the same message.
    const auto again = encode(*message);
    CHECK(again && decode(*again) == message);
}

void malformed() {
    test::section("hostile input");
    const auto base = captured();
    CHECK(fails_with(decode(std::span{base}.first(11)), DnsError::truncated));
    for (std::size_t cut = 12; cut < base.size(); ++cut) {
        const auto result = decode(std::span{base}.first(cut));
        CHECK(!result);
    }
    auto trailing = base;
    trailing.push_back(std::byte{0});
    CHECK(fails_with(decode(trailing), DnsError::trailing_data));

    const auto question = [](std::initializer_list<int> name) {
        auto out = wire({0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0});
        append(out, name);
        append(out, {0, 1, 0, 1});
        return out;
    };
    CHECK(fails_with(decode(question({0xC0, 0x0C})), DnsError::bad_pointer));  // self
    CHECK(fails_with(decode(question({0xC0, 0x05})), DnsError::bad_pointer));  // header
    CHECK(fails_with(decode(question({0xC0, 0x20})), DnsError::bad_pointer));  // forward
    CHECK(fails_with(decode(question({0x40, 0})), DnsError::bad_label));
    CHECK(fails_with(decode(question({0x80, 0})), DnsError::bad_label));
    {
        // Two names chasing each other: the second jumps back into the first,
        // which then points at the second — strictly-descending rule stops it.
        auto out = wire({0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0});
        append(out, {1, 'a', 0xC0, 22, 0, 1, 0, 1});  // name at 12, pointer to 22
        append(out, {0xC0, 12, 0, 1, 0, 1});          // name at 20? (offset 20)
        CHECK(!decode(out));
    }
    {
        auto out = wire({0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0});
        for (int i = 0; i < 5; ++i) {
            append(out, {63});
            append_text(out, std::string(63, 'x'));
        }
        append(out, {0, 0, 1, 0, 1});
        CHECK(fails_with(decode(out), DnsError::name_too_long));
    }
    {
        auto amplified = wire({0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0});
        CHECK(fails_with(decode(amplified), DnsError::too_many_records));
        auto sparse = wire({0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0});
        CHECK(fails_with(decode(sparse), DnsError::truncated));
        Limits tight;
        tight.max_records = 1;
        CHECK(fails_with(decode(base, tight), DnsError::too_many_records));
        tight = {};
        tight.max_message_size = 20;
        CHECK(fails_with(decode(base, tight), DnsError::too_large));
    }
    const auto record = [](std::initializer_list<int> rr, int section = 0) {
        auto out = wire({0, 0, 0x80, 0, 0, 0, section == 0 ? 0 : 0, section == 0 ? 1 : 0, 0, 0, 0,
                         section == 2 ? 1 : 0});
        append(out, rr);
        return out;
    };
    CHECK(fails_with(decode(record({0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4, 5})), DnsError::bad_rdata));
    CHECK(fails_with(decode(record({0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 3, 5, 'a', 'b'})), DnsError::bad_rdata));
    CHECK(fails_with(decode(record({0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 0})), DnsError::bad_rdata));
    CHECK(fails_with(decode(record({0, 0, 5, 0, 1, 0, 0, 0, 0, 0, 4, 1, 'a', 0, 0})), DnsError::bad_rdata));
    CHECK(fails_with(decode(record({0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 9, 1, 2})), DnsError::truncated));
    CHECK(fails_with(decode(record({0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0})), DnsError::bad_opt));  // answer
    CHECK(fails_with(decode(record({1, 'a', 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0}, 2)), DnsError::bad_opt));
    CHECK(fails_with(decode(record({0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 3, 0, 1, 0}, 2)), DnsError::bad_opt));
    {
        auto twice = wire({0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 2});
        append(twice, {0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0});
        CHECK(fails_with(decode(twice), DnsError::bad_opt));
    }
    {
        // CHAOS-class A keeps raw RDATA rather than an IPv4 interpretation.
        const auto chaos = decode(record({0, 0, 1, 0, 3, 0, 0, 0, 0, 0, 2, 7, 7}));
        CHECK(chaos && std::holds_alternative<RawData>(chaos->answers[0].data));
    }
}

void round_trips() {
    test::section("encode/decode round trips");
    Message message;
    message.header = {.id = 7, .qr = true, .opcode = 0, .aa = true, .tc = false, .rd = true,
                      .ra = true, .ad = true, .cd = false, .rcode = rcode::badvers};
    const auto owner = *Name::parse("mira.test");
    message.questions.push_back({owner, type::any, class_in});
    message.answers.push_back({owner, type::a, class_in, 60, AData{{127, 0, 0, 1}}});
    message.answers.push_back({owner, type::aaaa, class_in, 61,
                               AaaaData{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}});
    message.answers.push_back({owner, type::cname, class_in, 62, NameData{*Name::parse("alias.test")}});
    message.answers.push_back({owner, type::mx, class_in, 63, MxData{10, *Name::parse("mx.mira.test")}});
    message.answers.push_back({owner, type::txt, class_in, 64, TxtData{{"v=1", "", std::string(255, 't')}}});
    message.answers.push_back({owner, type::https, class_in, 65, RawData{{std::byte{0}, std::byte{1}}}});
    message.authorities.push_back({*Name::parse("test"), type::soa, class_in, 3600,
                                   SoaData{*Name::parse("ns.test"), *Name::parse("admin.test"), 1, 2, 3, 4, 30}});
    message.additionals.push_back({*Name::parse("ns.test"), type::a, class_in, 5, AData{{10, 0, 0, 1}}});
    message.edns = Edns{4096, 0, true, {{10, {std::byte{1}, std::byte{2}}}, {12, {}}}};
    const auto encoded = encode(message);
    CHECK_VALUE(encoded);
    const auto decoded = encoded ? decode(*encoded) : Result<Message>{fail(Errc::internal)};
    CHECK_VALUE(decoded);
    CHECK(decoded && *decoded == message);
    CHECK(min_ttl(message) == std::optional<std::uint32_t>{30});

    auto bad = message;
    bad.edns.reset();
    CHECK(!encode(bad));  // extended RCODE needs EDNS
    bad = message;
    bad.header.opcode = 16;
    CHECK(!encode(bad));
    bad = message;
    bad.answers[0].type = type::mx;  // AData under MX
    CHECK(!encode(bad));
    bad = message;
    bad.answers[4].data = TxtData{};
    CHECK(!encode(bad));
    bad = message;
    bad.additionals.push_back({Name{}, type::opt, 512, 0, RawData{}});
    CHECK(!encode(bad));

    const auto query = encode_query(*Name::parse("www.example.com"), type::aaaa,
                                    {.id = 0, .udp_payload_size = 1232, .pad_to_block = 128});
    CHECK(query && query->size() % 128 == 0);
    const auto plain = encode_query(*Name::parse("www.example.com"), type::a, {.udp_payload_size = 0});
    CHECK(plain && plain->size() == 33);
    CHECK(!encode_query(*Name::parse("a"), type::a, {.udp_payload_size = 0, .pad_to_block = 128}));
    CHECK(make_error_code(DnsError::bad_pointer).message().find("pointer") != std::string::npos);
}

}  // namespace

int main() {
    names();
    decode_captured();
    malformed();
    round_trips();
    return test::summary();
}
