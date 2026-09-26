#pragma once

// Mira/http2/headers.hpp — the header list shared by HTTP/2 and HTTP/3.
//
// HPACK and QPACK compress the same field-section semantics, so the two
// protocols model a header list identically: an ordered sequence of
// name/value pairs where order and duplication are meaningful. One struct
// serves both, which is what lets an application switch transports without
// rewriting its header handling.
//
// This header deliberately carries nothing else — no limits, no framing —
// because the two protocols genuinely differ there: h2 limits are frame
// oriented, h3 limits are stream oriented. Sharing those would be inventing
// a unity that does not exist.

#include <string>
#include <vector>

namespace Mira::http2 {

/// One header field. Order matters (HTTP/2 treats a header list as an
/// ordered sequence), and duplicate names are legal (set-cookie et al.), so
/// this is a flat vector rather than a map.
struct Header {
    std::string name;
    std::string value;
};

using Headers = std::vector<Header>;

}  // namespace Mira::http2
