#pragma once

// HTTP field sections are protocol-neutral: HPACK and QPACK encode the same
// ordered, duplicate-preserving name/value representation. This header-only
// vocabulary must not pull either protocol engine into the other.
#include <string>
#include <vector>

namespace Mira::http {

struct Header {
    std::string name;
    std::string value;
};

using Headers = std::vector<Header>;

}  // namespace Mira::http
