#pragma once

// HPACK and QPACK share a protocol-neutral field-section vocabulary.
#include "mira/http/fields.hpp"

namespace Mira::http2 {
using Mira::http::Header;
using Mira::http::Headers;
}  // namespace Mira::http2
