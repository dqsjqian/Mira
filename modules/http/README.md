# modules/http — HTTP/1.1

Written entirely against the stream concepts in `modules/core`. This module
never names a socket type, which is what keeps one parser usable over TCP, over
TLS, and over an in-memory buffer in tests. The layering check enforces it.

Implemented here:

- `RequestParser` — incremental, with the framing rules in `decide_framing`.
- `write_response_head` / `write_chunk` / `write_last_chunk` — serialisation
  that owns framing, and refuses a caller-supplied `Content-Length` or
  `Transfer-Encoding` rather than silently dropping it.
- `ResponseWriter` and `serve_connection` — one connection's request loop,
  keep-alive and pipelining included.
- `Limits` and `ServerOptions` — the limit policy, closed by default.
- `grammar.hpp` — the RFC 9110 character classes and list splitting, shared by
  the parser and the serialiser. One definition on purpose: two copies of a
  `tchar` table is the same disagreement this module exists to prevent, except
  inside a single binary.

## Rules this module actually follows

- **Reject, don't guess.** A `Content-Length` / `Transfer-Encoding` conflict is
  an error, not a heuristic. So is whitespace before a colon, obsolete line
  folding, a bare LF where CRLF is required, a CR anywhere else, a non-`tchar`
  field name, and `chunked` appearing anywhere but last or more than once. Each
  of those is a place where two implementations could disagree about where a
  message ends, which is what request smuggling is made of.
- **Limits closed by default.** Header count, header and start-line size, body
  size, chunk size and chunk-extension size all have conservative defaults that
  configuration opens, never the reverse.

## Not here, and why

**Routing and static-file policy.** These remain application concerns; the
`tiny_file_server` example demonstrates streaming downloads and explicitly
opt-in uploads rather than providing a production file-service policy.

## Streaming, clients, and verification

`RequestBodyReader` delivers streaming input; buffered handlers remain available.
`ResponseWriter` supplies fixed-length responses, chunked streaming and
explicit completion; HTTP/1.0 streams use connection-close framing. `ClientConnection` includes a response parser, streaming
uploads, `Expect: 100-continue`, and concurrent early-response handling. The
separate client module composes this protocol with transport and connection pools.

Request and response parser fuzz harnesses run in CI. Independent curl checks
exercise HTTP/1 example servers; these complement, not replace, crafted-input
and lifecycle regressions. Evidence is scoped to its tested revision/configuration.

HTTP/2 and HTTP/3 are separate optional modules. Shared field vocabulary is in
`http_common`; neither includes this module's HTTP/1 connection machinery.

**A time bound that is on by default.** `ServerOptions::idle_timeout` and
`request_timeout` exist and are forwarded, but both default to zero, which is
off. A server exposed to the internet should set them; leaving them at the
default bounds a slow peer by message size only.

Upload sources may accept `OperationOptions` to receive the exchange's stop
token and absolute deadline. Server handlers can accept the same options as a
fourth argument, or obtain them from `writer.operation_options()`. Pass these
options through asynchronous callback work; callbacks that ignore cancellation
cannot be forcibly stopped. Legacy callback signatures remain supported.
