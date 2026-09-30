# modules/transport — TCP, UDP, local streams

`Socket` models `Mira::AsyncStream`, so a protocol written against the
concept accepts one without naming it. Implemented here:

- `Endpoint` — numeric IPv4 / IPv6 addresses. No name resolution: DNS is a
  protocol, and it belongs in its own module rather than inside the address
  type every transport depends on.
- `Listener` — `bind` with explicit `ListenOptions`, and `accept`.
- `Socket` — `read_some` / `write_some` with short-transfer semantics,
  `shutdown_send`, and `close`.
- `connect` — an outgoing connection with `ConnectOptions`.

This layer may include `Mira/core/…` and nothing above it; the layering
check in `tools/ci/check_layering.py` fails the build otherwise.

Every operation takes `OperationOptions` and forwards it to the event loop
unchanged, which is what makes `Socket` a `BoundedStream`. `connect` keeps it
separate from `ConnectOptions`: the latter configures a socket and may be
reused across calls, while a stop token and an absolute deadline belong to one
call, and storing them in a reusable struct is a deadline that silently belongs
to whichever call ran first.

## Why `ListenOptions::exclusive` exists

This option is where the disagreement that started the project gets an explicit
home. `SO_REUSEADDR` means two different things: on POSIX it permits rebinding
a port left in `TIME_WAIT`, while on Windows the same constant lets a second
process **steal** a port another process is actively bound to — so two servers
both "successfully" listen on one port and split the incoming connections
between them.

Mira therefore does not expose `SO_REUSEADDR` as a portable flag. It
exposes the *intent*, and each platform implements that intent with whatever
combination of socket options actually produces it. `tcp.hpp` carries the full
reasoning; this is a summary, not the specification.

## Additional transports and composition

- `udp::Socket` preserves message boundaries with bounded send/receive,
  truncation reporting, stop tokens and deadlines. `DatagramTransport` is a
  separate concept: a UDP datagram is never represented as an `AsyncStream`.
- `local::Socket` and `local::Listener` implement Unix-domain streams on
  supported POSIX platforms.
- The resolver and `tcp::dial` compose bounded system name resolution with
  family-interleaved connection attempts. DNS/DoH wire codecs live in `dns`.
- `tcp::serve` adds connection admission, structured handlers and staged
  shutdown. Resource reservations are accounting limits, not process-RSS caps.

Core backend tests exercise real loopback I/O on desktop CI; mobile builds are
cross-compilation evidence unless a device run is explicitly recorded.
