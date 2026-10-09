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
check in `scripts/ci/check_layering.py` fails the build otherwise.

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
  truncation reporting, stop tokens and deadlines. ASM multicast membership,
  outgoing interface, hops and loopback are explicit operations. POSIX packet
  metadata includes destination/interface, traffic class and kernel receive
  timestamp; `send_message` selects supported per-packet source information.
  Unsupported metadata options fail explicitly on Windows. No SSM or batch API
  is implied. `DatagramTransport` remains separate from `AsyncStream`.
- `local::Socket` and `local::Listener` implement Unix-domain streams on
  supported POSIX platforms.
- The resolver and `tcp::dial` compose bounded system name resolution with
  family-interleaved connection attempts. Optional bounded positive/negative
  policy caching and in-flight query coalescing preserve independent waiter
  cancellation. Cache lifetimes are caller policy, not DNS TTL; `clear_cache`
  prevents old in-flight results repopulating the cache. Entered `getaddrinfo`
  calls still cannot be interrupted and destruction joins their workers.
  `dns::query_udp` / `query_tcp` offer separately composed, deadline-bounded
  wire exchanges without resolver threads, not automatic NSS/server discovery.
- `tcp::serve` adds connection admission, structured handlers and staged
  shutdown. Resource reservations are accounting limits, not process-RSS caps.

Core backend tests exercise real loopback I/O on desktop CI; mobile builds are
cross-compilation evidence unless a device run is explicitly recorded.
