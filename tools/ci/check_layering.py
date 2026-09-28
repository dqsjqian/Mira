#!/usr/bin/env python3
"""Enforce Mira's architectural invariants at build time.

These rules exist because the failure mode they prevent is *gradual*. Nobody
decides to weld the socket layer to the parser; it happens one include at a
time, and by the time it hurts, the fix is a rewrite. A comment in a design
document cannot stop that. A failing build can.

Rule 1 — layering is one-way.

    protocol (http, ws, ...)  ->  transport (tcp, udp, unix)  ->  core

    core must not include transport or protocol headers; transport must not
    include protocol headers. Reaching *up* a layer is the exact move that
    makes a library unable to grow a second protocol later.

Rule 2 — no host framework dependency.

    Mira must stay usable without Aria (or any other framework). Hosts
    integrate through the executor and stream seams; a single `#include
    <aria/...>` anywhere in the library would turn an optional adapter into a
    hard dependency for every consumer.

Rule 3 — platform detection has exactly one home.

    Only `platform.hpp` may test raw compiler macros (`_WIN32`, `__linux__`,
    `__APPLE__`, ...). Everywhere else asks it via `MIRA_*`. Scattered
    `#ifdef _WIN32` is how a library ends up with a first-class POSIX path and
    a Windows path nobody can reason about — and why "supports Windows" starts
    meaning "compiles on Windows".

Rule 4 — protocols are platform-agnostic.

    A protocol module must not include OS headers. Protocols speak to the
    stream and executor seams only; the moment a parser knows what a socket is,
    the same parser can no longer be tested over an in-memory pipe or run over
    TLS.

Usage:
    python3 tools/ci/check_layering.py [repo_root]

Exit status is 0 when clean, 1 when any violation is found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SOURCE_SUFFIXES = {".hpp", ".h", ".cpp", ".cc", ".ipp"}

# Layer name -> module directories that make up that layer.
LAYERS: dict[str, tuple[str, ...]] = {
    "core": ("core",),
    "transport": ("transport",),
    "composition": ("client",),
    "tls": ("tls",),
    "crypto": ("crypto",),
    "quic": ("quic",),
    "protocol": ("http_common", "http", "http2", "http3", "ws", "h2", "h3", "dns"),
}

# Layer -> include path prefixes it is not allowed to reach for.
FORBIDDEN_INCLUDES: dict[str, tuple[str, ...]] = {
    "core": ("mira/client/", "mira/crypto/", "mira/tls/", "openssl/", "mira/transport/", "mira/http/", "mira/ws/",
             "mira/h2/", "mira/h3/", "mira/dns/", "mira/http2/", "mira/http3/",
             "mira/quic/", "nghttp2/", "nghttp3/", "ngtcp2/"),
    "transport": ("mira/client/", "mira/tls/", "openssl/", "mira/http/", "mira/ws/", "mira/h2/",
                  "mira/h3/", "mira/dns/", "mira/http2/", "mira/http3/",
                  "mira/quic/", "nghttp2/", "nghttp3/", "ngtcp2/"),
    "crypto": ("mira/client/", "mira/transport/", "mira/tls/", "mira/http/", "mira/ws/", "mira/quic/"),
    "tls": ("mira/client/", "mira/transport/", "mira/http/", "mira/ws/", "mira/h2/",
            "mira/h3/", "mira/dns/", "mira/http2/", "mira/http3/", "mira/quic/"),
    "quic": ("mira/client/", "mira/http/", "mira/http2/", "mira/http3/", "mira/h2/",
             "mira/h3/", "nghttp2/", "nghttp3/"),
    "protocol": ("openssl/", "mira/tls/", "mira/transport/", "mira/client/"),
    "composition": ("openssl/", "ngtcp2/", "nghttp3/", "nghttp2/"),
}

# Include prefixes no layer may use, with the reason reported to the user.
BANNED_EVERYWHERE: dict[str, str] = {
    "aria/": "Mira must not depend on Aria; hosts integrate via the executor/stream seams",
}

# OS headers a protocol module must never reach for.
PLATFORM_HEADER_PREFIXES: tuple[str, ...] = (
    "sys/", "netinet/", "arpa/", "net/",
    "windows.h", "winsock2.h", "ws2tcpip.h", "mswsock.h", "basetsd.h",
    "unistd.h", "fcntl.h", "poll.h", "errno.h",
    "TargetConditionals.h",
)

# Raw compiler macros that only platform.hpp may test. Everything else uses the
# MIRA_* macros it derives.
RAW_PLATFORM_MACROS: tuple[str, ...] = (
    "_WIN32", "_WIN64", "__linux__", "__APPLE__", "__ANDROID__",
    "__FreeBSD__", "__OpenBSD__", "__NetBSD__", "TARGET_OS_IPHONE",
)

# The single file allowed to do platform detection, relative to repo root.
PLATFORM_DETECTION_HOME = "modules/core/include/mira/core/platform.hpp"

INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')

# Matches a preprocessor conditional that tests a raw platform macro, e.g.
# `#if defined(_WIN32)`, `#ifdef __linux__`, `#elif __APPLE__`.
CONDITIONAL_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif)\b(.*)$")


def layer_of(path: Path, modules_root: Path) -> str | None:
    """Return the layer a file belongs to, or None if it is outside modules/."""
    try:
        relative = path.relative_to(modules_root)
    except ValueError:
        return None
    if not relative.parts:
        return None
    module = relative.parts[0]
    for layer, modules in LAYERS.items():
        if module in modules:
            return layer
    return None


def iter_sources(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in SOURCE_SUFFIXES:
            yield path


def check(repo_root: Path) -> list[str]:
    modules_root = repo_root / "modules"
    if not modules_root.is_dir():
        return [f"{modules_root}: modules/ directory not found"]

    violations: list[str] = []

    for path in iter_sources(modules_root):
        layer = layer_of(path, modules_root)
        # Integration tests may compose modules; production headers/sources may not.
        is_test = "tests" in path.relative_to(modules_root).parts
        forbidden = () if is_test else FORBIDDEN_INCLUDES.get(layer or "", ())
        display = path.relative_to(repo_root)
        is_platform_home = display.as_posix() == PLATFORM_DETECTION_HOME

        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            # Rule 3 — platform detection has exactly one home.
            if not is_platform_home:
                conditional = CONDITIONAL_RE.match(line)
                if conditional:
                    expression = conditional.group(2)
                    for macro in RAW_PLATFORM_MACROS:
                        if re.search(rf"\b{re.escape(macro)}\b", expression):
                            violations.append(
                                f"{display}:{lineno}: tests raw platform macro '{macro}' — "
                                f"use the MIRA_* macros from {PLATFORM_DETECTION_HOME}"
                            )

            match = INCLUDE_RE.match(line)
            if not match:
                continue
            included = match.group(1)

            # Rule 2 — no host framework dependency.
            for prefix, reason in BANNED_EVERYWHERE.items():
                if included.startswith(prefix):
                    violations.append(
                        f"{display}:{lineno}: includes '{included}' — {reason}"
                    )

            # Rule 1 — dependencies point downwards only.
            for prefix in forbidden:
                if included.startswith(prefix):
                    violations.append(
                        f"{display}:{lineno}: layer '{layer}' includes '{included}' — "
                        f"dependencies only point downwards"
                    )

            # Rule 4 — protocols are platform-agnostic.
            if layer in ("protocol", "tls", "composition") and not is_test:
                for prefix in PLATFORM_HEADER_PREFIXES:
                    if included.startswith(prefix):
                        violations.append(
                            f"{display}:{lineno}: protocol module includes OS header "
                            f"'{included}' — protocols talk to the stream/executor seams only"
                        )

    return violations


def main(argv: list[str]) -> int:
    repo_root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[2]
    violations = check(repo_root)

    if violations:
        print("Layering violations found:\n", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        print(f"\n{len(violations)} violation(s).", file=sys.stderr)
        return 1

    print(f"Layering OK — {repo_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
