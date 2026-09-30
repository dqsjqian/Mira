#!/usr/bin/env python3
"""Verify packages, components, linking and execution from an isolated installed SDK."""

import argparse
import contextlib
from pathlib import Path
import subprocess
import tempfile


BASE_SOURCE = r'''
#include <mira/core/version.hpp>
#include <mira/core/error.hpp>
#include <mira/http/parser.hpp>
#include <mira/transport/endpoint.hpp>
#include <iostream>
int main() {
    auto endpoint = Mira::transport::Endpoint::parse("127.0.0.1", 8123);
    if (!endpoint || endpoint->port() != 8123) return 1;
    Mira::Buffer buffer;
    Mira::http::RequestParser parser;
    auto step = parser.parse(buffer);
    if (!step || *step != Mira::http::ParseStep::need_more) return 2;
    if (!Mira::make_error_code(Mira::Errc::invalid_argument)) return 3;
    std::cout << MIRA_VERSION_STRING << '\n';
    return 0;
}
'''
H3_SOURCE = r'''
#include <mira/core/version.hpp>
#include <mira/http3/connection.hpp>
#include <mira/transport/udp.hpp>
#include <iostream>
int main() {
    auto error = Mira::http3::http3_error(-1);
    if (!error) return 1;
    std::cout << MIRA_VERSION_STRING << ' ' << error.message() << '\n';
    return 0;
}
'''


def run(command, *, success=True, diagnostic=None):
    print('+', ' '.join(str(arg) for arg in command), flush=True)
    result = subprocess.run(command, text=True, encoding='utf-8', errors='replace',
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    print(result.stdout, end='', flush=True)
    if success != (result.returncode == 0):
        raise RuntimeError(f'Unexpected command exit status: {result.returncode}')
    if diagnostic and diagnostic not in result.stdout:
        raise RuntimeError(f'Missing component diagnostic: {diagnostic}')


def cache_values(build):
    values = {}
    for line in (build / 'CMakeCache.txt').read_text(encoding='utf-8').splitlines():
        if line and not line.startswith(('#', '//')) and '=' in line:
            key, value = line.split('=', 1)
            values[key.split(':', 1)[0]] = value
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--config', default='Debug')
    parser.add_argument('--expect-http3-only', action='store_true')
    parser.add_argument('--output-dir', type=Path, help='retain evidence in a new directory instead of temporary cleanup')
    args = parser.parse_args()
    build = args.build_dir.resolve()
    cache = cache_values(build)
    version = cache['CMAKE_PROJECT_VERSION']
    major, minor, patch = (int(part) for part in version.split('.'))
    version_checks = f'''
#include <mira/core/version.hpp>
#include <string_view>
static_assert(MIRA_VERSION_MAJOR == {major});
static_assert(MIRA_VERSION_MINOR == {minor});
static_assert(MIRA_VERSION_PATCH == {patch});
static_assert(MIRA_VERSION == MIRA_VERSION_NUMBER({major}, {minor}, {patch}));
static_assert(std::string_view{{MIRA_VERSION_STRING}} == "{version}");
'''
    installed = ['core', 'transport', 'http', 'client', 'socks', 'dns', 'mqtt']
    for component, option in [('tls', 'TLS'), ('ws', 'WEBSOCKET'), ('http2', 'HTTP2'), ('http3', 'HTTP3')]:
        if cache.get('MIRA_ENABLE_' + option) == 'ON':
            installed.append(component)
    if 'http3' in installed:
        installed.append('quic')
    if 'tls' in installed:
        installed.append('client_tls')
    if args.expect_http3_only and ('http3' not in installed or 'http2' in installed):
        raise RuntimeError('This mode requires HTTP3=ON and HTTP2=OFF')

    if args.output_dir:
        args.output_dir = args.output_dir.resolve()
        args.output_dir.mkdir(parents=True, exist_ok=False)
    workspace = (contextlib.nullcontext(str(args.output_dir)) if args.output_dir else
                 tempfile.TemporaryDirectory(prefix='mira-install-consumer-'))
    with workspace as temporary:
        root = Path(temporary)
        prefix = root / 'prefix'
        run(['cmake', '--install', str(build), '--prefix', str(prefix),
             '--config', args.config])
        data_dir = cache.get('CMAKE_INSTALL_DATADIR') or cache.get('CMAKE_INSTALL_DATAROOTDIR') or 'share'
        if not (prefix / data_dir / 'licenses' / 'Mira' / 'LICENSE').is_file():
            raise RuntimeError('Installed SDK is missing its LICENSE')
        common = ['-G', cache['CMAKE_GENERATOR']]
        if cache.get('CMAKE_CONFIGURATION_TYPES'):
            common.append('-DCMAKE_CONFIGURATION_TYPES=' + args.config)
        else:
            common.append('-DCMAKE_BUILD_TYPE=' + args.config)
        for key in ('CMAKE_CXX_COMPILER', 'CMAKE_TOOLCHAIN_FILE', 'CMAKE_CXX_FLAGS',
                    'CMAKE_OSX_ARCHITECTURES', 'CMAKE_OSX_DEPLOYMENT_TARGET'):
            if cache.get(key):
                common.append(f'-D{key}={cache[key]}')
        for key, flag in [('CMAKE_GENERATOR_PLATFORM', '-A'),
                          ('CMAKE_GENERATOR_TOOLSET', '-T')]:
            if cache.get(key):
                common.extend([flag, cache[key]])
        prefixes = str(prefix) + ';' + cache.get('CMAKE_PREFIX_PATH', '')
        common.extend(['-DCMAKE_PREFIX_PATH=' + prefixes,
                       '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF',
                       '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF'])
        def case(name, find, *, source=None, links='transport http',
                 checks='', hidden=False, success=True, diagnostic=None, disabled=(),
                 requested_version=''):
            directory = root / name
            directory.mkdir()
            # Isolation is a property of each test project. Some intentionally
            # never call find_package for these dependencies, so define the
            # policy here instead of passing unused CLI cache overrides.
            hidden_packages = set(disabled)
            if hidden:
                hidden_packages.update(('OpenSSL', 'NGHTTP2', 'ZLIB'))
            if args.expect_http3_only:
                hidden_packages.add('NGHTTP2')
            settings = ''.join(f'set(CMAKE_DISABLE_FIND_PACKAGE_{package} TRUE)\n'
                               for package in sorted(hidden_packages))
            if cache.get('OPENSSL_ROOT_DIR') and not hidden:
                openssl_root = Path(cache['OPENSSL_ROOT_DIR']).as_posix()
                settings += f'set(OPENSSL_ROOT_DIR [==[{openssl_root}]==])\n'
            text = ('cmake_minimum_required(VERSION 3.21)\n'
                    'project(consumer LANGUAGES CXX)\n' + settings +
                    f'find_package(Mira {requested_version} REQUIRED {find})\n' + checks + '\n')
            if source:
                (directory / 'main.cpp').write_text(version_checks + source, encoding='utf-8')
                targets = ' '.join('Mira::' + name for name in links.split())
                text += ('add_executable(consumer main.cpp)\n'
                         f'target_link_libraries(consumer PRIVATE {targets})\n'
                         'enable_testing()\n'
                         'add_test(NAME installed_api COMMAND consumer)\n')
            (directory / 'CMakeLists.txt').write_text(text, encoding='utf-8')
            command = ['cmake', '-S', str(directory), '-B', str(directory / 'build'),
                       *common]
            run(command, success=success, diagnostic=diagnostic)
            if source and success:
                run(['cmake', '--build', str(directory / 'build'), '--config', args.config])
                run(['ctest', '--test-dir', str(directory / 'build'),
                     '--build-config', args.config, '--output-on-failure', '--no-tests=error'])

        case('version-exact', 'COMPONENTS core transport http',
             requested_version=version + ' EXACT', source=BASE_SOURCE, hidden=True,
             checks=f'if(NOT Mira_VERSION STREQUAL "{version}")\n'
                    '  message(FATAL_ERROR "Installed package version does not match the build")\nendif()')
        case('version-compatible', 'COMPONENTS core', requested_version=f'{major}.0', hidden=True)
        for name, requested in [('future-major', f'{major + 1}.0.0'),
                                ('future-patch', f'{major}.{minor}.{patch + 1}')]:
            case('version-' + name, 'COMPONENTS core', requested_version=requested,
                 hidden=True, success=False, diagnostic='considered but not accepted')
        if major > 0:
            case('version-previous-major', 'COMPONENTS core',
                 requested_version=f'{major - 1}.0.0', hidden=True,
                 success=False, diagnostic='considered but not accepted')

        case('base', 'COMPONENTS core transport http', source=BASE_SOURCE, hidden=True,
             checks='''
foreach(component IN ITEMS core transport http)
  if(NOT Mira_${component}_FOUND)
    message(FATAL_ERROR "Missing standard component status ${component}")
  endif()
endforeach()
foreach(component IN ITEMS tls crypto ws http2 quic http3)
  if(TARGET Mira::${component})
    message(FATAL_ERROR "Unexpected optional component loaded ${component}")
  endif()
endforeach()
''')
        checks = '\n'.join(
            f'if(NOT TARGET Mira::{component})\n'
            f'  message(FATAL_ERROR "Installed component not loaded {component}")\nendif()'
            for component in installed)
        case('all', '', source=BASE_SOURCE, checks=checks)
        if 'http2' in installed:
            case('h2-link', 'COMPONENTS http2', links='http2', source='''
#include <mira/http2/session.hpp>
int main() {
    auto session = Mira::http2::Session::create(Mira::http2::Role::client);
    if (!session) return 1;
    auto stream = session->request({{":method", "GET"}, {":scheme", "https"},
                                    {":authority", "localhost"}, {":path", "/"}});
    auto output = session->output();
    return stream && output && !output->empty() ? 0 : 2;
}
''')
        case('optional-unknown', 'COMPONENTS core OPTIONAL_COMPONENTS unknown',
             checks='if(Mira_unknown_FOUND)\n  message(FATAL_ERROR "Unknown component unexpectedly found")\nendif()')
        for component in ('tls', 'ws', 'http2'):
            if component in installed:
                case('explicit-' + component, 'COMPONENTS ' + component,
                     checks=f'if(NOT Mira_{component}_FOUND OR NOT TARGET Mira::{component})\n'
                            f'  message(FATAL_ERROR "Explicit component not loaded {component}")\nendif()')
        if 'ws' in installed:
            no_zlib = ('ZLIB',)
            case('ws-missing-zlib', 'COMPONENTS ws', disabled=no_zlib, success=False,
                 diagnostic="Mira component 'ws' is unavailable")
            case('ws-optional-missing-zlib', 'COMPONENTS core crypto OPTIONAL_COMPONENTS ws',
                 disabled=no_zlib, checks='''
if(Mira_ws_FOUND OR TARGET Mira::ws OR NOT Mira_crypto_FOUND)
  message(FATAL_ERROR "Missing zlib must hide ws without hiding crypto")
endif()
''')
            case('ws-codec', 'COMPONENTS ws', links='ws', source='''
#include <mira/ws/compression.hpp>
int main() {
    Mira::ws::CompressionParameters parameters;
    parameters.enabled = true;
    auto codec = Mira::ws::DeflateEncoder::create(Mira::ws::Role::client, parameters);
    if (!codec) return 1;
    Mira::ws::Frame frame;
    frame.payload.assign(1024, std::byte{0x61});
    auto compressed = codec->encode(frame);
    return compressed && compressed->compressed && compressed->payload.size() < frame.payload.size() ? 0 : 2;
}
''')
        case('socks-api', 'COMPONENTS socks', links='socks', hidden=True, source='''
#include <mira/socks/socks5.hpp>
int main() {
    auto address = Mira::socks::Address::parse("::ffff:192.0.2.1", 1080);
    if (!address || address->kind() != Mira::socks::Address::Kind::ipv6) return 1;
    return address->to_string() == "[::ffff:192.0.2.1]:1080" ? 0 : 2;
}
''')
        case('mqtt-api', 'COMPONENTS mqtt', links='mqtt', hidden=True, source='''
#include <mira/mqtt/session.hpp>
int main() {
    Mira::mqtt::ClientOptions options;
    options.client_id = "consumer";
    auto session = Mira::mqtt::Session::create(options);
    if (!session || !session->connect(0)) return 1;
    auto wire = session->take_output(0);
    auto decoded = Mira::mqtt::decode(wire, Mira::mqtt::Version::v5, Mira::mqtt::Role::server);
    return decoded && decoded->packet && Mira::mqtt::topic_matches("a/+", "a/b") ? 0 : 2;
}
''')
        case('client-api', 'COMPONENTS client', links='client', hidden=True, source='''
#include <mira/client/http.hpp>
int main() {
    auto loop = Mira::EventLoop::create();
    if (!loop) return 1;
    auto client = Mira::client::HttpClient::create(*loop, {});
    return client && client->active_and_idle() == 0 ? 0 : 2;
}
''')
        if 'client_tls' in installed:
            case('client-tls-api', 'COMPONENTS client_tls', links='client_tls', source='''
#include <mira/client/https.hpp>
int main() {
    auto loop = Mira::EventLoop::create();
    auto factory = Mira::client::HttpsFactory::create();
    if (!loop || !factory) return 1;
    auto client = Mira::client::HttpsClient::create(*loop, std::move(*factory));
    return client && client->active_and_idle() == 0 ? 0 : 2;
}
''')
        case('client-tls-required-hidden', 'COMPONENTS client_tls', hidden=True, success=False,
             diagnostic="Mira component 'client_tls' is unavailable")
        case('client-tls-optional-hidden', 'COMPONENTS client OPTIONAL_COMPONENTS client_tls',
             hidden=True, checks='''
if(NOT Mira_client_FOUND OR Mira_client_tls_FOUND OR TARGET Mira::client_tls)
  message(FATAL_ERROR "Client TLS dependency isolation failed")
endif()
''')
        case('unknown-required', 'COMPONENTS unknown', success=False,
             diagnostic="Mira component 'unknown' is unavailable")
        optional = 'tls crypto ws http2 quic http3 unknown'
        case('optional-hidden', 'COMPONENTS core OPTIONAL_COMPONENTS ' + optional,
             hidden=True, checks='''
foreach(component IN ITEMS tls crypto ws http2 quic http3 unknown)
  if(Mira_${component}_FOUND)
    message(FATAL_ERROR "Missing optional component unexpectedly found ${component}")
  endif()
endforeach()
''')
        for component in ['tls', 'http2', 'quic', 'http3']:
            case('missing-' + component, 'COMPONENTS ' + component,
                 hidden=True, success=False,
                 diagnostic=f"Mira component '{component}' is unavailable")
        if 'quic' in installed:
            case('quic', 'COMPONENTS quic', checks='''
if(NOT Mira_quic_FOUND OR NOT TARGET Mira::quic)
  message(FATAL_ERROR "QUIC component not loaded")
endif()
if(TARGET Mira::http3 OR TARGET mira_nghttp3 OR TARGET Mira::http2
    OR DEFINED MIRA_NGHTTP3_INCLUDE_DIR OR DEFINED MIRA_NGHTTP3_LIBRARY)
  message(FATAL_ERROR "QUIC must not discover or load HTTP/3 or HTTP/2")
endif()
''')
        if 'http3' in installed:
            case('h3', 'COMPONENTS http3', source=H3_SOURCE, links='http3', checks='''
if(TARGET Mira::http2 OR TARGET NGHTTP2::NGHTTP2)
  message(FATAL_ERROR "HTTP/3 must not load HTTP/2")
endif()
if(NOT Mira_http3_FOUND OR NOT Mira_quic_FOUND)
  message(FATAL_ERROR "HTTP/3 dependency closure is incomplete")
endif()
''')
        case('repeat-after-miss', 'COMPONENTS core', checks='''
find_package(Mira QUIET COMPONENTS unknown)
if(Mira_FOUND)
  message(FATAL_ERROR "Unknown required component lookup must fail")
endif()
find_package(Mira REQUIRED COMPONENTS core)
if(NOT Mira_FOUND OR NOT Mira_core_FOUND)
  message(FATAL_ERROR "A failed lookup must not poison subsequent lookups")
endif()
''')
    print('PASS: installed SDK, version header, component isolation, required and optional lookups')


if __name__ == '__main__':
    main()
