#!/usr/bin/env python3
"""Verify packages, components, linking and execution from an isolated installed SDK."""

import argparse
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
    args = parser.parse_args()
    build = args.build_dir.resolve()
    cache = cache_values(build)
    installed = ['core', 'transport', 'http']
    for component, option in [('tls', 'TLS'), ('ws', 'WEBSOCKET'), ('http2', 'HTTP2'), ('http3', 'HTTP3')]:
        if cache.get('MIRA_ENABLE_' + option) == 'ON':
            installed.append(component)
    if 'http3' in installed:
        installed.append('quic')
    if args.expect_http3_only and ('http3' not in installed or 'http2' in installed):
        raise RuntimeError('This mode requires HTTP3=ON and HTTP2=OFF')

    with tempfile.TemporaryDirectory(prefix='mira-install-consumer-') as temporary:
        root = Path(temporary)
        prefix = root / 'prefix'
        run(['cmake', '--install', str(build), '--prefix', str(prefix),
             '--config', args.config])
        common = ['-G', cache['CMAKE_GENERATOR'],
                  '-DCMAKE_BUILD_TYPE=' + args.config,
                  '-DCMAKE_CONFIGURATION_TYPES=' + args.config]
        for key in ('CMAKE_CXX_COMPILER', 'CMAKE_TOOLCHAIN_FILE', 'CMAKE_CXX_FLAGS',
                    'CMAKE_OSX_ARCHITECTURES', 'CMAKE_OSX_DEPLOYMENT_TARGET',
                    'OPENSSL_ROOT_DIR'):
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
        if args.expect_http3_only:
            common.append('-DCMAKE_DISABLE_FIND_PACKAGE_NGHTTP2=TRUE')

        def case(name, find, *, source=None, links='core transport http',
                 checks='', hidden=False, success=True, diagnostic=None):
            directory = root / name
            directory.mkdir()
            text = ('cmake_minimum_required(VERSION 3.20)\n'
                    'project(consumer LANGUAGES CXX)\n'
                    f'find_package(Mira REQUIRED {find})\n' + checks + '\n')
            if source:
                (directory / 'main.cpp').write_text(source, encoding='utf-8')
                targets = ' '.join('Mira::' + name for name in links.split())
                text += ('add_executable(consumer main.cpp)\n'
                         f'target_link_libraries(consumer PRIVATE {targets})\n'
                         'enable_testing()\n'
                         'add_test(NAME installed_api COMMAND consumer)\n')
            (directory / 'CMakeLists.txt').write_text(text, encoding='utf-8')
            command = ['cmake', '-S', str(directory), '-B', str(directory / 'build'),
                       *common]
            if hidden:
                command += ['-DCMAKE_DISABLE_FIND_PACKAGE_OpenSSL=TRUE',
                            '-DCMAKE_DISABLE_FIND_PACKAGE_NGHTTP2=TRUE']
            run(command, success=success, diagnostic=diagnostic)
            if source and success:
                run(['cmake', '--build', str(directory / 'build'), '--config', args.config])
                run(['ctest', '--test-dir', str(directory / 'build'),
                     '--build-config', args.config, '--output-on-failure'])

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
        case('optional-unknown', 'COMPONENTS core OPTIONAL_COMPONENTS unknown',
             checks='if(Mira_unknown_FOUND)\n  message(FATAL_ERROR "Unknown component unexpectedly found")\nendif()')
        for component in ('tls', 'ws', 'http2'):
            if component in installed:
                case('explicit-' + component, 'COMPONENTS ' + component,
                     checks=f'if(NOT Mira_{component}_FOUND OR NOT TARGET Mira::{component})\n'
                            f'  message(FATAL_ERROR "Explicit component not loaded {component}")\nendif()')
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
