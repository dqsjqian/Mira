#!/usr/bin/env python3
"""Build a locked HTTP/3 curl artifact against an existing protocol environment."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess

from forgedeps.artifacts import BuildRequest, Environment
from forgedeps.environments import read_environment, write_environment
from forgedeps.home import prepare_home
from forgedeps.source_cache import fetch_archive
from forgedeps.store import build_package
from forgedeps.toolchains import probe_toolchain
from forgerecipes import make_curl_recipe, recipe_input_files
from forgerecipes.bindings import build_curl
from build_protocol_deps import output_path, positive_jobs

VERSION = '8.22.0'
DIGEST = 'f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7'
REPO = Path(__file__).resolve().parents[2]


def required_artifacts(environment, names):
    all_artifacts = {}
    def visit(item):
        previous = all_artifacts.get(item.name)
        if previous and previous != item:
            raise ValueError('Conflicting protocol artifact: ' + item.name)
        all_artifacts[item.name] = item
        for dependency in item.requires:
            visit(dependency)
    for item in environment.artifacts:
        visit(item)
    missing = set(names) - set(all_artifacts)
    if missing:
        raise ValueError('Protocol environment is missing curl dependencies: ' + ', '.join(sorted(missing)))
    return tuple(all_artifacts[name] for name in names)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--environment', type=Path, required=True,
                        help='Mira configure output forgedeps-environment.json')
    parser.add_argument('--path', type=Path, default=REPO / 'build/interop-curl')
    parser.add_argument('--home', type=Path)
    parser.add_argument('--jobs', type=positive_jobs, default=4)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    root = prepare_home(args.home)
    work = output_path(args.path)
    environment = read_environment(args.environment)
    recipe = make_curl_recipe(cli=True, http2=True, http3=True)
    requires = required_artifacts(environment, recipe.requires)
    with environment.lease():
        # The read lease verifies manifests before their recorded toolchain is
        # used. Reprobe those compiler/ABI inputs; never replace the dependencies.
        dependency = next(item for item in requires if item.name == 'ngtcp2')
        previous = json.loads(dependency.manifest.read_text(encoding='utf-8'))['inputs']['target']
        settings = previous['cmake']
        option_names = ('CMAKE_C_FLAGS', 'CMAKE_CXX_FLAGS', 'CMAKE_EXE_LINKER_FLAGS',
                        'CMAKE_SHARED_LINKER_FLAGS', 'CMAKE_STATIC_LINKER_FLAGS',
                        'CMAKE_OSX_ARCHITECTURES', 'CMAKE_OSX_SYSROOT', 'CMAKE_OSX_DEPLOYMENT_TARGET',
                        'CMAKE_SYSROOT', 'CMAKE_MSVC_RUNTIME_LIBRARY')
        options = [f'-D{name}={settings[name]}' for name in option_names if name in settings]
        options.extend(recipe.options)
        options.append('-DCMAKE_INSTALL_LIBDIR=lib')
        quote = subprocess.list2cmdline if os.name == 'nt' else shlex.join
        compiler = lambda key: quote([previous[key]['path'], *previous[key].get('arguments', [])])
        target = probe_toolchain(configuration=previous['configuration'],
            c=compiler('c'), cxx=compiler('cxx'), toolchain=settings.get('CMAKE_TOOLCHAIN_FILE'),
            cmake_options=options, environment=previous['environment'], home=root)
        source = fetch_archive('curl', VERSION,
            f'https://github.com/curl/curl/releases/download/curl-{VERSION.replace(".", "_")}/curl-{VERSION}.tar.xz',
            DIGEST, root / 'downloads/curl', offline=args.offline)
        request = BuildRequest(name='curl', source=Path(source['source_dir']), builder=build_curl,
            recipe_input_files=recipe_input_files('curl'), target=target,
            options={'cmake_options': options}, environment=target['environment'], requires=requires,
            artifacts=(*recipe.artifacts, 'bin/curl.exe' if os.name == 'nt' else 'bin/curl'),
            license_files=recipe.license_files, jobs=args.jobs, configuration=previous['configuration'])
        artifact = build_package(request, home=root)
    result = Environment((artifact,))
    with result.lease():
        write_environment(work / 'environment.json', result)
        binary = artifact.prefix / 'bin' / ('curl.exe' if os.name == 'nt' else 'curl')
        version = subprocess.check_output([str(binary), '--version'], text=True, timeout=10)
        if 'HTTP3' not in version:
            raise RuntimeError('Built curl lacks HTTP3 support')
        work.mkdir(parents=True, exist_ok=True)
        (work / 'binary.txt').write_text(str(binary) + '\n', encoding='utf-8')
        print(version)
        print(f'HTTP/3 interop client: {binary}')


if __name__ == '__main__':
    main()
