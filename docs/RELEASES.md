# Versions and release consumption / 版本与发布

The single source of the library version is `project(Mira VERSION ...)` in
[CMakeLists.txt](../CMakeLists.txt). CMake generates `mira/core/version.hpp`,
the installed package version and each compiled module's version from it.
Do not maintain a second current-version number in documentation or CI paths.

库版本只在根目录 CMake 中定义；头文件、安装包和编译模块均从它生成。
本文集中维护消费方式与兼容规则，README 不重复保存版本号或源码包哈希。
[CHANGELOG](../CHANGELOG.md) 中的版本标题保留发布与开发历史。

## Compatibility

Mira follows semantic versioning for source compatibility: breaking public API
changes increment the major version. Installed CMake packages use
`SameMajorVersion`; `EXACT` requests require an exact version. Rebuild all
consumers when changing SDKs: this policy does not promise a stable binary ABI.
Historical pre-stable releases used minor-version compatibility instead.

Protocol versions, dependency pins and compiler requirements are separate from
the library version. They must not be changed during a library version bump.

## Choosing and pinning a release

Use the [published Releases](https://github.com/dqsjqian/Mira/releases) to select
a tag, its source archive and its SHA256 checksum. Pin that selection in your
application's dependency lock file; do not use a moving `main` or `latest` URL
as a reproducible build input. Read the README and API at the selected tag.

The archive checksum lives in the Release's `SHA256SUMS` asset and release
notes. Keeping it outside the source archive avoids a self-referential checksum
and duplicate pins across translated READMEs.

For an application that defines `my_app`, set `MIRA_SOURCE_URL` and
`MIRA_SOURCE_SHA256` from its lock file before including this CMake fragment:

```cmake
include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
set(MIRA_BUILD_TESTS OFF CACHE BOOL "Build Mira tests" FORCE)
set(MIRA_BUILD_EXAMPLES OFF CACHE BOOL "Build Mira examples" FORCE)
FetchContent_Declare(Mira
    URL "${MIRA_SOURCE_URL}"
    URL_HASH "SHA256=${MIRA_SOURCE_SHA256}"
)
FetchContent_MakeAvailable(Mira)
target_link_libraries(my_app PRIVATE Mira::transport Mira::http)
```

Alternatively, verify and extract the archive outside CMake, then use
`add_subdirectory(vendor/Mira)`. Installed SDK consumers keep their desired
version in the application's same dependency lock file:

```cmake
find_package(Mira ${MIRA_REQUIRED_VERSION} EXACT REQUIRED COMPONENTS core transport http)
target_link_libraries(my_app PRIVATE Mira::transport Mira::http)
```

## Release verification

Prepare version and changelog changes, compile the installed SDK consumer, and
push the candidate commit. Check every CI job and review warnings. Code, build
configuration and verification-tool changes require a successful run for that
candidate before tagging and publishing. A follow-up changing only Markdown
may reuse that passing run: verify the complete diff contains only Markdown
files and record both the tested commit and the release commit in the notes.

Package the tagged source tree, attach the archive and `SHA256SUMS`, then
download and verify both. Release notes link the successful CI run and describe
remaining validation limits. A historical run does not certify later code or
build changes.

For redistribution, review [third-party notices](../THIRD_PARTY_NOTICES.md).
The source archive does not bundle external dependency implementations. Binary
packages that include them must retain their applicable licenses and notices,
including embedded components; Mira's MIT license does not replace those terms.
