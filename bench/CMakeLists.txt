# Benchmarks — measuring, not guessing
#
# Mira's performance claims need numbers, and the numbers need a way to be
# reproduced. These are in-process benches: server and client coroutines run
# on one event loop (or a small set), so they measure the library's own
# protocol machinery — parsing, framing, allocation churn — not the noise of
# a remote load generator, and they need no external tooling.
#
# In-process also means the numbers are *relative*: compare two commits, not
# Mira against wrk. Use `tools/bench/run.sh` for the blessed invocation.
#
# Two scenarios, chosen because they are what the optimization work targeted:
#   * bench_h1_keepalive — HTTP/1.1 keep-alive small-response request/response
#   * bench_h2_roundtrip — HTTP/2 multiple concurrent streams per connection
#
# Gated behind MIRA_BUILD_BENCH for the same reason the examples are opt-in:
# a consumer pulling Mira in via add_subdirectory() did not ask for our
# measurement binaries.

if(NOT MIRA_BUILD_BENCH)
    return()
endif()

add_executable(bench_h1_keepalive h1_keepalive.cpp)
target_link_libraries(bench_h1_keepalive
    PRIVATE Mira::transport Mira::http Mira::warnings)
target_compile_features(bench_h1_keepalive PRIVATE cxx_std_23)

add_executable(bench_h2_roundtrip h2_roundtrip.cpp)
target_link_libraries(bench_h2_roundtrip
    PRIVATE Mira::transport Mira::http2 Mira::warnings)
target_compile_features(bench_h2_roundtrip PRIVATE cxx_std_23)
