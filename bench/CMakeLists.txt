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
# Scenarios, chosen because they are what the optimization work targeted:
#   * bench_h1_keepalive — HTTP/1.1 keep-alive small-response request/response
#   * bench_h2_roundtrip — HTTP/2 multiple concurrent streams per connection
#   * bench_h1_churn     — full connection lifetime (accept/serve/close)
#   * bench_h1_cancel    — deadline and stop-token cancellation overhead
#   * bench_h1_overload  — backpressure: 4 KiB bodies through a 512 B window

if(NOT MIRA_BUILD_BENCH)
    return()
endif()

# bench_h2_roundtrip needs nghttp2; without it the bench set degrades to the
# HTTP/1.1 scenarios with a note, rather than failing the whole configure.
if(NOT TARGET Mira::http2)
    message(STATUS
        "Mira bench: MIRA_ENABLE_HTTP2 is off — skipping bench_h2_roundtrip "
        "(tools/bench/run.sh configures it for you)")
else()
    add_executable(bench_h2_roundtrip h2_roundtrip.cpp)
    target_link_libraries(bench_h2_roundtrip
        PRIVATE Mira::transport Mira::http2 Mira::warnings)
    target_compile_features(bench_h2_roundtrip PRIVATE cxx_std_23)
endif()

add_executable(bench_h1_keepalive h1_keepalive.cpp)
target_link_libraries(bench_h1_keepalive
    PRIVATE Mira::transport Mira::http Mira::warnings)
target_compile_features(bench_h1_keepalive PRIVATE cxx_std_23)

add_executable(bench_h1_churn h1_churn.cpp)
target_link_libraries(bench_h1_churn
    PRIVATE Mira::transport Mira::http Mira::warnings)
target_compile_features(bench_h1_churn PRIVATE cxx_std_23)

add_executable(bench_h1_cancel h1_cancel.cpp)
target_link_libraries(bench_h1_cancel
    PRIVATE Mira::http Mira::warnings)
target_compile_features(bench_h1_cancel PRIVATE cxx_std_23)

add_executable(bench_h1_overload h1_overload.cpp)
target_link_libraries(bench_h1_overload
    PRIVATE Mira::transport Mira::http Mira::warnings)
target_compile_features(bench_h1_overload PRIVATE cxx_std_23)
