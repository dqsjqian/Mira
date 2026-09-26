// Mira/core/functional.hpp — the move-only callable the loop posts.
//
// `std::move_only_function` is the right *shape* for posted work: it accepts
// callables capturing move-only state (a `Task`, a socket) that
// `std::function` rejects for not being copyable. It is also one of the last
// C++23 library pieces to ship — and the shipments that exist are uneven:
// Apple Clang and the Android NDK's clang lack the type entirely, and the
// NDK's feature macro advertises it anyway, so `__cpp_lib_move_only_function`
// cannot be trusted as a gate. A macro-gated branch is how a header compiles
// on the desktop and dies on the phone — this library's CI crossed exactly
// that line.
//
// So the library speaks one name everywhere — `mira::move_only_function` —
// and this header provides exactly one backing implementation on every
// platform. No feature detection, no per-toolchain divergence, nothing to
// mispredict. The type is deliberately not a general `std::function`
// replacement: it is exactly what `post()` needs — unique ownership, one
// `operator()`, destroying the target on move-out — and nothing else. Post
// traffic is one allocation per completed operation, not per byte; the loop's
// hot paths live elsewhere.

#pragma once

#include <memory>
#include <type_traits>
#include <utility>

namespace Mira {

/// Move-only callable wrapper, API-compatible with the C++23
/// `std::move_only_function<void()>` for the single use this library makes of
/// it: posting work to the event loop.
template<typename Signature>
class move_only_function;
template<>
class move_only_function<void()> {
public:
    move_only_function() noexcept = default;

    template<typename Callable>
        requires(!std::is_same_v<std::decay_t<Callable>, move_only_function> &&
                 std::is_invocable_v<Callable&>)
    move_only_function(Callable&& target)
        : model_(std::make_unique<Model<std::decay_t<Callable>>>(
              std::forward<Callable>(target))) {}

    move_only_function(move_only_function&&) noexcept = default;
    move_only_function& operator=(move_only_function&&) noexcept = default;
    move_only_function(const move_only_function&) = delete;
    move_only_function& operator=(const move_only_function&) = delete;

    ~move_only_function() = default;

    void operator()() {
        if (model_ != nullptr) model_->invoke();
    }

    explicit operator bool() const noexcept { return model_ != nullptr; }

private:
    struct Concept {
        virtual ~Concept() = default;
        virtual void invoke() = 0;
    };
    template<typename Callable>
    struct Model final : Concept {
        Callable target;
        explicit Model(Callable value) : target(std::move(value)) {}
        void invoke() override { target(); }
    };
    std::unique_ptr<Concept> model_;
};

}  // namespace Mira
