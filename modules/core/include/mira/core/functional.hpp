// Mira/core/functional.hpp — the move-only callable the loop posts.
//
// `std::move_only_function` is the right type for posted work: it accepts
// callables capturing move-only state (a `Task`, a socket) that
// `std::function` rejects for not being copyable. It is also one of the
// last C++23 library pieces to ship: Apple Clang (Xcode 26) and the
// Android NDK's clang still lack it while otherwise implementing the
// language level this library requires.
//
// So the library speaks one name everywhere — `mira::MoveOnlyFunction` —
// and this header decides what backs it: the standard type when the
// toolchain has it, a small equivalent when it does not. The fallback is
// deliberately not a general `std::function` replacement: it is exactly
// what `post()` needs — unique ownership, one operator(), destroying the
// target on move-out — and nothing else.

#pragma once

#include <functional>
#include <memory>
#include <utility>

namespace Mira {

#if defined(__cpp_lib_move_only_function)
using std::move_only_function;
#else
/// Move-only callable wrapper, API-compatible with the C++23
/// `std::move_only_function<void()>` for the single use this library
/// makes of it: posting work to the event loop.
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
        : model_(std::make_unique<Model<Callable>>(std::forward<Callable>(target))) {}

    move_only_function(move_only_function&&) noexcept = default;
    move_only_function& operator=(move_only_function&&) noexcept = default;
    move_only_function(const move_only_function&) = delete;
    move_only_function& operator=(const move_only_function&) = delete;

    void operator()() {
        if (model_) model_->invoke();
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
#endif

}  // namespace Mira
