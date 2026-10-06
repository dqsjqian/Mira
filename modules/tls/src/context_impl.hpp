#pragma once

#include "mira/tls/context.hpp"

#include <openssl/ssl.h>

#include <array>
#include <mutex>
#include <string>
#include <vector>

namespace Mira::tls {

struct ContextDeleter {
    void operator()(SSL_CTX* handle) const noexcept { SSL_CTX_free(handle); }
};
using ContextHandle = std::unique_ptr<SSL_CTX, ContextDeleter>;

// Immutable after publication; Engine retains callbacks and all candidate identities.
struct ContextSnapshot {
    struct NamedIdentity {
        std::string hostname;
        ContextHandle handle;
        std::array<unsigned char, 32> session_scope{};
    };
    ContextHandle handle;
    std::array<unsigned char, 32> session_scope{};
    std::vector<NamedIdentity> identities;
    Context::SniPolicy unknown_sni{Context::SniPolicy::use_default};
    Context::SniPolicy missing_sni{Context::SniPolicy::use_default};
    Context::OcspPolicy ocsp{Context::OcspPolicy::disabled};
};

struct OcspWireState {
    bool seen = false;
    bool invalid = false;
};
Result<void> track_peer_ocsp(SSL* ssl, OcspWireState& state) noexcept;
bool verify_peer_ocsp(SSL* ssl, Context::OcspPolicy policy) noexcept;

struct Context::Impl {
    mutable std::mutex mutex;
    std::shared_ptr<const ContextSnapshot> snapshot;
    bool client = false;

    std::shared_ptr<const ContextSnapshot> load_snapshot() const {
        std::lock_guard lock(mutex);
        return snapshot;
    }
    void publish(std::shared_ptr<const ContextSnapshot> replacement) {
        {
            std::lock_guard lock(mutex);
            snapshot.swap(replacement);
        }
        // Destroy retired snapshots outside the lock; never lock around file I/O or callbacks.
    }
};

}  // namespace Mira::tls
