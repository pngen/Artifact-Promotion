// Artifact Promotion - authoritative coordinator over framed TCP.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_COORDINATOR_SERVER_HPP
#define ARTIFACT_PROMOTION_COORDINATOR_SERVER_HPP

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "artifact_promotion/config.hpp"
#include "artifact_promotion/engine.hpp"
#include "artifact_promotion/error.hpp"
#include "artifact_promotion/persistence.hpp"
#include "artifact_promotion/protocol.hpp"
#include "artifact_promotion/socket.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// CoordinatorServer
//
// Owns the authoritative PromotionEngine plus the durable snapshot it writes on
// every committed mutation. It serves the framed protocol on the loopback
// interface only.
//
// Authority rules enforced at the transport boundary:
//   * a request addressed to a different coordinator identity is rejected;
//   * a request carrying a stale coordinator epoch is rejected, except for the
//     handshake, which exists so a restarted worker can learn the new epoch;
//   * a worker boot identity that is older than the boot already registered for
//     that worker is rejected, so a killed worker cannot resume its authority;
//   * a request identity already seen on the same connection is rejected as a
//     duplicate rather than executed twice.
// ---------------------------------------------------------------------------
class CoordinatorServer {
public:
    struct Options {
        std::uint16_t port = 0;  // 0 selects an ephemeral port
        std::string state_path{};  // empty disables durable snapshots
        EngineConfig engine{};
        int backlog = 16;
        std::uint32_t connection_receive_timeout_millis = 250;
    };

    explicit CoordinatorServer(Options options);
    ~CoordinatorServer();

    CoordinatorServer(const CoordinatorServer&) = delete;
    CoordinatorServer& operator=(const CoordinatorServer&) = delete;

    // Loads durable state when a state path is configured. A corrupt snapshot is
    // rejected; the server never silently starts from an empty state.
    [[nodiscard]] Status start();

    // Stops admission, drains connections, joins every connection thread, and
    // writes a final snapshot of the state that actually crossed a durable
    // boundary.
    void stop();

    [[nodiscard]] std::uint16_t port() const noexcept { return listener_.bound_port(); }
    [[nodiscard]] PromotionEngine& engine() noexcept { return engine_; }
    [[nodiscard]] const PromotionEngine& engine() const noexcept { return engine_; }
    [[nodiscard]] bool running() const noexcept { return running_.load(); }
    [[nodiscard]] std::size_t active_connections() const noexcept { return active_connections_.load(); }

    // Test and diagnostic hooks: the number of requests rejected because their
    // authority was stale.
    [[nodiscard]] std::uint64_t stale_authority_rejections() const noexcept {
        return stale_authority_rejections_.load();
    }
    [[nodiscard]] std::uint64_t duplicate_request_rejections() const noexcept {
        return duplicate_request_rejections_.load();
    }
    [[nodiscard]] std::uint64_t protocol_rejections() const noexcept { return protocol_rejections_.load(); }

    // Persists the current authoritative state. Returns an error when no state
    // path is configured.
    [[nodiscard]] Status persist_now();

private:
    void accept_loop();
    void serve_connection(net::Socket socket);
    [[nodiscard]] Status handle_frame(const protocol::Frame& request, protocol::Frame& response);
    [[nodiscard]] Status register_worker_boot(WorkerId worker, WorkerBootId boot);

    Options options_;
    PromotionEngine engine_;
    net::Listener listener_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<std::size_t> active_connections_{0};
    std::atomic<std::uint64_t> stale_authority_rejections_{0};
    std::atomic<std::uint64_t> duplicate_request_rejections_{0};
    std::atomic<std::uint64_t> protocol_rejections_{0};
    std::thread accept_thread_;
    std::mutex connections_mutex_;
    std::vector<std::thread> connection_threads_;
    std::mutex persist_mutex_;
    std::mutex workers_mutex_;
    std::map<WorkerId, WorkerBootId> worker_boots_;
};

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_COORDINATOR_SERVER_HPP
