// Artifact Promotion - evidence producing worker over framed TCP.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_WORKER_CLIENT_HPP
#define ARTIFACT_PROMOTION_WORKER_CLIENT_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "artifact_promotion/artifact.hpp"
#include "artifact_promotion/decision.hpp"
#include "artifact_promotion/engine.hpp"
#include "artifact_promotion/evidence.hpp"
#include "artifact_promotion/error.hpp"
#include "artifact_promotion/protocol.hpp"
#include "artifact_promotion/socket.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// WorkerClient
//
// A process bound evidence producer. The client generates a fresh WorkerBootId
// for every connection, so a restarted worker is a new incarnation and its
// previous evidence cannot be mistaken for current authority.
//
// Every call performs a handshake-driven epoch refresh: when the coordinator
// reports a newer epoch the client adopts it before sending the next request,
// which is what lets a worker survive a coordinator restart without inventing
// authority it does not have.
// ---------------------------------------------------------------------------
class WorkerClient {
public:
    struct Options {
        std::uint16_t port = 0;
        WorkerId worker{};  // empty selects a fresh identity
        int connect_attempts = 20;
        std::uint32_t connect_delay_millis = 25;
    };

    explicit WorkerClient(Options options);
    ~WorkerClient();

    WorkerClient(const WorkerClient&) = delete;
    WorkerClient& operator=(const WorkerClient&) = delete;

    [[nodiscard]] Status connect();
    void disconnect();

    [[nodiscard]] bool connected() const noexcept { return connected_; }
    [[nodiscard]] WorkerId worker_id() const noexcept { return worker_; }
    [[nodiscard]] WorkerBootId boot_id() const noexcept { return boot_; }
    [[nodiscard]] CoordinatorId coordinator_id() const noexcept { return coordinator_; }
    [[nodiscard]] CoordinatorEpoch epoch() const noexcept { return epoch_; }

    // Re-runs the handshake. Used after a coordinator restart so the client can
    // adopt the new epoch before its next request.
    [[nodiscard]] Status handshake();

    struct RegisterResult {
        PromotionOutcome outcome = PromotionOutcome::Invalid;
        ArtifactRecord artifact{};
        std::vector<Reason> reasons{};
    };

    [[nodiscard]] Result<ArtifactRecord> register_artifact(const ArtifactRegistration& registration);
    [[nodiscard]] Result<EvidenceRecord> submit_evidence(const EvidenceSubmission& submission);
    [[nodiscard]] Result<PromotionEngine::CommitResult> promote(const PromotionRequest& request);
    [[nodiscard]] Result<PromotionEngine::EvaluationResult> evaluate(const PromotionRequest& request);
    [[nodiscard]] Result<protocol::ArtifactStatePayload> artifact_state(ArtifactId artifact);
    [[nodiscard]] Result<std::vector<PromotionRecord>> history(ArtifactId artifact);
    [[nodiscard]] Result<PromotionEngine::TrustMutation> quarantine(ArtifactId artifact, std::string reason_class,
                                                                  std::string detail);
    [[nodiscard]] Result<PromotionEngine::TrustMutation> revoke(ArtifactId artifact, std::string reason_class,
                                                               std::string detail);
    [[nodiscard]] Result<PromotionDecision> explain(ArtifactId artifact, Stage destination);
    [[nodiscard]] Status request_snapshot_save();

    [[nodiscard]] PromotionRequestId next_request_id();
    [[nodiscard]] PromotionAttemptId next_attempt_id();

    // Round trip count of frames exchanged, for tests that assert a retry did
    // not create a second transition.
    [[nodiscard]] std::uint64_t frames_sent() const noexcept { return frames_sent_; }

private:
    [[nodiscard]] Status exchange(const protocol::Frame& request, protocol::Frame& response);

    Options options_;
    net::Socket socket_;
    bool connected_ = false;
    WorkerId worker_{};
    WorkerBootId boot_{};
    CoordinatorId coordinator_{};
    CoordinatorEpoch epoch_{};
    std::uint64_t frames_sent_ = 0;
    IdentityGenerator<PromotionRequestIdTag> request_generator_;
    IdentityGenerator<PromotionAttemptIdTag> attempt_generator_;
};

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_WORKER_CLIENT_HPP
