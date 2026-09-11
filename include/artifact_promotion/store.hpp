// Artifact Promotion - authoritative coordinator state.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_STORE_HPP
#define ARTIFACT_PROMOTION_STORE_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "artifact_promotion/artifact.hpp"
#include "artifact_promotion/config.hpp"
#include "artifact_promotion/decision.hpp"
#include "artifact_promotion/evidence.hpp"
#include "artifact_promotion/identity.hpp"
#include "artifact_promotion/policy.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// HistoryEventKind
//
// Append-only audit history. Nothing in the runtime deletes a history event:
// a revocation adds an event and leaves the original promotion event in place,
// so historical queries can still show that an artifact was promoted.
// ---------------------------------------------------------------------------
enum class HistoryEventKind : std::uint8_t {
    Invalid = 0,
    ArtifactRegistered = 1,
    ArtifactSupersededRegistration = 2,
    EvidenceSubmitted = 3,
    EvidenceSuperseded = 4,
    EvidenceRevoked = 5,
    PolicyPublished = 6,
    PromotionEvaluated = 7,
    PromotionCommitted = 8,
    PromotionRejected = 9,
    Quarantined = 10,
    QuarantineReleased = 11,
    Revoked = 12,
    Superseded = 13,
    Retired = 14,
    RecoveryNote = 15,
};

[[nodiscard]] const char* to_string(HistoryEventKind kind) noexcept;

struct HistoryEvent {
    CommitSequence sequence{};
    HistoryEventKind kind = HistoryEventKind::Invalid;
    ArtifactId artifact{};
    ArtifactRevision artifact_revision{};
    EvidenceId evidence{};
    PromotionDecisionId decision{};
    PromotionOutcome outcome = PromotionOutcome::Invalid;
    Stage from = Stage::Invalid;
    Stage to = Stage::Invalid;
    CoordinatorAuthority authority{};
    std::string note{};
};

// ---------------------------------------------------------------------------
// PendingTransition
//
// A reservation record. Reservations are keyed by artifact identity AND stage
// generation, so two workers cannot concurrently drive the same artifact
// transition while independent artifacts proceed in parallel.
// ---------------------------------------------------------------------------
struct PendingTransition {
    ReservationId id{};
    ArtifactId artifact{};
    ArtifactRevision artifact_revision{};
    ArtifactGeneration artifact_generation{};
    StageGeneration stage_generation{};
    Stage from = Stage::Invalid;
    Stage to = Stage::Invalid;
    PromotionPlanId plan{};
    PromotionRequestId request{};
    PromotionAttemptId attempt{};
    CoordinatorAuthority authority{};
    CommitSequence created_sequence{};
    std::uint64_t created_unix_millis = 0;
};

// ---------------------------------------------------------------------------
// IdempotencyRecord
//
// Binds (request, attempt) identity to the decision it produced. A retried
// request that is semantically identical returns the original decision rather
// than creating a second transition.
// ---------------------------------------------------------------------------
struct IdempotencyRecord {
    PromotionRequestId request{};
    PromotionAttemptId attempt{};
    PromotionDecisionId decision{};
    PromotionOutcome outcome = PromotionOutcome::Invalid;
    PromotionPlanId plan{};
    Digest request_digest{};
    CommitSequence created_sequence{};
};

// ---------------------------------------------------------------------------
// VetoState
//
// Externally supplied and explicitly cleared. A veto is durable state, not a
// transient hint, and it blocks promotion through a policy gate.
// ---------------------------------------------------------------------------
struct VetoState {
    bool security_veto = false;
    std::string security_reason{};
    bool dependency_veto = false;
    std::string dependency_reason{};
};

// ---------------------------------------------------------------------------
// CoordinatorState
//
// The complete authoritative state of one coordinator. Everything in this
// structure is durable except the identity generators and the transient
// reservation map: the generators resume from persisted counters so a restart
// never reissues an identity, and reservations are rebuilt conservatively on
// load because a reservation held by a dead process is not authority.
// ---------------------------------------------------------------------------
struct CoordinatorState {
    static constexpr std::uint32_t kFormatVersion = 1;

    CoordinatorId coordinator{};
    CoordinatorEpoch epoch{};
    CommitSequence commit_sequence{};
    DecisionSequence decision_sequence{};
    ArtifactGeneration artifact_generation{};
    CompatibilityGeneration compatibility_generation{1};
    CompatibilityProfileId compatibility_profile{};

    PromotionPolicyId active_policy{};
    PolicyGeneration active_policy_generation{};
    Digest active_policy_digest{};

    std::map<ArtifactId, std::vector<ArtifactRecord>> artifacts{};
    std::map<EvidenceId, EvidenceRecord> evidence{};
    std::map<PromotionPlanId, PromotionPlan> plans{};
    std::map<PromotionDecisionId, PromotionDecision> decisions{};
    std::map<TransitionId, PromotionRecord> records{};
    std::map<PromotionRequestId, IdempotencyRecord> idempotency{};
    std::map<CommitSequence, HistoryEvent> history{};
    std::map<ArtifactId, VetoState> vetoes{};

    // Live-only state. Never persisted as authority.
    std::map<ArtifactId, PendingTransition> pending{};

    // Identity generators.
    IdentityGenerator<ArtifactRevisionTag> revision_generator{};
    IdentityGenerator<EvidenceIdTag> evidence_generator{};
    IdentityGenerator<PromotionPlanIdTag> plan_generator{};
    IdentityGenerator<PromotionDecisionIdTag> decision_generator{};
    IdentityGenerator<TransitionIdTag> transition_generator{};
    IdentityGenerator<ReservationIdTag> reservation_generator{};
    IdentityGenerator<ArtifactInstanceIdTag> instance_generator{};
    IdentityGenerator<ProvenanceRefTag> provenance_generator{};
    IdentityGenerator<PromotionRequestIdTag> internal_request_generator{};
    IdentityGenerator<PromotionAttemptIdTag> internal_attempt_generator{};

    [[nodiscard]] const ArtifactRecord* find_current(ArtifactId id) const;
    [[nodiscard]] ArtifactRecord* find_current(ArtifactId id);
    [[nodiscard]] const ArtifactRecord* find_revision(ArtifactId id, ArtifactRevision revision) const;
    [[nodiscard]] ArtifactRecord* find_revision(ArtifactId id, ArtifactRevision revision);

    // The active policy body is held inline alongside its identity so that
    // evaluation never performs a container lookup to find the governing policy.
    void set_active_policy(PromotionPolicy policy);
    [[nodiscard]] const PromotionPolicy& policy() const noexcept { return active_policy_body_; }

    [[nodiscard]] CommitSequence next_sequence() { return commit_sequence = commit_sequence.next(); }
    [[nodiscard]] DecisionSequence next_decision_sequence() {
        return decision_sequence = decision_sequence.next();
    }

    // Request and attempt identities are normally supplied by the caller. When
    // a governed transition (quarantine release) is driven by the coordinator
    // itself, it allocates a request identity here so the transition is still
    // exactly identified and auditable.
    [[nodiscard]] PromotionRequestId next_internal_request() { return internal_request_generator.next(); }
    [[nodiscard]] PromotionAttemptId next_internal_attempt() { return internal_attempt_generator.next(); }

    // Identifies the policy body held in this state. It always equals
    // active_policy; the field exists so a snapshot can be validated without
    // trusting the policy section alone.
    PromotionPolicyId active_policy_id{};

    [[nodiscard]] std::size_t total_evidence() const noexcept { return evidence.size(); }

    // Verifies that the loaded state is internally consistent. Called after a
    // snapshot load so a corrupt or contradictory file is rejected instead of
    // being trusted.
    [[nodiscard]] Status verify_consistency() const;

    // Live reservations. They are never authority after a restart, which is why
    // install_state() clears them and the snapshot writer excludes them.
    [[nodiscard]] std::size_t pending_size() const noexcept { return pending.size(); }

private:
    friend class PromotionEngine;
    friend class StatePersistence;
    PromotionPolicy active_policy_body_{};
};

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_STORE_HPP
