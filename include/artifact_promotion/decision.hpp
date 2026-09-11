// Artifact Promotion - deterministic promotion decisions and explanations.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_DECISION_HPP
#define ARTIFACT_PROMOTION_DECISION_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "artifact_promotion/artifact.hpp"
#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/error.hpp"
#include "artifact_promotion/evidence.hpp"
#include "artifact_promotion/identity.hpp"
#include "artifact_promotion/policy.hpp"
#include "artifact_promotion/sha256.hpp"
#include "artifact_promotion/stage.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// PromotionOutcome
//
// A rejection is never collapsed into false. Each outcome names a distinct
// semantic condition, and the accompanying reasons name the exact gates that
// produced it.
// ---------------------------------------------------------------------------
enum class PromotionOutcome : std::uint8_t {
    Invalid = 0,
    PromotionEligible = 1,
    PromotionCommitted = 2,
    PromotionIneligible = 3,
    RevalidationRequired = 4,
    EvidenceMissing = 5,
    EvidenceStale = 6,
    EvidenceRevoked = 7,
    EvidenceMismatch = 8,
    ArtifactMismatch = 9,
    DigestMismatch = 10,
    TransitionIllegal = 11,
    PolicyStale = 12,
    CompatibilityFailed = 13,
    ApprovalRequired = 14,
    Quarantined = 15,
    Revoked = 16,
    Superseded = 17,
    Conflict = 18,
    AlreadyPromoted = 19,
    OutcomeUnknown = 20,
    Unsupported = 21,
    ArtifactNotFound = 22,
    PolicyNotFound = 23,
    Cancelled = 24,
    AuthorityStale = 25,
    ProvenanceMissing = 26,
    SecurityVeto = 27,
    DependencyVeto = 28,
    AdmissionRejected = 29,
};

[[nodiscard]] const char* to_string(PromotionOutcome outcome) noexcept;
[[nodiscard]] bool is_valid_promotion_outcome(std::uint64_t raw) noexcept;

// A committed or already-committed transition is the only condition under which
// an artifact holds the destination stage as a result of this decision.
[[nodiscard]] inline bool is_success_outcome(PromotionOutcome outcome) noexcept {
    return outcome == PromotionOutcome::PromotionEligible || outcome == PromotionOutcome::PromotionCommitted ||
           outcome == PromotionOutcome::AlreadyPromoted;
}

// ---------------------------------------------------------------------------
// GateStatus
// ---------------------------------------------------------------------------
enum class GateStatus : std::uint8_t {
    NotEvaluated = 0,
    Satisfied = 1,
    Failed = 2,
    Unknown = 3,
    NotApplicable = 4,
};

[[nodiscard]] const char* to_string(GateStatus status) noexcept;

// ---------------------------------------------------------------------------
// GateExplanation
//
// One record per evaluated gate, in the policy declared order. Explanation
// ordering is canonical: it never depends on hash iteration.
// ---------------------------------------------------------------------------
struct GateExplanation {
    GateKind kind = GateKind::Invalid;
    std::string label{};
    GateStatus status = GateStatus::NotEvaluated;
    ErrorCode code = ErrorCode::Ok;
    std::string detail{};

    [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// EvidenceFinding
//
// Structured detail for an evidence related rejection. The finding always names
// the evidence identity and the exact artifact revision and digest it was
// compared against, so an operator can see precisely why it did not apply.
// ---------------------------------------------------------------------------
struct EvidenceFinding {
    EvidenceId id{};
    EvidenceType type = EvidenceType::Invalid;
    std::string custom_type{};
    EvidenceGeneration generation{};
    EvidenceResult result = EvidenceResult::Unknown;
    Digest subject_digest{};
    ArtifactRevision subject_revision{};
    ErrorCode code = ErrorCode::Ok;
    std::string detail{};
};

// ---------------------------------------------------------------------------
// PromotionDecision
// ---------------------------------------------------------------------------
struct PromotionDecision {
    PromotionDecisionId id{};
    PromotionRequestId request{};
    PromotionAttemptId attempt{};
    ArtifactId artifact{};
    ArtifactRevision artifact_revision{};
    ArtifactGeneration artifact_generation{};
    Digest artifact_digest{};
    ArtifactKind artifact_kind = ArtifactKind::Invalid;

    Stage from = Stage::Invalid;
    Stage to = Stage::Invalid;

    PromotionOutcome outcome = PromotionOutcome::Invalid;

    PromotionPolicyId policy{};
    PolicyGeneration policy_generation{};
    Digest policy_digest{};
    CoordinatorAuthority authority{};
    DecisionSequence sequence{};

    Digest evidence_snapshot_digest{};
    std::vector<GateExplanation> gates{};
    std::vector<EvidenceFinding> findings{};
    std::vector<Reason> reasons{};

    PromotionPlanId plan{};

    bool authoritative = false;
    std::optional<std::uint64_t> decided_unix_millis;

    [[nodiscard]] bool eligible() const noexcept { return outcome == PromotionOutcome::PromotionEligible; }
    [[nodiscard]] bool committed() const noexcept { return outcome == PromotionOutcome::PromotionCommitted; }
    [[nodiscard]] bool succeeded() const noexcept { return is_success_outcome(outcome); }

    [[nodiscard]] std::size_t failed_gate_count() const noexcept;
    [[nodiscard]] std::vector<std::string> failed_gate_labels() const;
    [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// PromotionRequest
// ---------------------------------------------------------------------------
struct PromotionRequest {
    ArtifactId artifact{};
    ArtifactRevision expected_revision{};
    Digest expected_digest{};
    Stage requested_stage = Stage::Invalid;

    PromotionRequestId request{};
    PromotionAttemptId attempt{};
    CoordinatorAuthority authority{};

    ProducerIncarnation requester{};

    bool operator==(const PromotionRequest& other) const noexcept {
        return artifact == other.artifact && expected_revision == other.expected_revision &&
               expected_digest == other.expected_digest && requested_stage == other.requested_stage;
    }
};

// ---------------------------------------------------------------------------
// PromotionPlan
//
// A positive eligibility evaluation does not itself authorize a lifecycle
// mutation. The plan is the authority carrier: it names every component whose
// change invalidates it, and it must be revalidated immediately before commit.
// ---------------------------------------------------------------------------
struct PromotionPlan {
    PromotionPlanId id{};
    PromotionRequestId request{};
    PromotionAttemptId attempt{};
    PromotionDecisionId decision{};

    ArtifactId artifact{};
    ArtifactRevision artifact_revision{};
    ArtifactGeneration artifact_generation{};
    Digest artifact_digest{};
    ArtifactKind artifact_kind = ArtifactKind::Invalid;

    Stage from = Stage::Invalid;
    Stage to = Stage::Invalid;
    StageGeneration stage_generation{};

    PromotionPolicyId policy{};
    PolicyGeneration policy_generation{};
    Digest policy_digest{};
    Digest lifecycle_digest{};

    CoordinatorAuthority authority{};

    Digest evidence_snapshot_digest{};
    std::size_t evidence_entry_count = 0;

    CompatibilityProfileId compatibility_profile{};
    CompatibilityGeneration compatibility_generation{};

    CommitSequence artifact_sequence{};
    CommitSequence created_sequence{};
    DecisionSequence decision_sequence{};

    bool has_expiry = false;
    std::uint64_t expires_unix_millis = 0;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] std::string render() const;

    // Field-by-field equality over every authority-bearing component. Used to
    // reject a plan that was not issued by this coordinator, or one that has
    // been altered in transit.
    [[nodiscard]] bool operator==(const PromotionPlan& other) const noexcept {
        return id == other.id && request == other.request && attempt == other.attempt &&
               decision == other.decision && artifact == other.artifact &&
               artifact_revision == other.artifact_revision && artifact_generation == other.artifact_generation &&
               artifact_digest == other.artifact_digest && artifact_kind == other.artifact_kind &&
               from == other.from && to == other.to && stage_generation == other.stage_generation &&
               policy == other.policy && policy_generation == other.policy_generation &&
               policy_digest == other.policy_digest && lifecycle_digest == other.lifecycle_digest &&
               authority == other.authority &&
               evidence_snapshot_digest == other.evidence_snapshot_digest &&
               evidence_entry_count == other.evidence_entry_count &&
               compatibility_profile == other.compatibility_profile &&
               compatibility_generation == other.compatibility_generation &&
               artifact_sequence == other.artifact_sequence && created_sequence == other.created_sequence &&
               decision_sequence == other.decision_sequence && has_expiry == other.has_expiry &&
               expires_unix_millis == other.expires_unix_millis;
    }
};

// ---------------------------------------------------------------------------
// PromotionRecord
//
// The durable audit record of a committed transition. It is append-only: a
// revocation or supersession adds a new record and never rewrites history.
// ---------------------------------------------------------------------------
struct PromotionRecord {
    TransitionId transition{};
    ArtifactId artifact{};
    ArtifactRevision artifact_revision{};
    Digest artifact_digest{};

    Stage from = Stage::Invalid;
    Stage to = Stage::Invalid;

    PromotionDecisionId decision{};
    PromotionPlanId plan{};
    PromotionRequestId request{};
    PromotionAttemptId attempt{};

    PromotionPolicyId policy{};
    PolicyGeneration policy_generation{};
    CoordinatorAuthority authority{};
    Digest evidence_snapshot_digest{};

    CommitSequence sequence{};
    std::uint64_t committed_unix_millis = 0;
    std::string note{};

    [[nodiscard]] bool valid() const noexcept;
};

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_DECISION_HPP
