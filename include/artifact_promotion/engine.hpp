// Artifact Promotion - promotion evaluation, authority, and transactional commit.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_ENGINE_HPP
#define ARTIFACT_PROMOTION_ENGINE_HPP

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

#include "artifact_promotion/artifact.hpp"
#include "artifact_promotion/config.hpp"
#include "artifact_promotion/decision.hpp"
#include "artifact_promotion/evidence.hpp"
#include "artifact_promotion/policy.hpp"
#include "artifact_promotion/store.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// PromotionEngine
//
// The authoritative promotion gate. It owns artifact promotion identity,
// lifecycle stage, evidence applicability, policy generation, promotion
// authority, reservations, the durable commit, and restart recovery. It does
// not own artifact bytes, builds, experiments, deployment rollouts, or
// research provenance.
//
// Concurrency contract
// --------------------
// Readers (inspect, evaluate, list) take a shared lock on the state. Mutations
// take an exclusive lock on the state while holding the commit gate. The
// pending reservation map has its own mutex, always acquired while the state
// lock is already held, establishing one documented lock order:
//
//     state_mutex_  ->  pending_mutex_  ->  store_mutex_
//
// No callback is ever invoked while a lock is held: the change notification
// runs after the state lock has been released, so a subscriber that calls back
// into the engine cannot deadlock.
// ---------------------------------------------------------------------------
class PromotionEngine {
public:
    using Clock = std::uint64_t;  // unix epoch milliseconds

    explicit PromotionEngine(EngineConfig config = EngineConfig::defaults(),
                             CoordinatorEpoch epoch = CoordinatorEpoch(1));
    ~PromotionEngine();

    PromotionEngine(const PromotionEngine&) = delete;
    PromotionEngine& operator=(const PromotionEngine&) = delete;

    // -----------------------------------------------------------------------
    // Lifecycle of the engine itself
    // -----------------------------------------------------------------------

    // Installs a policy revision and advances the policy generation. Every
    // outstanding plan built on the previous generation is invalidated.
    Result<PolicyGeneration> publish_policy(PromotionPolicy policy);

    // Advances the coordinator epoch. Every plan issued under the previous
    // epoch is fenced and must be revalidated before it can commit.
    Result<CoordinatorEpoch> restart(CoordinatorEpoch epoch);

    // Records a conservative recovery note for any transition that was in
    // flight when the previous coordinator stopped. Returns the number of
    // reservations released. It never promotes anything and never guesses an
    // uncertain commit.
    std::size_t recover_in_flight();

    // -----------------------------------------------------------------------
    // Registration and evidence
    // -----------------------------------------------------------------------
    Result<ArtifactRecord> register_artifact(const ArtifactRegistration& registration);
    Result<EvidenceRecord> submit_evidence(const EvidenceSubmission& submission);

    // -----------------------------------------------------------------------
    // Inspection
    // -----------------------------------------------------------------------
    struct ArtifactView {
        ArtifactRecord artifact{};
        std::size_t evidence_count = 0;
        std::size_t promotion_record_count = 0;
        bool has_active_reservation = false;
    };

    std::optional<ArtifactView> inspect_artifact(ArtifactId id) const;
    std::optional<ArtifactRecord> inspect_revision(ArtifactId id, ArtifactRevision revision) const;
    std::optional<EvidenceRecord> inspect_evidence(EvidenceId id) const;
    std::optional<PromotionDecision> inspect_decision(PromotionDecisionId id) const;
    std::optional<PromotionPlan> inspect_plan(PromotionPlanId id) const;

    std::vector<PromotionRecord> promotion_history(ArtifactId id) const;
    std::vector<HistoryEvent> artifact_history(ArtifactId id, std::size_t limit) const;
    std::vector<EvidenceRecord> evidence_for(ArtifactId id, ArtifactRevision revision) const;
    std::optional<PendingTransition> pending_transition(ArtifactId id) const;

    // Rollback eligibility. A previously promoted artifact is not
    // automatically safe to restore: the active policy must allow rollback for
    // its promoted revision and the artifact must still satisfy the gates.
    struct RollbackEligibility {
        bool eligible = false;
        PromotionOutcome outcome = PromotionOutcome::Invalid;
        std::vector<std::string> blocking_gates{};
        [[nodiscard]] std::string render() const;
    };
    RollbackEligibility evaluate_rollback_eligibility(ArtifactId id) const;

    // -----------------------------------------------------------------------
    // Promotion
    // -----------------------------------------------------------------------
    struct EvaluationResult {
        PromotionDecision decision{};
        PromotionPlan plan{};
        bool has_plan = false;
    };

    // Evaluates hard gates and, when eligible, issues a promotion plan. A
    // positive eligibility evaluation does not itself mutate lifecycle state.
    Result<EvaluationResult> evaluate(const PromotionRequest& request);

    struct CommitResult {
        PromotionOutcome outcome = PromotionOutcome::Invalid;
        PromotionDecision decision{};
        PromotionRecord record{};
        bool has_record = false;
    };

    // Revalidates the plan against current authority and durably commits the
    // transition. Success is never acknowledged before the commit is durable.
    Result<CommitResult> commit(const PromotionPlan& plan);

    // Evaluates and commits in one governed transaction.
    Result<CommitResult> promote(const PromotionRequest& request);

    // -----------------------------------------------------------------------
    // Trust mutation
    // -----------------------------------------------------------------------
    struct TrustMutation {
        PromotionOutcome outcome = PromotionOutcome::Invalid;
        ArtifactRecord artifact{};
        PromotionRecord record{};
        bool has_record = false;
        std::vector<Reason> reasons{};
    };

    Result<TrustMutation> quarantine(ArtifactId id, std::string reason_class, std::string detail,
                                     CoordinatorAuthority authority);
    Result<TrustMutation> release_quarantine(ArtifactId id, CoordinatorAuthority authority);
    Result<TrustMutation> revoke(ArtifactId id, PromotionDecisionId decision, std::string reason_class,
                                 std::string detail, CoordinatorAuthority authority, EvidenceId cause = EvidenceId{});
    Result<TrustMutation> supersede(ArtifactId id, ArtifactId successor, std::string reason,
                                    CoordinatorAuthority authority);
    Result<TrustMutation> retire(ArtifactId id, CoordinatorAuthority authority);
    Result<TrustMutation> revoke_evidence(EvidenceId id, std::string reason, CoordinatorAuthority authority);

    Status set_security_veto(ArtifactId id, bool active, std::string reason);
    Status set_dependency_veto(ArtifactId id, bool active, std::string reason);
    Result<CompatibilityGeneration> set_compatibility_generation(CompatibilityGeneration generation);

    // -----------------------------------------------------------------------
    // Explanation
    // -----------------------------------------------------------------------
    // Re-derives the current decision for a requested destination without
    // issuing a plan and without mutating state, so an operator can ask "why".
    std::optional<PromotionDecision> explain(ArtifactId id, Stage destination) const;

    // -----------------------------------------------------------------------
    // Persistence-facing access
    // -----------------------------------------------------------------------
    // Returns a copy of the authoritative state. Transient reservations are
    // excluded because a reservation held by a dead process is not authority.
    CoordinatorState snapshot() const;

    // Installs state restored from a durable snapshot. Outstanding plans bound
    // to a previous epoch are not authority afterwards.
    Status install_state(CoordinatorState state);

    CoordinatorAuthority authority() const;
    EngineConfig config() const;
    CoordinatorId coordinator_id() const;

    // Registered callback invoked after a mutation completes, with no engine
    // lock held. The reference deployment uses it to persist snapshots.
    using ChangeListener = std::function<void()>;
    void set_change_listener(ChangeListener listener);

    // Admission control used by shutdown.
    void close_admission();
    void open_admission();
    bool admission_open() const;

    // -----------------------------------------------------------------------
    // Invariant checking
    // -----------------------------------------------------------------------
    Status check_invariants() const;
    std::size_t count_pending_transitions() const;
    std::size_t count_artifacts() const;
    std::size_t count_evidence() const;

    static Clock now_millis() noexcept;

private:
    struct GateOutcome {
        PromotionOutcome outcome = PromotionOutcome::PromotionIneligible;
        bool failed = false;
    };

    // Gate evaluation reads canonical state and never mutates it. It is a
    // const operation so both the mutation path and the read-only explanation
    // path share exactly one implementation of the policy semantics.
    GateOutcome evaluate_gates(const CoordinatorState& state, const PromotionRequest& request, std::uint64_t now,
                               PromotionDecision& decision,
                               std::vector<EvidenceSnapshotEntry>& snapshot_entries) const;

    void notify_change();

    EngineConfig config_;
    mutable std::shared_mutex state_mutex_;
    mutable std::shared_mutex store_mutex_;
    // Guards the durable-write path so two mutations never interleave a
    // snapshot write. Always acquired after state_mutex_.
    mutable std::shared_mutex persist_mutex_;
    CoordinatorState state_;
    bool admission_open_ = true;
    // Durable-write bookkeeping. A mutation only has to guarantee that the
    // state it produced, or a later one, eventually reaches disk.
    std::uint64_t persist_epoch_ = 0;
    std::uint64_t persist_clean_epoch_ = 0;
    ChangeListener listener_{};
};

// ---------------------------------------------------------------------------
// Canonical request digest
//
// Binds request identity to the exact semantic content of a promotion request
// so a retried request with the same identity and content returns the committed
// result, while the same identity carrying different content is a conflict
// rather than a silent second transition.
// ---------------------------------------------------------------------------
[[nodiscard]] Digest compute_request_digest(const PromotionRequest& request);

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_ENGINE_HPP
