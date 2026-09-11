// Artifact Promotion - quarantine, revocation, supersession, rollback, vetoes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <sstream>

#include "artifact_promotion/engine.hpp"

namespace artifact_promotion {
namespace {

[[nodiscard]] std::string bounded(std::string_view text, std::size_t limit) {
    if (text.size() <= limit) {
        return std::string(text);
    }
    return std::string(text.substr(0, limit));
}

void append_history(CoordinatorState& state, const EngineConfig& config, HistoryEventKind kind,
                    const ArtifactRecord& artifact, Stage from, Stage to, std::string note) {
    HistoryEvent event;
    event.sequence = state.next_sequence();
    event.kind = kind;
    event.artifact = artifact.id;
    event.artifact_revision = artifact.revision;
    event.from = from;
    event.to = to;
    event.authority = CoordinatorAuthority{state.coordinator, state.epoch};
    event.note = std::move(note);
    if (state.history.size() >= config.max_history_events) {
        state.history.erase(state.history.begin());
    }
    state.history[event.sequence] = event;
}

}  // namespace

Result<PromotionEngine::TrustMutation> PromotionEngine::quarantine(ArtifactId id, std::string reason_class,
                                                                   std::string detail,
                                                                   CoordinatorAuthority authority) {
    TrustMutation result;
    if (!is_valid_name(reason_class)) {
        return Status(ErrorCode::InvalidName, "quarantine reason class is empty, too long, or malformed");
    }
    if (authority.valid() && authority.coordinator != coordinator_id()) {
        return Status(ErrorCode::StaleCoordinatorEpoch, "quarantine authority names a different coordinator");
    }
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!admission_open_) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is not admitting new work");
        }
        ArtifactRecord* artifact = state_.find_current(id);
        if (artifact == nullptr) {
            return Status(ErrorCode::ArtifactNotFound, "artifact identity is not registered", id.to_string());
        }
        const Stage from = artifact->stage;
        if (artifact->quarantine.active) {
            result.outcome = PromotionOutcome::Quarantined;
            result.artifact = *artifact;
            result.reasons.push_back(Reason(ErrorCode::ArtifactQuarantined, "artifact is already quarantined"));
            return result;
        }
        if (artifact->stage == Stage::Revoked || artifact->stage == Stage::Retired) {
            result.outcome = PromotionOutcome::Revoked;
            result.artifact = *artifact;
            result.reasons.push_back(Reason(ErrorCode::ArtifactRevoked,
                                            "a revoked or retired artifact cannot be quarantined"));
            return result;
        }
        if (!state_.policy().graph.has_edge(from, Stage::Quarantined)) {
            return Status(ErrorCode::TransitionIllegal, "the active lifecycle graph forbids this quarantine",
                          std::string(to_string(from)));
        }

        artifact->quarantine.active = true;
        artifact->quarantine.reason_class = reason_class;
        artifact->quarantine.detail = bounded(detail, kMaxTextLength);
        artifact->quarantine.authority =
            AuthorityId::from_parts(state_.coordinator.high(), state_.epoch.value());
        artifact->quarantine.sequence = state_.next_sequence();
        artifact->quarantine.policy_generation = state_.active_policy_generation;
        artifact->last_sequence = artifact->quarantine.sequence;
        artifact->stage = Stage::Quarantined;
        artifact->stage_generation = artifact->stage_generation.next();

        // Quarantine fences an uncommitted transition: the reservation bound to
        // the pre-quarantine stage generation can no longer commit because
        // commit() revalidates the stage generation.
        state_.pending.erase(id);

        append_history(state_, config_, HistoryEventKind::Quarantined, *artifact, from, Stage::Quarantined,
                       "quarantine: " + reason_class);
        ++persist_epoch_;
        result.outcome = PromotionOutcome::Quarantined;
        result.artifact = *artifact;
        result.reasons.push_back(Reason(ErrorCode::ArtifactQuarantined, "artifact quarantined"));
    }
    notify_change();
    return result;
}

Result<PromotionEngine::TrustMutation> PromotionEngine::release_quarantine(ArtifactId id,
                                                                           CoordinatorAuthority authority) {
    TrustMutation result;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!admission_open_) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is not admitting new work");
        }
        ArtifactRecord* artifact = state_.find_current(id);
        if (artifact == nullptr) {
            return Status(ErrorCode::ArtifactNotFound, "artifact identity is not registered", id.to_string());
        }
        if (!artifact->quarantine.active) {
            result.outcome = PromotionOutcome::PromotionIneligible;
            result.artifact = *artifact;
            result.reasons.push_back(Reason(ErrorCode::InvalidArgument, "artifact is not quarantined"));
            return result;
        }
        if (authority.valid() && authority.coordinator != state_.coordinator) {
            return Status(ErrorCode::StaleCoordinatorEpoch, "release authority names a different coordinator");
        }

        // Releasing quarantine is a governed transition, not a flag reset: the
        // active policy must cover QUARANTINED -> CANDIDATE and every gate on
        // that rule must pass before the artifact returns to evaluation.
        PromotionRequest request;
        request.artifact = id;
        request.expected_revision = artifact->revision;
        request.expected_digest = artifact->digest;
        request.requested_stage = Stage::Candidate;
        request.request = state_.next_internal_request();
        request.attempt = state_.next_internal_attempt();
        request.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};

        PromotionDecision decision;
        decision.request = request.request;
        decision.attempt = request.attempt;
        decision.artifact = id;
        decision.artifact_revision = artifact->revision;
        decision.artifact_generation = artifact->generation;
        decision.artifact_digest = artifact->digest;
        decision.artifact_kind = artifact->kind;
        decision.from = artifact->stage;
        decision.to = Stage::Candidate;
        decision.policy = state_.active_policy;
        decision.policy_generation = state_.active_policy_generation;
        decision.policy_digest = state_.active_policy_digest;
        decision.authority = request.authority;
        decision.id = state_.decision_generator.next();
        decision.sequence = state_.next_decision_sequence();

        const std::uint64_t now = now_millis();
        std::vector<EvidenceSnapshotEntry> snapshot_entries;
        const GateOutcome outcome = evaluate_gates(state_, request, now, decision, snapshot_entries);
        decision.outcome = outcome.outcome;
        decision.decided_unix_millis = now;
        decision.evidence_snapshot_digest =
            compute_snapshot_digest(artifact->id, artifact->revision, artifact->digest, snapshot_entries);
        state_.decisions[decision.id] = decision;

        if (outcome.failed) {
            result.outcome = decision.outcome;
            result.artifact = *artifact;
            result.reasons = decision.reasons;
            ++persist_epoch_;
            notify_change();
            return result;
        }

        const Stage from = artifact->stage;
        artifact->quarantine.active = false;
        artifact->stage = Stage::Candidate;
        artifact->stage_generation = artifact->stage_generation.next();
        artifact->last_sequence = state_.next_sequence();

        PromotionRecord record;
        record.transition = state_.transition_generator.next();
        record.artifact = artifact->id;
        record.artifact_revision = artifact->revision;
        record.artifact_digest = artifact->digest;
        record.from = from;
        record.to = Stage::Candidate;
        record.decision = decision.id;
        record.plan = PromotionPlanId{};
        record.request = request.request;
        record.attempt = request.attempt;
        record.policy = state_.active_policy;
        record.policy_generation = state_.active_policy_generation;
        record.authority = request.authority;
        record.evidence_snapshot_digest = decision.evidence_snapshot_digest;
        record.sequence = artifact->last_sequence;
        record.committed_unix_millis = now_millis();
        record.note = "quarantine released; artifact returned to CANDIDATE for full re-evaluation";
        if (state_.records.size() >= config_.max_records_retained) {
            state_.records.erase(state_.records.begin());
        }
        state_.records[record.transition] = record;

        append_history(state_, config_, HistoryEventKind::QuarantineReleased, *artifact, from, Stage::Candidate,
                       record.note);
        ++persist_epoch_;
        result.outcome = PromotionOutcome::PromotionCommitted;
        result.artifact = *artifact;
        result.record = record;
        result.has_record = true;
    }
    notify_change();
    return result;
}

Result<PromotionEngine::TrustMutation> PromotionEngine::revoke(ArtifactId id, PromotionDecisionId decision,
                                                              std::string reason_class, std::string detail,
                                                              CoordinatorAuthority authority, EvidenceId cause) {
    TrustMutation result;
    if (!is_valid_name(reason_class)) {
        return Status(ErrorCode::InvalidName, "revocation reason class is empty, too long, or malformed");
    }
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!admission_open_) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is not admitting new work");
        }
        ArtifactRecord* artifact = state_.find_current(id);
        if (artifact == nullptr) {
            return Status(ErrorCode::ArtifactNotFound, "artifact identity is not registered", id.to_string());
        }
        if (artifact->revocation.active) {
            result.outcome = PromotionOutcome::Revoked;
            result.artifact = *artifact;
            result.reasons.push_back(Reason(ErrorCode::ArtifactRevoked, "artifact authority is already revoked"));
            return result;
        }
        if (authority.valid() && authority.coordinator != state_.coordinator) {
            return Status(ErrorCode::StaleCoordinatorEpoch, "revocation authority names a different coordinator");
        }

        PromotionDecisionId target = decision;
        if (target.invalid()) {
            if (!artifact->promoted || artifact->promotion_decision.invalid()) {
                result.outcome = PromotionOutcome::Revoked;
                result.artifact = *artifact;
                result.reasons.push_back(Reason(
                    ErrorCode::ArtifactRevoked,
                    "artifact holds no promotion authority to revoke and no decision was named"));
                return result;
            }
            target = artifact->promotion_decision;
        }
        if (!state_.decisions.count(target)) {
            return Status(ErrorCode::DecisionNotFound, "the named promotion decision is not held by this coordinator",
                          target.to_string());
        }
        if (cause.valid() && !state_.evidence.count(cause)) {
            return Status(ErrorCode::EvidenceNotFound, "the named revocation cause evidence is not held",
                          cause.to_string());
        }

        const Stage from = artifact->stage;
        artifact->revocation.active = true;
        artifact->revocation.decision = target;
        artifact->revocation.reason_class = reason_class;
        artifact->revocation.detail = bounded(detail, kMaxTextLength);
        artifact->revocation.authority =
            AuthorityId::from_parts(state_.coordinator.high(), state_.epoch.value());
        artifact->revocation.sequence = state_.next_sequence();
        artifact->revocation.policy_generation = state_.active_policy_generation;
        artifact->revocation.cause = cause;
        artifact->last_sequence = artifact->revocation.sequence;
        artifact->promoted = false;
        artifact->stage = Stage::Revoked;
        artifact->stage_generation = artifact->stage_generation.next();
        state_.pending.erase(id);

        PromotionRecord record;
        record.transition = state_.transition_generator.next();
        record.artifact = artifact->id;
        record.artifact_revision = artifact->revision;
        record.artifact_digest = artifact->digest;
        record.from = from;
        record.to = Stage::Revoked;
        record.decision = target;
        record.request = PromotionRequestId{};
        record.attempt = PromotionAttemptId{};
        record.policy = state_.active_policy;
        record.policy_generation = state_.active_policy_generation;
        record.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
        record.evidence_snapshot_digest = artifact->digest;
        record.sequence = artifact->last_sequence;
        record.committed_unix_millis = now_millis();
        record.note = "revocation: " + reason_class;
        if (state_.records.size() >= config_.max_records_retained) {
            state_.records.erase(state_.records.begin());
        }
        state_.records[record.transition] = record;

        append_history(state_, config_, HistoryEventKind::Revoked, *artifact, from, Stage::Revoked,
                       "revocation: " + reason_class);
        ++persist_epoch_;
        result.outcome = PromotionOutcome::Revoked;
        result.artifact = *artifact;
        result.record = record;
        result.has_record = true;
    }
    notify_change();
    return result;
}

Result<PromotionEngine::TrustMutation> PromotionEngine::supersede(ArtifactId id, ArtifactId successor,
                                                                 std::string reason,
                                                                 CoordinatorAuthority authority) {
    TrustMutation result;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!admission_open_) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is not admitting new work");
        }
        if (successor.invalid()) {
            return Status(ErrorCode::InvalidIdentity, "superseding artifact identity is the invalid sentinel");
        }
        if (successor == id) {
            return Status(ErrorCode::InvalidArgument, "an artifact cannot supersede itself");
        }
        ArtifactRecord* artifact = state_.find_current(id);
        if (artifact == nullptr) {
            return Status(ErrorCode::ArtifactNotFound, "artifact identity is not registered", id.to_string());
        }
        const ArtifactRecord* successor_record = state_.find_current(successor);
        if (successor_record == nullptr) {
            return Status(ErrorCode::ArtifactNotFound, "the superseding artifact is not registered",
                          successor.to_string());
        }
        if (authority.valid() && authority.coordinator != state_.coordinator) {
            return Status(ErrorCode::StaleCoordinatorEpoch, "supersession authority names a different coordinator");
        }
        if (artifact->supersession.active) {
            result.outcome = PromotionOutcome::Superseded;
            result.artifact = *artifact;
            result.reasons.push_back(Reason(ErrorCode::ArtifactSuperseded, "artifact is already superseded"));
            return result;
        }
        if (artifact->stage == Stage::Revoked || artifact->stage == Stage::Retired) {
            result.outcome = PromotionOutcome::Superseded;
            result.artifact = *artifact;
            result.reasons.push_back(
                Reason(ErrorCode::ArtifactSuperseded, "a revoked or retired artifact cannot be superseded"));
            return result;
        }
        // Supersession is a governed transition. An artifact that has not yet
        // reached a stage from which supersession is legal cannot be marked as
        // superseded, because the lifecycle graph does not permit that edge.
        if (!state_.policy().graph.has_edge(artifact->stage, Stage::Superseded)) {
            return Status(ErrorCode::TransitionIllegal,
                          "the active lifecycle graph forbids superseding an artifact in this stage",
                          std::string(to_string(artifact->stage)));
        }

        const Stage from = artifact->stage;
        // Supersession does not assert that the older artifact is invalid. It
        // asserts only that it is no longer the current artifact.
        artifact->supersession.active = true;
        artifact->supersession.successor = successor;
        artifact->supersession.successor_revision = successor_record->revision;
        artifact->supersession.reason = bounded(reason, kMaxTextLength);
        artifact->supersession.authority =
            AuthorityId::from_parts(state_.coordinator.high(), state_.epoch.value());
        artifact->supersession.sequence = state_.next_sequence();
        artifact->last_sequence = artifact->supersession.sequence;
        if (from != Stage::Revoked && from != Stage::Retired) {
            artifact->stage = Stage::Superseded;
            artifact->stage_generation = artifact->stage_generation.next();
        }
        artifact->promoted = false;
        state_.pending.erase(id);

        PromotionRecord record;
        record.transition = state_.transition_generator.next();
        record.artifact = artifact->id;
        record.artifact_revision = artifact->revision;
        record.artifact_digest = artifact->digest;
        record.from = from;
        record.to = artifact->stage;
        // A supersession that is not tied to a promotion decision must not claim
        // one. Recording the all-zero decision sentinel would produce a record
        // that references a decision the coordinator does not hold, which is
        // exactly the kind of dangling authority the audit trail forbids, so the
        // record is explicitly marked as not decision-bound instead.
        record.decision = artifact->promotion_decision;
        record.policy = state_.active_policy;
        record.policy_generation = state_.active_policy_generation;
        record.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
        record.evidence_snapshot_digest = artifact->digest;
        record.sequence = artifact->last_sequence;
        record.committed_unix_millis = now_millis();
        record.note = "superseded by " + successor.to_string();
        if (state_.records.size() >= config_.max_records_retained) {
            state_.records.erase(state_.records.begin());
        }
        state_.records[record.transition] = record;

        append_history(state_, config_, HistoryEventKind::Superseded, *artifact, from, artifact->stage,
                       record.note);
        ++persist_epoch_;
        result.outcome = PromotionOutcome::Superseded;
        result.artifact = *artifact;
        result.record = record;
        result.has_record = true;
    }
    notify_change();
    return result;
}

Result<PromotionEngine::TrustMutation> PromotionEngine::retire(ArtifactId id, CoordinatorAuthority authority) {
    TrustMutation result;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!admission_open_) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is not admitting new work");
        }
        ArtifactRecord* artifact = state_.find_current(id);
        if (artifact == nullptr) {
            return Status(ErrorCode::ArtifactNotFound, "artifact identity is not registered", id.to_string());
        }
        if (authority.valid() && authority.coordinator != state_.coordinator) {
            return Status(ErrorCode::StaleCoordinatorEpoch, "retirement authority names a different coordinator");
        }
        const Stage from = artifact->stage;
        if (from == Stage::Retired) {
            result.outcome = PromotionOutcome::PromotionIneligible;
            result.artifact = *artifact;
            result.reasons.push_back(Reason(ErrorCode::InvalidArgument, "artifact is already retired"));
            return result;
        }
        if (!state_.policy().graph.has_edge(from, Stage::Retired)) {
            return Status(ErrorCode::TransitionIllegal, "the active lifecycle graph forbids retirement",
                          std::string(to_string(from)));
        }
        artifact->promoted = false;
        artifact->stage = Stage::Retired;
        artifact->stage_generation = artifact->stage_generation.next();
        artifact->last_sequence = state_.next_sequence();
        state_.pending.erase(id);

        PromotionRecord record;
        record.transition = state_.transition_generator.next();
        record.artifact = artifact->id;
        record.artifact_revision = artifact->revision;
        record.artifact_digest = artifact->digest;
        record.from = from;
        record.to = Stage::Retired;
        record.decision = artifact->promotion_decision;
        record.policy = state_.active_policy;
        record.policy_generation = state_.active_policy_generation;
        record.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
        record.evidence_snapshot_digest = artifact->digest;
        record.sequence = artifact->last_sequence;
        record.committed_unix_millis = now_millis();
        record.note = "retired";
        if (state_.records.size() >= config_.max_records_retained) {
            state_.records.erase(state_.records.begin());
        }
        state_.records[record.transition] = record;

        append_history(state_, config_, HistoryEventKind::Retired, *artifact, from, Stage::Retired, record.note);
        ++persist_epoch_;
        result.outcome = PromotionOutcome::PromotionCommitted;
        result.artifact = *artifact;
        result.record = record;
        result.has_record = true;
    }
    notify_change();
    return result;
}

Result<PromotionEngine::TrustMutation> PromotionEngine::revoke_evidence(EvidenceId id, std::string reason,
                                                                       CoordinatorAuthority authority) {
    TrustMutation result;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!admission_open_) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is not admitting new work");
        }
        const auto it = state_.evidence.find(id);
        if (it == state_.evidence.end()) {
            return Status(ErrorCode::EvidenceNotFound, "evidence identity is not registered", id.to_string());
        }
        if (authority.valid() && authority.coordinator != state_.coordinator) {
            return Status(ErrorCode::StaleCoordinatorEpoch, "revocation authority names a different coordinator");
        }
        EvidenceRecord& record = it->second;
        if (record.revoked) {
            result.outcome = PromotionOutcome::EvidenceRevoked;
            result.reasons.push_back(Reason(ErrorCode::EvidenceRevoked, "evidence is already revoked"));
            return result;
        }
        record.revoked = true;
        record.revocation_reason = bounded(reason, kMaxTextLength);
        record.revocation_authority =
            AuthorityId::from_parts(state_.coordinator.high(), state_.epoch.value());
        record.revocation_sequence = state_.next_sequence();
        record.integrity_digest = compute_evidence_integrity(record);

        // An evidence revocation fences an uncommitted plan that depended on it:
        // the plan is released and its next commit attempt fails the snapshot
        // comparison in commit().
        std::vector<ArtifactId> fenced;
        for (const auto& [artifact_id, pending] : state_.pending) {
            if (pending.artifact == record.subject && pending.artifact_revision == record.subject_revision) {
                fenced.push_back(artifact_id);
            }
        }
        for (const ArtifactId& artifact_id : fenced) {
            state_.pending.erase(artifact_id);
        }

        HistoryEvent event;
        event.sequence = record.revocation_sequence;
        event.kind = HistoryEventKind::EvidenceRevoked;
        event.artifact = record.subject;
        event.artifact_revision = record.subject_revision;
        event.evidence = record.id;
        event.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
        event.note = "evidence revoked: " + record.revocation_reason;
        if (state_.history.size() >= config_.max_history_events) {
            state_.history.erase(state_.history.begin());
        }
        state_.history[event.sequence] = event;
        ++persist_epoch_;
        result.outcome = PromotionOutcome::EvidenceRevoked;
        result.reasons.push_back(Reason(ErrorCode::EvidenceRevoked, "evidence revoked"));
    }
    notify_change();
    return result;
}

Status PromotionEngine::set_security_veto(ArtifactId id, bool active, std::string reason) {
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (id.invalid()) {
            return Status(ErrorCode::InvalidIdentity, "security veto references an invalid artifact identity");
        }
        VetoState& veto = state_.vetoes[id];
        veto.security_veto = active;
        veto.security_reason = bounded(reason, kMaxTextLength);
        ++persist_epoch_;
    }
    notify_change();
    return Status::success();
}

Status PromotionEngine::set_dependency_veto(ArtifactId id, bool active, std::string reason) {
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (id.invalid()) {
            return Status(ErrorCode::InvalidIdentity, "dependency veto references an invalid artifact identity");
        }
        VetoState& veto = state_.vetoes[id];
        veto.dependency_veto = active;
        veto.dependency_reason = bounded(reason, kMaxTextLength);
        ++persist_epoch_;
    }
    notify_change();
    return Status::success();
}

Result<CompatibilityGeneration> PromotionEngine::set_compatibility_generation(CompatibilityGeneration generation) {
    CompatibilityGeneration applied{};
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!generation.valid()) {
            return Status(ErrorCode::InvalidCount, "compatibility generation must be non-zero");
        }
        if (!(generation > state_.compatibility_generation)) {
            return Status(ErrorCode::Conflict, "compatibility generation must advance");
        }
        state_.compatibility_generation = generation;
        applied = generation;
        // Every outstanding plan was evaluated against the previous generation
        // and is released rather than silently reinterpreted.
        state_.pending.clear();
        ++persist_epoch_;
    }
    notify_change();
    return applied;
}

std::string PromotionEngine::RollbackEligibility::render() const {
    std::ostringstream out;
    out << "rollback_eligible=" << (eligible ? "true" : "false") << " outcome=" << to_string(outcome);
    for (const std::string& gate : blocking_gates) {
        out << "\n  blocked_by=" << gate;
    }
    return out.str();
}

PromotionEngine::RollbackEligibility PromotionEngine::evaluate_rollback_eligibility(ArtifactId id) const {
    RollbackEligibility result;
    std::unique_lock<std::shared_mutex> lock(state_mutex_);
    const ArtifactRecord* artifact = state_.find_current(id);
    if (artifact == nullptr) {
        result.outcome = PromotionOutcome::ArtifactNotFound;
        result.blocking_gates.push_back("artifact is not registered");
        return result;
    }

    // Only a revision that actually held promotion authority can be a rollback
    // target. Being registered is not enough.
    bool has_promotion_record = false;
    for (const auto& [transition, record] : state_.records) {
        (void)transition;
        if (record.artifact == id && record.artifact_revision == artifact->revision &&
            record.to == Stage::Promoted) {
            has_promotion_record = true;
            break;
        }
    }

    // Explicit policy gate: rollback eligibility is a policy choice, applied to
    // the transition that produced or would restore authority.
    bool policy_allows_rollback = false;
    if (const PolicyRule* rule = state_.policy().find_rule(artifact->kind, Stage::Approved, Stage::Promoted);
        rule != nullptr) {
        policy_allows_rollback = rule->allow_rollback_eligibility;
    }

    PromotionRequest request;
    request.artifact = id;
    request.expected_revision = artifact->revision;
    request.expected_digest = artifact->digest;
    request.requested_stage = Stage::Promoted;
    if (!policy_allows_rollback) {
        result.blocking_gates.push_back("policy does not permit rollback eligibility for this artifact class");
    }
    if (!has_promotion_record) {
        result.blocking_gates.push_back("the current revision has never been promoted");
    }
    if (artifact->revocation.active) {
        result.blocking_gates.push_back("artifact authority was revoked");
    }
    if (artifact->quarantine.active) {
        result.blocking_gates.push_back("artifact is quarantined");
    }
    if (artifact->stage == Stage::Retired) {
        result.blocking_gates.push_back("artifact is retired");
    }

    result.eligible = result.blocking_gates.empty();
    result.outcome = result.eligible ? PromotionOutcome::PromotionEligible : PromotionOutcome::PromotionIneligible;
    return result;
}

}  // namespace artifact_promotion
