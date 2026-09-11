// Artifact Promotion - transactional promotion: plan, revalidate, commit.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <sstream>

#include "artifact_promotion/engine.hpp"

namespace artifact_promotion {
namespace {

[[nodiscard]] Status detached(ErrorCode code, std::string_view message, std::string subject = {}) {
    return Status(code, message, std::move(subject));
}

[[nodiscard]] PromotionDecision make_base_decision(CoordinatorState& state, const PromotionRequest& request) {
    PromotionDecision decision;
    decision.request = request.request;
    decision.attempt = request.attempt;
    decision.artifact = request.artifact;
    decision.artifact_revision = request.expected_revision;
    decision.artifact_digest = request.expected_digest;
    decision.to = request.requested_stage;
    decision.policy = state.active_policy;
    decision.policy_generation = state.active_policy_generation;
    decision.policy_digest = state.active_policy_digest;
    decision.authority = CoordinatorAuthority{state.coordinator, state.epoch};
    return decision;
}

[[nodiscard]] bool request_is_well_formed(const PromotionRequest& request) {
    return request.artifact.valid() && request.expected_revision.valid() && request.expected_digest.valid() &&
           request.requested_stage != Stage::Invalid &&
           is_valid_stage_value(static_cast<std::uint64_t>(request.requested_stage)) && request.request.valid() &&
           request.attempt.valid() && request.authority.valid();
}

[[nodiscard]] bool stage_is_reachable(const PromotionPolicy& policy, ArtifactKind kind, Stage from,
                                      Stage to) noexcept {
    return policy.graph.has_edge(from, to) || policy.find_rule(kind, from, to) != nullptr;
}

}  // namespace

Result<PromotionEngine::EvaluationResult> PromotionEngine::evaluate(const PromotionRequest& request) {
    EvaluationResult result;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!admission_open_) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is not admitting new work");
        }
        if (!request_is_well_formed(request)) {
            return Status(ErrorCode::InvalidArgument, "promotion request is not well formed");
        }

        // Idempotency: a retried request identity returns the decision already
        // produced for it instead of creating a second transition.
        const auto existing = state_.idempotency.find(request.request);
        if (existing != state_.idempotency.end()) {
            if (existing->second.request_digest != compute_request_digest(request)) {
                return Status(ErrorCode::Conflict,
                              "this request identity was already used for different request content");
            }
            const auto decision_it = state_.decisions.find(existing->second.decision);
            if (decision_it != state_.decisions.end()) {
                result.decision = decision_it->second;
                return result;
            }
        }

        const ArtifactRecord* artifact = state_.find_revision(request.artifact, request.expected_revision);
        if (artifact == nullptr) {
            result.decision = make_base_decision(state_, request);
            result.decision.id = state_.decision_generator.next();
            result.decision.sequence = state_.next_decision_sequence();
            result.decision.outcome = PromotionOutcome::ArtifactNotFound;
            result.decision.reasons.push_back(
                Reason(ErrorCode::ArtifactNotFound, "the requested artifact revision is not registered",
                       request.artifact.to_string()));
            state_.decisions[result.decision.id] = result.decision;
            ++persist_epoch_;
        } else if (artifact->digest != request.expected_digest) {
            result.decision = make_base_decision(state_, request);
            result.decision.id = state_.decision_generator.next();
            result.decision.sequence = state_.next_decision_sequence();
            result.decision.outcome = PromotionOutcome::DigestMismatch;
            result.decision.artifact_generation = artifact->generation;
            result.decision.artifact_kind = artifact->kind;
            result.decision.from = artifact->stage;
            result.decision.reasons.push_back(
                Reason(ErrorCode::DigestMismatch,
                       "the caller's expected digest does not match the registered artifact revision",
                       request.expected_digest.to_string()));
            state_.decisions[result.decision.id] = result.decision;
            ++persist_epoch_;
        } else {
            const std::uint64_t now = now_millis();
            result.decision = make_base_decision(state_, request);
            result.decision.id = state_.decision_generator.next();
            result.decision.sequence = state_.next_decision_sequence();
            result.decision.artifact_generation = artifact->generation;
            result.decision.artifact_kind = artifact->kind;
            result.decision.from = artifact->stage;
            result.decision.decided_unix_millis = now;

            // A pending reservation held by a different attempt is a conflict,
            // not a queue position: promotion is never silently serialized
            // behind an unknown holder.
            bool conflicted = false;
            const auto pending = state_.pending.find(request.artifact);
            if (pending != state_.pending.end()) {
                const bool same_attempt =
                    pending->second.request == request.request && pending->second.attempt == request.attempt;
                conflicted = !same_attempt;
            }

            std::vector<EvidenceSnapshotEntry> snapshot_entries;
            if (artifact->stage == request.requested_stage) {
                const bool current = artifact->currently_authoritative();
                result.decision.outcome =
                    current ? PromotionOutcome::AlreadyPromoted : PromotionOutcome::TransitionIllegal;
                result.decision.authoritative = current;
                result.decision.reasons.push_back(Reason(
                    current ? ErrorCode::Ok : ErrorCode::TransitionIllegal,
                    current ? "the artifact is already promoted at the requested stage under current authority"
                            : "the artifact already occupies the requested stage but is not currently authoritative",
                    std::string(to_string(artifact->stage))));
            } else if (!stage_is_reachable(state_.policy(), artifact->kind, artifact->stage,
                                           request.requested_stage)) {
                result.decision.outcome = PromotionOutcome::TransitionIllegal;
                result.decision.reasons.push_back(Reason(
                    ErrorCode::TransitionIllegal, "the active lifecycle graph does not permit this transition",
                    std::string(to_string(artifact->stage)) + "->" + to_string(request.requested_stage)));
            } else if (conflicted) {
                result.decision.outcome = PromotionOutcome::Conflict;
                result.decision.reasons.push_back(Reason(
                    ErrorCode::ReservationHeld,
                    "another promotion attempt holds the reservation on this artifact", request.artifact.to_string()));
            } else {
                const GateOutcome outcome = evaluate_gates(state_, request, now, result.decision, snapshot_entries);
                result.decision.outcome = outcome.outcome;
                if (!outcome.failed) {
                    if (state_.plans.size() >= config_.max_plans_retained) {
                        state_.plans.erase(state_.plans.begin());
                    }
                    PromotionPlan plan;
                    plan.id = state_.plan_generator.next();
                    plan.request = request.request;
                    plan.attempt = request.attempt;
                    plan.decision = result.decision.id;
                    plan.artifact = artifact->id;
                    plan.artifact_revision = artifact->revision;
                    plan.artifact_generation = artifact->generation;
                    plan.artifact_digest = artifact->digest;
                    plan.artifact_kind = artifact->kind;
                    plan.from = artifact->stage;
                    plan.to = request.requested_stage;
                    plan.stage_generation = artifact->stage_generation;
                    plan.policy = state_.active_policy;
                    plan.policy_generation = state_.active_policy_generation;
                    plan.policy_digest = state_.active_policy_digest;
                    plan.lifecycle_digest = state_.policy().graph.graph_digest();
                    plan.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
                    plan.evidence_snapshot_digest = result.decision.evidence_snapshot_digest;
                    plan.evidence_entry_count = snapshot_entries.size();
                    plan.compatibility_profile = state_.compatibility_profile;
                    plan.compatibility_generation = state_.compatibility_generation;
                    plan.artifact_sequence = artifact->last_sequence;
                    plan.created_sequence = state_.next_sequence();
                    plan.decision_sequence = DecisionSequence(result.decision.sequence.value());
                    plan.has_expiry = config_.plan_ttl_millis > 0;
                    plan.expires_unix_millis = now + config_.plan_ttl_millis;

                    // Reserve the transition. At most one authoritative
                    // transition per artifact can proceed, and the reservation
                    // is bound to the stage generation it was computed from.
                    PendingTransition reservation;
                    reservation.id = state_.reservation_generator.next();
                    reservation.artifact = artifact->id;
                    reservation.artifact_revision = artifact->revision;
                    reservation.artifact_generation = artifact->generation;
                    reservation.stage_generation = artifact->stage_generation;
                    reservation.from = plan.from;
                    reservation.to = plan.to;
                    reservation.plan = plan.id;
                    reservation.request = request.request;
                    reservation.attempt = request.attempt;
                    reservation.authority = plan.authority;
                    reservation.created_sequence = plan.created_sequence;
                    reservation.created_unix_millis = now;
                    if (state_.pending.size() < config_.max_pending_promotions ||
                        state_.pending.count(artifact->id) > 0) {
                        state_.pending[artifact->id] = reservation;
                        state_.plans[plan.id] = plan;
                        result.plan = plan;
                        result.has_plan = true;
                        result.decision.plan = plan.id;
                    } else {
                        result.decision.outcome = PromotionOutcome::AdmissionRejected;
                        result.decision.reasons.push_back(Reason(
                            ErrorCode::AdmissionRejected,
                            "the coordinator has reached its configured bound of concurrent promotions",
                            artifact->id.to_string()));
                    }
                }
            }

            state_.decisions[result.decision.id] = result.decision;
            IdempotencyRecord record;
            record.request = request.request;
            record.attempt = request.attempt;
            record.decision = result.decision.id;
            record.outcome = result.decision.outcome;
            record.plan = result.decision.plan;
            record.request_digest = compute_request_digest(request);
            record.created_sequence = CommitSequence(result.decision.sequence.value());
            state_.idempotency[request.request] = record;

            HistoryEvent event;
            event.sequence = state_.next_sequence();
            event.kind = result.decision.succeeded() ? HistoryEventKind::PromotionEvaluated
                                                     : HistoryEventKind::PromotionRejected;
            event.artifact = artifact->id;
            event.artifact_revision = artifact->revision;
            event.decision = result.decision.id;
            event.outcome = result.decision.outcome;
            event.from = artifact->stage;
            event.to = request.requested_stage;
            event.authority = result.decision.authority;
            event.note = std::string("decision ") + to_string(result.decision.outcome);
            if (state_.history.size() >= config_.max_history_events) {
                state_.history.erase(state_.history.begin());
            }
            state_.history[event.sequence] = event;
            ++persist_epoch_;
        }
    }
    notify_change();
    return result;
}

Result<PromotionEngine::CommitResult> PromotionEngine::promote(const PromotionRequest& request) {
    auto evaluated = evaluate(request);
    if (!evaluated) {
        return detached_status(evaluated.status());
    }
    EvaluationResult evaluated_value = evaluated.value();
    if (!evaluated_value.has_plan) {
        CommitResult result;
        result.outcome = evaluated_value.decision.outcome;
        result.decision = evaluated_value.decision;
        return result;
    }
    return commit(evaluated_value.plan);
}

Result<PromotionEngine::CommitResult> PromotionEngine::commit(const PromotionPlan& plan) {
    CommitResult result;
    // commit() returns through many rejection paths. Holding the state lock
    // across any of them and then calling notify_change() would re-enter that
    // lock on the same thread, which deadlocks because a shared_mutex is not
    // recursive. The scope below therefore owns no notification at all: the lock
    // is released first and notify_change() runs exactly once at the end.
    bool committed = false;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!admission_open_) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is not admitting new work");
        }
        if (!plan.valid()) {
            return Status(ErrorCode::InvalidArgument, "promotion plan is not well formed");
        }

        const auto stored_plan = state_.plans.find(plan.id);
        if (stored_plan == state_.plans.end()) {
            return Status(ErrorCode::PlanNotFound, "the plan was never issued by this coordinator",
                          plan.id.to_string());
        }
        if (!(stored_plan->second == plan) || stored_plan->second.policy_digest != plan.policy_digest ||
            stored_plan->second.lifecycle_digest != plan.lifecycle_digest ||
            stored_plan->second.evidence_snapshot_digest != plan.evidence_snapshot_digest ||
            stored_plan->second.stage_generation != plan.stage_generation ||
            stored_plan->second.artifact_generation != plan.artifact_generation) {
            return Status(ErrorCode::InvariantViolation,
                          "the submitted plan does not match the plan this coordinator issued",
                          plan.id.to_string());
        }

        PromotionDecision& decision = state_.decisions[stored_plan->second.decision];
        result.decision = decision;

        const ArtifactRecord* artifact = state_.find_revision(plan.artifact, plan.artifact_revision);
        if (artifact == nullptr) {
            result.outcome = PromotionOutcome::ArtifactNotFound;
            return result;
        }

        const std::uint64_t now = now_millis();
        if (plan.has_expiry && now > plan.expires_unix_millis) {
            result.outcome = PromotionOutcome::RevalidationRequired;
            decision.outcome = PromotionOutcome::RevalidationRequired;
            decision.reasons.push_back(
                Reason(ErrorCode::PlanExpired, "the promotion plan expired before it was committed",
                       plan.id.to_string()));
            state_.decisions[plan.decision] = decision;
            state_.pending.erase(plan.artifact);
            ++persist_epoch_;
            result.decision = decision;
            return result;
        }

        const auto reservation = state_.pending.find(plan.artifact);
        if (reservation == state_.pending.end() || reservation->second.plan != plan.id) {
            result.outcome = PromotionOutcome::Conflict;
            decision.outcome = PromotionOutcome::Conflict;
            decision.reasons.push_back(Reason(ErrorCode::ReservationLost,
                                               "the reservation for this transition is no longer held",
                                               plan.id.to_string()));
            state_.decisions[plan.decision] = decision;
            ++persist_epoch_;
            result.decision = decision;
            return result;
        }

        // Revalidate every authority-bearing component of the plan against
        // current state. A plan is authority only for as long as the authority
        // it was computed from still exists.
        PromotionRequest request;
        request.artifact = plan.artifact;
        request.expected_revision = plan.artifact_revision;
        request.expected_digest = plan.artifact_digest;
        request.requested_stage = plan.to;
        request.request = plan.request;
        request.attempt = plan.attempt;
        request.authority = plan.authority;

        std::vector<EvidenceSnapshotEntry> snapshot_entries;
        const GateOutcome outcome = evaluate_gates(state_, request, now, decision, snapshot_entries);
        const Digest current_snapshot = compute_snapshot_digest(artifact->id, artifact->revision, artifact->digest,
                                                                snapshot_entries);
        if (current_snapshot != plan.evidence_snapshot_digest) {
            decision.outcome = PromotionOutcome::RevalidationRequired;
            decision.reasons.push_back(Reason(
                ErrorCode::EvidenceMismatch,
                "the evidence set changed after the plan was issued and the plan must be revalidated",
                plan.id.to_string()));
            state_.decisions[plan.decision] = decision;
            state_.pending.erase(plan.artifact);
            ++persist_epoch_;
            result.decision = decision;
            return result;
        }

        if (outcome.failed) {
            decision.outcome = outcome.outcome;
            decision.decided_unix_millis = now;
            state_.decisions[plan.decision] = decision;
            state_.pending.erase(plan.artifact);
            ++persist_epoch_;
            result.outcome = decision.outcome;
            result.decision = decision;
            return result;
        }

        // The plan is still authoritative. Commit the transition durably before
        // acknowledging success.
        const Stage from = artifact->stage;
        if (from == plan.to) {
            // The transition already committed under this same plan.
            decision.outcome = PromotionOutcome::AlreadyPromoted;
            decision.authoritative = artifact->currently_authoritative();
            state_.decisions[plan.decision] = decision;
            state_.pending.erase(plan.artifact);
            ++persist_epoch_;
            result.outcome = decision.outcome;
            result.decision = decision;
            return result;
        }

        ArtifactRecord* mutable_artifact = state_.find_revision(plan.artifact, plan.artifact_revision);
        mutable_artifact->stage = plan.to;
        mutable_artifact->stage_generation = mutable_artifact->stage_generation.next();
        mutable_artifact->last_sequence = state_.next_sequence();
        if (plan.to == Stage::Promoted) {
            mutable_artifact->promoted = true;
            mutable_artifact->promotion_decision = plan.decision;
            mutable_artifact->promotion_authority =
                AuthorityId::from_parts(state_.coordinator.high(), state_.epoch.value());
            mutable_artifact->promotion_sequence = mutable_artifact->last_sequence;
        }

        PromotionRecord record;
        record.transition = state_.transition_generator.next();
        record.artifact = plan.artifact;
        record.artifact_revision = plan.artifact_revision;
        record.artifact_digest = plan.artifact_digest;
        record.from = from;
        record.to = plan.to;
        record.decision = plan.decision;
        record.plan = plan.id;
        record.request = plan.request;
        record.attempt = plan.attempt;
        record.policy = plan.policy;
        record.policy_generation = plan.policy_generation;
        record.authority = plan.authority;
        record.evidence_snapshot_digest = plan.evidence_snapshot_digest;
        record.sequence = mutable_artifact->last_sequence;
        record.committed_unix_millis = now;
        record.note = std::string("committed ") + to_string(from) + " -> " + to_string(plan.to);
        if (state_.records.size() >= config_.max_records_retained) {
            state_.records.erase(state_.records.begin());
        }
        state_.records[record.transition] = record;

        decision.outcome = PromotionOutcome::PromotionCommitted;
        decision.authoritative = plan.to == Stage::Promoted;
        decision.decided_unix_millis = now;
        if (state_.decisions.size() >= config_.max_decisions_retained &&
            !state_.decisions.count(plan.decision)) {
            state_.decisions.erase(state_.decisions.begin());
        }
        state_.decisions[plan.decision] = decision;

        const auto idempotency = state_.idempotency.find(plan.request);
        if (idempotency != state_.idempotency.end()) {
            idempotency->second.outcome = PromotionOutcome::PromotionCommitted;
            idempotency->second.decision = plan.decision;
        }

        state_.pending.erase(plan.artifact);

        HistoryEvent event;
        event.sequence = record.sequence;
        event.kind = plan.to == Stage::Promoted ? HistoryEventKind::PromotionCommitted
                                                : HistoryEventKind::PromotionEvaluated;
        event.artifact = record.artifact;
        event.artifact_revision = record.artifact_revision;
        event.decision = record.decision;
        event.outcome = PromotionOutcome::PromotionCommitted;
        event.from = from;
        event.to = plan.to;
        event.authority = record.authority;
        event.note = record.note;
        if (state_.history.size() >= config_.max_history_events) {
            state_.history.erase(state_.history.begin());
        }
        state_.history[event.sequence] = event;

        result.outcome = PromotionOutcome::PromotionCommitted;
        result.record = record;
        result.has_record = true;
        result.decision = decision;
        ++persist_epoch_;
        committed = true;
    }

    // Success is acknowledged only after the change listener has written the
    // authoritative snapshot. Nothing is returned to the caller while the state
    // lock is held, so the listener can freely re-enter the engine.
    if (committed) {
        std::shared_lock<std::shared_mutex> persist_lock(persist_mutex_);
        std::function<void()> listener;
        std::uint64_t target = 0;
        {
            std::shared_lock<std::shared_mutex> state_lock(state_mutex_);
            listener = listener_;
            target = persist_epoch_;
        }
        if (listener) {
            listener();
            if (target > persist_clean_epoch_) {
                persist_clean_epoch_ = target;
            }
        }
    }
    notify_change();
    return result;
}

}  // namespace artifact_promotion
