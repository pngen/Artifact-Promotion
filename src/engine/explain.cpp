// Artifact Promotion - policy explanation without mutation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/engine.hpp"

namespace artifact_promotion {

std::optional<PromotionDecision> PromotionEngine::explain(ArtifactId id, Stage destination) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    const ArtifactRecord* artifact = state_.find_current(id);
    if (artifact == nullptr) {
        return std::nullopt;
    }
    if (destination == Stage::Invalid || !is_valid_stage_value(static_cast<std::uint64_t>(destination))) {
        return std::nullopt;
    }

    PromotionDecision decision;
    decision.artifact = id;
    decision.artifact_revision = artifact->revision;
    decision.artifact_generation = artifact->generation;
    decision.artifact_digest = artifact->digest;
    decision.artifact_kind = artifact->kind;
    decision.from = artifact->stage;
    decision.to = destination;
    decision.policy = state_.active_policy;
    decision.policy_generation = state_.active_policy_generation;
    decision.policy_digest = state_.active_policy_digest;
    decision.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};

    // Explanation issues no plan, reserves nothing, and writes nothing. The
    // decision identity and sequence are deliberately left at their invalid
    // sentinels, so a decision returned here can never be mistaken for one the
    // coordinator actually recorded.
    // When the requested transition is not one the lifecycle permits, the
    // caller still deserves the requirement set that governs the artifact where
    // it actually stands. The explanation is therefore evaluated against the
    // next transition out of the current stage, and the requested destination is
    // restored afterwards. The refusal itself is unchanged: it stays
    // TransitionIllegal, and the reasons and gates simply describe what the
    // policy would demand of this artifact next.
    Stage evaluated = destination;
    if (state_.policy().find_rule(artifact->kind, artifact->stage, destination) == nullptr) {
        for (const PolicyRule& candidate : state_.policy().rules) {
            if (candidate.from != artifact->stage) {
                continue;
            }
            if (candidate.has_kind_scope && candidate.kind_scope != artifact->kind) {
                continue;
            }
            if (!state_.policy().graph.has_edge(candidate.from, candidate.to)) {
                continue;
            }
            evaluated = candidate.to;
            break;
        }
    }

    PromotionRequest request;
    request.artifact = id;
    request.expected_revision = artifact->revision;
    request.expected_digest = artifact->digest;
    request.requested_stage = evaluated;
    request.authority = decision.authority;

    std::vector<EvidenceSnapshotEntry> snapshot_entries;
    const GateOutcome outcome = evaluate_gates(state_, request, now_millis(), decision, snapshot_entries);
    decision.outcome = outcome.outcome;
    decision.to = destination;
    decision.decided_unix_millis = now_millis();
    if (artifact->stage == destination && artifact->currently_authoritative()) {
        decision.outcome = PromotionOutcome::AlreadyPromoted;
        decision.authoritative = true;
    }
    return decision;
}

}  // namespace artifact_promotion
