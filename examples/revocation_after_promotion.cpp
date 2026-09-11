// Artifact Promotion example: revocation after a committed promotion.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// An artifact is promoted, then its authority is revoked. History keeps the
// promotion, current state reports the revocation, and a stale retry cannot
// resurrect authority: the plan that produced the promotion no longer holds a
// reservation, a fresh request is a transition the lifecycle forbids, and a
// replay of the original request returns the decision that was recorded at the
// time rather than restoring anything.
//
// Exit codes: 0 expectations observed, 1 expectation violated, 2 usage error.

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "artifact_promotion/engine.hpp"

namespace {

using namespace artifact_promotion;

const char* yes_no(bool value) noexcept { return value ? "true" : "false"; }

Result<EvidenceRecord> submit_pass(PromotionEngine& engine, const ArtifactRecord& artifact, EvidenceType type,
                                   std::string_view environment) {
    EvidenceSubmission submission;
    submission.subject = artifact.id;
    submission.subject_revision = artifact.revision;
    submission.subject_digest = artifact.digest;
    submission.type = type;
    submission.result = EvidenceResult::Pass;
    submission.confidence_milli = 1000;
    submission.measurement = "example-harness";
    submission.detail = std::string("pass evidence for ") + to_string(type);
    submission.payload_digest =
        Digest::from_string(std::string("payload:") + to_string(type) + artifact.digest.to_string());
    submission.produced_unix_millis = PromotionEngine::now_millis();
    submission.environment = std::string(environment);
    return engine.submit_evidence(submission);
}

PromotionRequest make_request(const ArtifactRecord& artifact, const CoordinatorAuthority& authority,
                              Stage destination, PromotionRequestId request, PromotionAttemptId attempt) {
    PromotionRequest promotion;
    promotion.artifact = artifact.id;
    promotion.expected_revision = artifact.revision;
    promotion.expected_digest = artifact.digest;
    promotion.requested_stage = destination;
    promotion.request = request;
    promotion.attempt = attempt;
    promotion.authority = authority;
    return promotion;
}

std::size_t promotion_event_count(const std::vector<HistoryEvent>& events) {
    std::size_t count = 0;
    for (const HistoryEvent& event : events) {
        if (event.kind == HistoryEventKind::PromotionCommitted) {
            ++count;
        }
    }
    return count;
}

}  // namespace

int main(int argc, char*[]) {
    if (argc != 1) {
        std::cout << "USAGE revocation_after_promotion takes no arguments\n";
        return 2;
    }

    PromotionEngine engine;
    const CoordinatorAuthority authority = engine.authority();

    IdentityGenerator<ArtifactIdTag> artifact_ids(0x9E51U);
    IdentityGenerator<PromotionRequestIdTag> request_ids(0x9E52U);
    IdentityGenerator<PromotionAttemptIdTag> attempt_ids(0x9E53U);
    IdentityGenerator<ProvenanceRefTag> provenance_refs(0x9E54U);

    ProvenanceRecord provenance;
    provenance.reference = provenance_refs.next();
    provenance.source = "research-ledger";
    provenance.subject = "ledger:summon-cli:5.0.0";
    provenance.resolution = ProvenanceResolution::Resolved;

    ArtifactRegistration registration;
    registration.id = artifact_ids.next();
    registration.kind = ArtifactKind::Executable;
    registration.digest = Digest::from_string("artifact:summon-cli:5.0.0");
    registration.size_bytes = 8U * 1024U * 1024U;
    registration.name = "summon-cli";
    registration.provenance.push_back(provenance);

    const Result<ArtifactRecord> registered = engine.register_artifact(registration);
    if (!registered) {
        std::cout << "ARTIFACT registered=false status=" << registered.status().render() << '\n';
        return 1;
    }
    const ArtifactRecord artifact = registered.value();
    std::cout << "ARTIFACT name=" << artifact.name << " stage=" << to_string(artifact.stage) << '\n';

    const EvidenceType required[] = {EvidenceType::ProvenanceComplete, EvidenceType::BuildPass,
                                     EvidenceType::UnitTestPass,       EvidenceType::IntegrationTestPass,
                                     EvidenceType::ReproducibilityPass, EvidenceType::MachineCriticApproval,
                                     EvidenceType::SignatureValid};
    for (EvidenceType type : required) {
        const std::string_view environment = type == EvidenceType::UnitTestPass ? "windows-x64-msvc" : "";
        const Result<EvidenceRecord> stored = submit_pass(engine, artifact, type, environment);
        if (!stored) {
            std::cout << "EVIDENCE type=" << to_string(type)
                      << " stored=false status=" << stored.status().render() << '\n';
            return 1;
        }
    }

    const Stage pipeline[] = {Stage::Verified, Stage::Qualified, Stage::Staged, Stage::Approved, Stage::Promoted};
    PromotionRequest promoted_request{};
    PromotionEngine::CommitResult promoted_commit{};
    bool have_promoted_commit = false;
    for (Stage destination : pipeline) {
        const PromotionRequest request =
            make_request(artifact, authority, destination, request_ids.next(), attempt_ids.next());
        const Result<PromotionEngine::CommitResult> committed = engine.promote(request);
        if (!committed || committed.value().outcome != PromotionOutcome::PromotionCommitted) {
            std::cout << "STAGE -> " << to_string(destination) << " outcome="
                      << (committed ? to_string(committed.value().outcome) : committed.status().render()) << '\n';
            return 1;
        }
        std::cout << "STAGE " << to_string(committed.value().record.from) << " -> "
                  << to_string(committed.value().record.to)
                  << " outcome=" << to_string(committed.value().outcome) << '\n';
        if (destination == Stage::Promoted) {
            promoted_request = request;
            promoted_commit = committed.value();
            have_promoted_commit = true;
        }
    }
    if (!have_promoted_commit) {
        std::cout << "STAGE promoted=false\n";
        return 1;
    }
    const PromotionDecisionId promotion_decision = promoted_commit.decision.id;

    // Revocation names the decision whose authority is being withdrawn.
    const Result<PromotionEngine::TrustMutation> revoked = engine.revoke(
        artifact.id, promotion_decision, "security_finding",
        "operator withdrew promotion authority after a security finding", authority);
    if (!revoked) {
        std::cout << "REVOKE applied=false status=" << revoked.status().render() << '\n';
        return 1;
    }
    std::cout << "REVOKE outcome=" << to_string(revoked.value().outcome)
              << " recorded=" << yes_no(revoked.value().has_record)
              << " stage=" << to_string(revoked.value().artifact.stage)
              << " promoted=" << yes_no(revoked.value().artifact.promoted)
              << " reason_class=" << revoked.value().artifact.revocation.reason_class << '\n';

    const std::optional<PromotionEngine::ArtifactView> view = engine.inspect_artifact(artifact.id);
    const std::vector<PromotionRecord> records = engine.promotion_history(artifact.id);
    const std::vector<HistoryEvent> events = engine.artifact_history(artifact.id, 64);
    std::size_t promotion_records = 0;
    for (const PromotionRecord& record : records) {
        if (record.to == Stage::Promoted) {
            ++promotion_records;
        }
    }

    std::cout << "STATE stage=" << (view.has_value() ? to_string(view->artifact.stage) : std::string("(missing)"))
              << " promoted=" << yes_no(view.has_value() && view->artifact.promoted)
              << " authoritative=" << yes_no(view.has_value() && view->artifact.currently_authoritative())
              << " revocation_active=" << yes_no(view.has_value() && view->artifact.revocation.active) << '\n';
    std::cout << "HISTORY records=" << std::to_string(records.size())
              << " promotion_records=" << std::to_string(promotion_records)
              << " committed_events=" << std::to_string(promotion_event_count(events))
              << " events=" << std::to_string(events.size()) << '\n';

    // The plan that produced the promotion is still retained, but revocation
    // released the reservation it was bound to, so it carries no authority.
    const std::optional<PromotionPlan> stale_plan = engine.inspect_plan(promoted_commit.record.plan);
    std::cout << "PLAN retained=" << yes_no(stale_plan.has_value())
              << " policy_generation="
              << (stale_plan.has_value() ? stale_plan->policy_generation.to_string() : std::string("-"))
              << " reservation=" << yes_no(engine.pending_transition(artifact.id).has_value())
              << " authority_restored=false" << '\n';

    // A fresh request identity asking for the stage the artifact no longer holds.
    const Result<PromotionEngine::CommitResult> fresh = engine.promote(
        make_request(artifact, authority, Stage::Promoted, request_ids.next(), attempt_ids.next()));
    const PromotionOutcome fresh_outcome = fresh ? fresh.value().outcome : PromotionOutcome::Invalid;
    std::cout << "REPLAY kind=fresh_identity outcome=" << to_string(fresh_outcome)
              << " committed=" << yes_no(fresh && fresh.value().has_record) << '\n';

    // explain() re-derives the same answer without mutating anything.
    const std::optional<PromotionDecision> explained = engine.explain(artifact.id, Stage::Promoted);
    std::cout << "EXPLAIN outcome="
              << (explained.has_value() ? to_string(explained->outcome) : std::string("(unavailable)"))
              << " mutation=none" << '\n';

    // The original request identity replays the decision that was recorded at
    // the time: a historical answer, not a restoration of authority.
    const Result<PromotionEngine::CommitResult> original_replay = engine.promote(promoted_request);
    const std::optional<PromotionEngine::ArtifactView> after_replay = engine.inspect_artifact(artifact.id);
    const std::vector<PromotionRecord> records_after = engine.promotion_history(artifact.id);
    std::cout << "REPLAY kind=original_identity outcome="
              << (original_replay ? to_string(original_replay.value().outcome) : original_replay.status().render())
              << " new_record=" << yes_no(original_replay && original_replay.value().has_record)
              << " records_unchanged=" << yes_no(records_after.size() == records.size())
              << " stage_after="
              << (after_replay.has_value() ? to_string(after_replay->artifact.stage) : std::string("(missing)"))
              << " authoritative_after="
              << yes_no(after_replay.has_value() && after_replay->artifact.currently_authoritative()) << '\n';

    const bool expected =
        revoked.value().outcome == PromotionOutcome::Revoked && revoked.value().has_record &&
        view.has_value() && view->artifact.stage == Stage::Revoked && !view->artifact.promoted &&
        !view->artifact.currently_authoritative() && view->artifact.revocation.active &&
        promotion_records == 1U && promotion_event_count(events) == 1U && stale_plan.has_value() &&
        !engine.pending_transition(artifact.id).has_value() &&
        fresh_outcome == PromotionOutcome::TransitionIllegal && explained.has_value() &&
        explained->outcome == PromotionOutcome::TransitionIllegal && after_replay.has_value() &&
        after_replay->artifact.stage == Stage::Revoked && !after_replay->artifact.currently_authoritative() &&
        records_after.size() == records.size();
    std::cout << "EXPECTATION " << (expected ? "satisfied" : "violated") << '\n';
    return expected ? 0 : 1;
}
