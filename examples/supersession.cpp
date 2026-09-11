// Artifact Promotion example: supersession of a current artifact.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// A newer artifact replaces an older one. The older artifact keeps its
// registration, its evidence, and its promotion history; it simply is no longer
// current. Supersession deliberately does not assert that the older artifact is
// invalid, so rollback eligibility is reported separately by the engine rather
// than inferred from the stage.
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

// Grants every evidence class the reference policy requires for an executable
// artifact and advances it to PROMOTED one transition at a time.
Status drive_to_promoted(PromotionEngine& engine, const ArtifactRecord& artifact,
                         const CoordinatorAuthority& authority,
                         IdentityGenerator<PromotionRequestIdTag>& request_ids,
                         IdentityGenerator<PromotionAttemptIdTag>& attempt_ids) {
    EvidenceSubmission base;
    base.subject = artifact.id;
    base.subject_revision = artifact.revision;
    base.subject_digest = artifact.digest;
    base.result = EvidenceResult::Pass;
    base.confidence_milli = 1000;
    base.measurement = "example-harness";
    base.produced_unix_millis = PromotionEngine::now_millis();

    const EvidenceType required[] = {EvidenceType::ProvenanceComplete, EvidenceType::BuildPass,
                                     EvidenceType::UnitTestPass,       EvidenceType::IntegrationTestPass,
                                     EvidenceType::ReproducibilityPass, EvidenceType::MachineCriticApproval,
                                     EvidenceType::SignatureValid};
    for (EvidenceType type : required) {
        EvidenceSubmission submission = base;
        submission.type = type;
        submission.detail = std::string("pass evidence for ") + to_string(type);
        submission.payload_digest =
            Digest::from_string(std::string("payload:") + to_string(type) + artifact.digest.to_string());
        submission.environment = type == EvidenceType::UnitTestPass ? "windows-x64-msvc" : "";
        const Result<EvidenceRecord> stored = engine.submit_evidence(submission);
        if (!stored) {
            return detached_status(stored.status());
        }
    }

    const Stage pipeline[] = {Stage::Verified, Stage::Qualified, Stage::Staged, Stage::Approved, Stage::Promoted};
    for (Stage destination : pipeline) {
        const Result<PromotionEngine::CommitResult> committed =
            engine.promote(make_request(artifact, authority, destination, request_ids.next(), attempt_ids.next()));
        if (!committed) {
            return detached_status(committed.status());
        }
        if (committed.value().outcome != PromotionOutcome::PromotionCommitted) {
            return Status(ErrorCode::PolicyViolation,
                          std::string("transition to ") + to_string(destination) + " did not commit");
        }
    }
    return Status::success();
}

Result<ArtifactRecord> register_artifact(PromotionEngine& engine, ArtifactId id, std::string name,
                                         std::string_view digest_seed, ProvenanceRef reference) {
    ProvenanceRecord provenance;
    provenance.reference = reference;
    provenance.source = "research-ledger";
    provenance.subject = "ledger:" + name;
    provenance.resolution = ProvenanceResolution::Resolved;

    ArtifactRegistration registration;
    registration.id = id;
    registration.kind = ArtifactKind::Executable;
    registration.digest = Digest::from_string(digest_seed);
    registration.size_bytes = 4U * 1024U * 1024U;
    registration.name = std::move(name);
    registration.provenance.push_back(provenance);
    return engine.register_artifact(registration);
}

std::size_t promoted_record_count(const std::vector<PromotionRecord>& records) {
    std::size_t count = 0;
    for (const PromotionRecord& record : records) {
        if (record.to == Stage::Promoted) {
            ++count;
        }
    }
    return count;
}

}  // namespace

int main(int argc, char*[]) {
    if (argc != 1) {
        std::cout << "USAGE supersession takes no arguments\n";
        return 2;
    }

    PromotionEngine engine;
    const CoordinatorAuthority authority = engine.authority();

    IdentityGenerator<ArtifactIdTag> artifact_ids(0x9E61U);
    IdentityGenerator<PromotionRequestIdTag> request_ids(0x9E62U);
    IdentityGenerator<PromotionAttemptIdTag> attempt_ids(0x9E63U);
    IdentityGenerator<ProvenanceRefTag> provenance_refs(0x9E64U);

    const Result<ArtifactRecord> previous =
        register_artifact(engine, artifact_ids.next(), "summon-cli", "artifact:summon-cli:6.0.0",
                          provenance_refs.next());
    const Result<ArtifactRecord> successor =
        register_artifact(engine, artifact_ids.next(), "summon-cli-next", "artifact:summon-cli:7.0.0",
                          provenance_refs.next());
    const Result<ArtifactRecord> fresh =
        register_artifact(engine, artifact_ids.next(), "summon-report", "artifact:summon-report:1.0.0",
                          provenance_refs.next());
    if (!previous || !successor || !fresh) {
        std::cout << "ARTIFACT registration_failed=true\n";
        return 1;
    }
    const ArtifactRecord older = previous.value();
    const ArtifactRecord newer = successor.value();
    const ArtifactRecord never_promoted = fresh.value();

    const Status older_drive = drive_to_promoted(engine, older, authority, request_ids, attempt_ids);
    const Status newer_drive = drive_to_promoted(engine, newer, authority, request_ids, attempt_ids);
    if (older_drive.failed() || newer_drive.failed()) {
        std::cout << "STAGE drive_failed=true status="
                  << (older_drive.failed() ? older_drive.render() : newer_drive.render()) << '\n';
        return 1;
    }
    std::cout << "ARTIFACT name=" << older.name << " stage=PROMOTED"
              << "  name=" << newer.name << " stage=PROMOTED"
              << "  name=" << never_promoted.name << " stage=" << to_string(never_promoted.stage) << '\n';

    const PromotionEngine::RollbackEligibility before_supersession = engine.evaluate_rollback_eligibility(older.id);
    std::cout << "ROLLBACK before_supersession eligible=" << yes_no(before_supersession.eligible)
              << " outcome=" << to_string(before_supersession.outcome) << '\n';

    // The newer artifact replaces the older one as the current artifact.
    const Result<PromotionEngine::TrustMutation> superseded =
        engine.supersede(older.id, newer.id, "newer release replaces the previous current artifact", authority);
    if (!superseded) {
        std::cout << "SUPERSEDE applied=false status=" << superseded.status().render() << '\n';
        return 1;
    }
    const ArtifactRecord& older_after = superseded.value().artifact;
    std::cout << "SUPERSEDE outcome=" << to_string(superseded.value().outcome)
              << " recorded=" << yes_no(superseded.value().has_record) << " stage=" << to_string(older_after.stage)
              << " successor_matches=" << yes_no(older_after.supersession.successor == newer.id)
              << " successor_revision_valid=" << yes_no(older_after.supersession.successor_revision.valid())
              << " reason=" << older_after.supersession.reason << '\n';

    const std::optional<PromotionEngine::ArtifactView> older_view = engine.inspect_artifact(older.id);
    const std::optional<PromotionEngine::ArtifactView> newer_view = engine.inspect_artifact(newer.id);
    const std::vector<PromotionRecord> older_records = engine.promotion_history(older.id);
    const std::vector<HistoryEvent> older_events = engine.artifact_history(older.id, 64);
    std::size_t superseded_events = 0;
    for (const HistoryEvent& event : older_events) {
        if (event.kind == HistoryEventKind::Superseded) {
            ++superseded_events;
        }
    }

    std::cout << "STATE older stage=" << (older_view.has_value() ? to_string(older_view->artifact.stage)
                                                                : std::string("(missing)"))
              << " promoted=" << yes_no(older_view.has_value() && older_view->artifact.promoted)
              << " authoritative="
              << yes_no(older_view.has_value() && older_view->artifact.currently_authoritative())
              << " superseded=" << yes_no(older_view.has_value() && older_view->artifact.supersession.active)
              << " promotion_records=" << std::to_string(promoted_record_count(older_records))
              << " superseded_events=" << std::to_string(superseded_events) << '\n';
    std::cout << "STATE newer stage=" << (newer_view.has_value() ? to_string(newer_view->artifact.stage)
                                                                : std::string("(missing)"))
              << " authoritative="
              << yes_no(newer_view.has_value() && newer_view->artifact.currently_authoritative()) << '\n';

    // Supersession removed the older artifact from the current lifecycle but did
    // not invalidate it, so its rollback eligibility is still reported by policy.
    const PromotionEngine::RollbackEligibility after_supersession = engine.evaluate_rollback_eligibility(older.id);
    const PromotionEngine::RollbackEligibility never = engine.evaluate_rollback_eligibility(never_promoted.id);
    std::cout << "ROLLBACK after_supersession eligible=" << yes_no(after_supersession.eligible)
              << " outcome=" << to_string(after_supersession.outcome)
              << " blocking_gates=" << std::to_string(after_supersession.blocking_gates.size()) << '\n';
    for (const std::string& gate : after_supersession.blocking_gates) {
        std::cout << "ROLLBACK blocking_gate=" << gate << '\n';
    }
    std::cout << "ROLLBACK never_promoted eligible=" << yes_no(never.eligible)
              << " outcome=" << to_string(never.outcome) << '\n';
    for (const std::string& gate : never.blocking_gates) {
        std::cout << "ROLLBACK blocking_gate=" << gate << '\n';
    }

    // The older artifact is no longer current, so it cannot be promoted again.
    const Result<PromotionEngine::CommitResult> re_promote =
        engine.promote(make_request(older, authority, Stage::Promoted, request_ids.next(), attempt_ids.next()));
    const PromotionOutcome re_promote_outcome = re_promote ? re_promote.value().outcome : PromotionOutcome::Invalid;
    std::cout << "REPLAY re_promote_older outcome=" << to_string(re_promote_outcome)
              << " committed=" << yes_no(re_promote && re_promote.value().has_record) << '\n';

    const bool expected =
        superseded.value().outcome == PromotionOutcome::Superseded && superseded.value().has_record &&
        older_after.stage == Stage::Superseded && !older_after.promoted && !older_after.currently_authoritative() &&
        promoted_record_count(older_records) == 1U && superseded_events == 1U && before_supersession.eligible &&
        after_supersession.eligible && after_supersession.blocking_gates.empty() && !never.eligible &&
        never.blocking_gates.size() == 1U && re_promote_outcome == PromotionOutcome::TransitionIllegal &&
        newer_view.has_value() && newer_view->artifact.currently_authoritative();
    std::cout << "EXPECTATION " << (expected ? "satisfied" : "violated") << '\n';
    return expected ? 0 : 1;
}
