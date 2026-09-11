// Artifact Promotion - end to end smoke test.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "support/test_context.hpp"

using namespace artifact_promotion;
using namespace artifact_promotion::test;

AP_TEST(promotion_reaches_promoted_with_required_evidence) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord registered =
        scenario.register_artifact(id, ArtifactKind::Executable, "smoke-exe", "digest-smoke-1");
    AP_REQUIRE(registered.id.valid());
    AP_CHECK_EQ(registered.stage, Stage::Candidate);

    const Status driven = scenario.drive_to_promoted(id);
    AP_CHECK_EQ(driven.code(), ErrorCode::Ok);

    const ArtifactRecord final_record = scenario.current(id);
    AP_CHECK_EQ(final_record.stage, Stage::Promoted);
    AP_CHECK(final_record.currently_authoritative());
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
}

AP_TEST(missing_evidence_blocks_promotion) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "smoke-exe-2", "digest-smoke-2");

    // No provenance evidence has been submitted, so CANDIDATE -> VERIFIED must
    // fail deterministically with a typed explanation.
    const PromotionOutcome outcome = scenario.step(id, Stage::Verified);
    AP_CHECK_EQ(outcome, PromotionOutcome::EvidenceMissing);
    AP_CHECK_EQ(scenario.current(id).stage, Stage::Candidate);
}

AP_TEST(persistence_round_trip_preserves_promoted_state) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "smoke-exe-3", "digest-smoke-3");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const CoordinatorState state = scenario.engine().snapshot();
    auto encoded = StatePersistence::encode(state);
    AP_REQUIRE(encoded.has_value());
    auto decoded = StatePersistence::decode(encoded.value());
    AP_REQUIRE(decoded.has_value());
    AP_CHECK_EQ(decoded.value().verify_consistency().code(), ErrorCode::Ok);
    const ArtifactRecord* current = decoded.value().find_current(id);
    AP_REQUIRE(current != nullptr);
    AP_CHECK_EQ(current->stage, Stage::Promoted);
    AP_CHECK(current->currently_authoritative());
}

AP_TEST(evidence_claiming_a_different_digest_is_rejected_at_submission) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord registered =
        scenario.register_artifact(id, ArtifactKind::Executable, "smoke-exe-4", "digest-smoke-4");
    AP_REQUIRE(registered.id.valid());

    // Evidence that names an artifact but a different content digest is not
    // "similar evidence": the runtime refuses it at the submission boundary, so
    // it can never sit in the store waiting to be misapplied later.
    Scenario::EvidenceSpec wrong;
    wrong.type = EvidenceType::ProvenanceComplete;
    wrong.use_current_digest = false;
    wrong.override_digest = Digest::from_string("a-completely-different-artifact");

    const ArtifactRecord before = scenario.current(id);
    EvidenceSubmission submission;
    submission.subject = id;
    submission.subject_revision = before.revision;
    submission.subject_digest = wrong.override_digest;
    submission.type = EvidenceType::ProvenanceComplete;
    submission.result = EvidenceResult::Pass;
    submission.payload_digest = Digest::from_string("payload");
    const auto rejected = scenario.engine().submit_evidence(submission);
    AP_REQUIRE(!rejected.has_value());
    AP_CHECK_EQ(rejected.status().code(), ErrorCode::DigestMismatch);
    AP_CHECK_EQ(scenario.engine().count_evidence(), static_cast<std::size_t>(0));
}

AP_TEST(evidence_bound_to_an_older_revision_does_not_promote_the_newer_one) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord first =
        scenario.register_artifact(id, ArtifactKind::Executable, "smoke-exe-5", "digest-smoke-5a");
    AP_REQUIRE(first.id.valid());

    // Evidence is attached to the first revision of this artifact identity.
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);

    // A second revision supersedes the first. The evidence that validated the
    // first revision says nothing about the second, so promotion of the new
    // revision must not inherit it.
    const ArtifactRecord second =
        scenario.register_artifact(id, ArtifactKind::Executable, "smoke-exe-5", "digest-smoke-5b");
    AP_REQUIRE(second.id.valid());
    AP_CHECK(second.revision != first.revision);
    AP_CHECK_EQ(second.digest.to_string(), Digest::from_string("digest-smoke-5b").to_string());

    const PromotionOutcome outcome = scenario.step(id, Stage::Verified);
    AP_CHECK_EQ(outcome, PromotionOutcome::EvidenceMissing);

    const std::optional<ArtifactRecord> superseded = scenario.engine().inspect_revision(id, first.revision);
    AP_REQUIRE(superseded.has_value());
    AP_CHECK(superseded.value().supersession.active);
}

int main(int argc, char** argv) {
    return run_suite_from_command_line("smoke", argc, argv);
}
