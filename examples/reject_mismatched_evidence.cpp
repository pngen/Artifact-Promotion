// Artifact Promotion example: evidence that describes something else.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Two boundaries are shown. At the submission boundary, evidence carrying a
// digest that does not match the registered artifact revision is refused
// outright, so inapplicable evidence never enters the store. At the gate
// boundary, evidence that was legitimately accepted for an older revision of
// the same artifact identity still cannot promote the current revision.
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

std::string short_digest(const Digest& digest) { return digest.to_string().substr(0, 12); }

// Builds one registration for the given identity, digest seed, and provenance
// reference.
ArtifactRegistration make_registration(ArtifactId id, std::string name, std::string_view digest_seed,
                                       ProvenanceRef reference) {
    ProvenanceRecord provenance;
    provenance.reference = reference;
    provenance.source = "research-ledger";
    provenance.subject = "ledger:" + std::move(name);
    provenance.resolution = ProvenanceResolution::Resolved;

    ArtifactRegistration registration;
    registration.id = id;
    registration.kind = ArtifactKind::Executable;
    registration.digest = Digest::from_string(digest_seed);
    registration.size_bytes = 4U * 1024U * 1024U;
    registration.name = "summon-cli";
    registration.provenance.push_back(provenance);
    return registration;
}

Result<EvidenceRecord> submit_evidence(PromotionEngine& engine, ArtifactId subject, ArtifactRevision revision,
                                       const Digest& digest, EvidenceType type) {
    EvidenceSubmission submission;
    submission.subject = subject;
    submission.subject_revision = revision;
    submission.subject_digest = digest;
    submission.type = type;
    submission.result = EvidenceResult::Pass;
    submission.confidence_milli = 1000;
    submission.measurement = "example-harness";
    submission.detail = "evidence bound to an explicit artifact revision and digest";
    submission.payload_digest = Digest::from_string(std::string("payload:") + to_string(type));
    submission.produced_unix_millis = PromotionEngine::now_millis();
    return engine.submit_evidence(submission);
}

Result<PromotionEngine::CommitResult> promote_revision(PromotionEngine& engine, const ArtifactRecord& artifact,
                                                       const CoordinatorAuthority& authority, Stage destination,
                                                       PromotionRequestId request, PromotionAttemptId attempt) {
    PromotionRequest promotion;
    promotion.artifact = artifact.id;
    promotion.expected_revision = artifact.revision;
    promotion.expected_digest = artifact.digest;
    promotion.requested_stage = destination;
    promotion.request = request;
    promotion.attempt = attempt;
    promotion.authority = authority;
    return engine.promote(promotion);
}

}  // namespace

int main(int argc, char*[]) {
    if (argc != 1) {
        std::cout << "USAGE reject_mismatched_evidence takes no arguments\n";
        return 2;
    }

    PromotionEngine engine;
    const CoordinatorAuthority authority = engine.authority();

    IdentityGenerator<ArtifactIdTag> artifact_ids(0x9E21U);
    IdentityGenerator<PromotionRequestIdTag> request_ids(0x9E22U);
    IdentityGenerator<PromotionAttemptIdTag> attempt_ids(0x9E23U);
    IdentityGenerator<ProvenanceRefTag> provenance_refs(0x9E24U);

    const ArtifactId artifact_id = artifact_ids.next();
    const ArtifactId other_id = artifact_ids.next();

    const Result<ArtifactRecord> first =
        engine.register_artifact(make_registration(artifact_id, "summon-cli", "artifact:summon-cli:1.0.0",
                                                   provenance_refs.next()));
    const Result<ArtifactRecord> other =
        engine.register_artifact(make_registration(other_id, "summon-lib", "artifact:summon-lib:1.0.0",
                                                   provenance_refs.next()));
    if (!first || !other) {
        std::cout << "ARTIFACT registration_failed=true\n";
        return 1;
    }
    const ArtifactRecord revision_one = first.value();
    const ArtifactRecord other_artifact = other.value();
    std::cout << "ARTIFACT name=" << revision_one.name << " revision_generation="
              << revision_one.generation.to_string() << " digest=" << short_digest(revision_one.digest)
              << " stage=" << to_string(revision_one.stage) << '\n';
    std::cout << "ARTIFACT name=" << other_artifact.name << " revision_generation="
              << other_artifact.generation.to_string() << " digest=" << short_digest(other_artifact.digest)
              << " stage=" << to_string(other_artifact.stage) << '\n';

    // Submission boundary: the caller claims this revision has the digest of a
    // different artifact's content.
    const Result<EvidenceRecord> wrong_digest =
        submit_evidence(engine, revision_one.id, revision_one.revision, other_artifact.digest,
                        EvidenceType::ProvenanceComplete);
    const bool digest_refused = !wrong_digest && wrong_digest.code() == ErrorCode::DigestMismatch;
    std::cout << "SUBMIT boundary=digest_mismatch refused=" << yes_no(digest_refused)
              << " code=" << (wrong_digest ? std::string("OK") : to_string(wrong_digest.code())) << '\n';

    // Submission boundary: evidence naming a revision that belongs to another
    // artifact identity is not this coordinator's revision at all.
    const Result<EvidenceRecord> wrong_subject =
        submit_evidence(engine, revision_one.id, other_artifact.revision, revision_one.digest,
                        EvidenceType::ProvenanceComplete);
    const bool subject_refused = !wrong_subject && wrong_subject.code() == ErrorCode::ArtifactNotFound;
    std::cout << "SUBMIT boundary=unknown_revision refused=" << yes_no(subject_refused)
              << " code=" << (wrong_subject ? std::string("OK") : to_string(wrong_subject.code())) << '\n';

    // A newer revision of the same artifact identity. The previous revision is
    // no longer current, but it keeps its own history and its own evidence.
    const Result<ArtifactRecord> second =
        engine.register_artifact(make_registration(artifact_id, "summon-cli", "artifact:summon-cli:2.0.0",
                                                   provenance_refs.next()));
    if (!second) {
        std::cout << "ARTIFACT registration_failed=true status=" << second.status().render() << '\n';
        return 1;
    }
    const ArtifactRecord revision_two = second.value();
    std::cout << "ARTIFACT revision_generation=" << revision_two.generation.to_string()
              << " digest=" << short_digest(revision_two.digest)
              << " stage=" << to_string(revision_two.stage) << '\n';

    // This evidence is accepted: it truthfully describes revision 1, which the
    // coordinator still holds.
    const Result<EvidenceRecord> older =
        submit_evidence(engine, revision_one.id, revision_one.revision, revision_one.digest,
                        EvidenceType::ProvenanceComplete);
    std::cout << "SUBMIT boundary=older_revision accepted=" << yes_no(older.has_value())
              << " code=" << (older ? std::string("OK") : to_string(older.code())) << '\n';

    // The current revision cannot be promoted by evidence that describes the
    // previous revision, however valid that evidence is for its own subject.
    const Result<PromotionEngine::CommitResult> rejected =
        promote_revision(engine, revision_two, authority, Stage::Verified, request_ids.next(), attempt_ids.next());
    if (!rejected) {
        std::cout << "DECISION transport_status=" << rejected.status().render() << '\n';
        return 1;
    }
    const PromotionEngine::CommitResult& commit = rejected.value();
    std::cout << "DECISION outcome=" << to_string(commit.decision.outcome)
              << " transition=" << to_string(commit.decision.from) << "->" << to_string(commit.decision.to)
              << " committed=" << yes_no(commit.has_record)
              << " failed_gates=" << std::to_string(commit.decision.failed_gate_count()) << '\n';
    for (const GateExplanation& gate : commit.decision.gates) {
        if (gate.status == GateStatus::Failed || gate.status == GateStatus::Unknown) {
            std::cout << "GATE " << to_string(gate.kind) << " status=" << to_string(gate.status)
                      << " code=" << to_string(gate.code) << " label=" << gate.label << '\n';
        }
    }
    for (const Reason& reason : commit.decision.reasons) {
        std::cout << "REASON code=" << to_string(reason.code) << " subject=" << reason.subject
                  << " detail=" << reason.text.view() << '\n';
    }

    const std::vector<EvidenceRecord> evidence_for_older =
        engine.evidence_for(revision_one.id, revision_one.revision);
    const std::vector<EvidenceRecord> evidence_for_current =
        engine.evidence_for(revision_two.id, revision_two.revision);
    std::cout << "EVIDENCE revision_generation=1 records=" << std::to_string(evidence_for_older.size())
              << "  revision_generation=2 records=" << std::to_string(evidence_for_current.size()) << '\n';

    // Evidence bound to the current revision is what the gate needs.
    const Result<EvidenceRecord> current =
        submit_evidence(engine, revision_two.id, revision_two.revision, revision_two.digest,
                        EvidenceType::ProvenanceComplete);
    if (!current) {
        std::cout << "SUBMIT boundary=current_revision accepted=false status=" << current.status().render() << '\n';
        return 1;
    }
    std::cout << "SUBMIT boundary=current_revision accepted=true generation="
              << current.value().generation.to_string() << '\n';

    const Result<PromotionEngine::CommitResult> accepted =
        promote_revision(engine, revision_two, authority, Stage::Verified, request_ids.next(), attempt_ids.next());
    if (!accepted) {
        std::cout << "DECISION transport_status=" << accepted.status().render() << '\n';
        return 1;
    }
    std::cout << "STAGE " << to_string(accepted.value().decision.from) << " -> "
              << to_string(accepted.value().decision.to)
              << " outcome=" << to_string(accepted.value().outcome) << '\n';

    // The older revision cannot be advanced at all: registration of a newer
    // revision already removed it from the current lifecycle.
    const Result<PromotionEngine::CommitResult> stale =
        promote_revision(engine, revision_one, authority, Stage::Verified, request_ids.next(), attempt_ids.next());
    const PromotionOutcome stale_outcome = stale ? stale.value().outcome : PromotionOutcome::Invalid;
    std::cout << "STAGE revision_generation=1 -> VERIFIED outcome=" << to_string(stale_outcome) << '\n';

    const std::optional<PromotionEngine::ArtifactView> view = engine.inspect_artifact(artifact_id);
    const bool current_verified = view.has_value() && view->artifact.stage == Stage::Verified;
    std::cout << "STATE current_revision_generation="
              << (view.has_value() ? view->artifact.generation.to_string() : std::string("-"))
              << " stage=" << (view.has_value() ? to_string(view->artifact.stage) : std::string("(missing)"))
              << '\n';

    const bool expected = digest_refused && subject_refused &&
                          commit.outcome == PromotionOutcome::EvidenceMissing && !commit.has_record &&
                          commit.decision.failed_gate_count() == 1U && evidence_for_older.size() == 1U &&
                          evidence_for_current.empty() && accepted.value().has_record &&
                          accepted.value().outcome == PromotionOutcome::PromotionCommitted &&
                          stale_outcome == PromotionOutcome::TransitionIllegal && current_verified;
    std::cout << "EXPECTATION " << (expected ? "satisfied" : "violated") << '\n';
    return expected ? 0 : 1;
}
