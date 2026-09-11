// Artifact Promotion example: request identity and idempotent replay.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// One request identity produces exactly one transition. Replaying the same
// identity with the same content returns the decision that was already
// recorded; replaying it with different content is a conflict rather than a
// second transition. A different request identity for an artifact that already
// holds authority reports ALREADY_PROMOTED and commits nothing.
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
        std::cout << "USAGE duplicate_request_idempotency takes no arguments\n";
        return 2;
    }

    PromotionEngine engine;
    const CoordinatorAuthority authority = engine.authority();

    IdentityGenerator<ArtifactIdTag> artifact_ids(0x9E41U);
    IdentityGenerator<PromotionRequestIdTag> request_ids(0x9E42U);
    IdentityGenerator<PromotionAttemptIdTag> attempt_ids(0x9E43U);
    IdentityGenerator<ProvenanceRefTag> provenance_refs(0x9E44U);

    ProvenanceRecord provenance;
    provenance.reference = provenance_refs.next();
    provenance.source = "research-ledger";
    provenance.subject = "ledger:summon-cli:4.0.0";
    provenance.resolution = ProvenanceResolution::Resolved;

    ArtifactRegistration registration;
    registration.id = artifact_ids.next();
    registration.kind = ArtifactKind::Executable;
    registration.digest = Digest::from_string("artifact:summon-cli:4.0.0");
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
    std::cout << "EVIDENCE submitted=" << std::to_string(sizeof(required) / sizeof(required[0])) << '\n';

    // One request identity, issued twice with identical content.
    const PromotionRequestId first_request = request_ids.next();
    const PromotionAttemptId first_attempt = attempt_ids.next();
    const PromotionRequest verified_request =
        make_request(artifact, authority, Stage::Verified, first_request, first_attempt);

    const Result<PromotionEngine::CommitResult> first = engine.promote(verified_request);
    if (!first || first.value().outcome != PromotionOutcome::PromotionCommitted) {
        std::cout << "STAGE -> VERIFIED outcome="
                  << (first ? to_string(first.value().outcome) : first.status().render()) << '\n';
        return 1;
    }
    const PromotionDecisionId decision_id = first.value().decision.id;
    const DecisionSequence decision_sequence = first.value().decision.sequence;
    const std::size_t after_first = engine.promotion_history(artifact.id).size();
    std::cout << "STAGE " << to_string(first.value().record.from) << " -> "
              << to_string(first.value().record.to)
              << " outcome=" << to_string(first.value().outcome)
              << " decision_sequence=" << decision_sequence.to_string()
              << " transitions=" << std::to_string(after_first) << '\n';

    const Result<PromotionEngine::CommitResult> replay = engine.promote(verified_request);
    if (!replay) {
        std::cout << "REPLAY status=" << replay.status().render() << '\n';
        return 1;
    }
    const bool same_decision = replay.value().decision.id == decision_id;
    const bool same_sequence = replay.value().decision.sequence == decision_sequence;
    const std::size_t after_replay = engine.promotion_history(artifact.id).size();
    std::cout << "REPLAY identity=original content=identical outcome="
              << to_string(replay.value().outcome)
              << " same_decision=" << yes_no(same_decision)
              << " same_sequence=" << yes_no(same_sequence)
              << " new_record=" << yes_no(replay.value().has_record)
              << " transitions=" << std::to_string(after_replay) << '\n';

    // The same identity carrying different content is a conflict, not a second
    // transition under a reused name.
    const Result<PromotionEngine::CommitResult> conflicting =
        engine.promote(make_request(artifact, authority, Stage::Qualified, first_request, attempt_ids.next()));
    const bool conflict_refused = !conflicting && conflicting.code() == ErrorCode::Conflict;
    std::cout << "REPLAY identity=original content=different refused=" << yes_no(conflict_refused)
              << " code=" << (conflicting ? std::string("OK") : to_string(conflicting.code())) << '\n';

    // Fresh request identities drive the remaining transitions.
    const Stage remaining[] = {Stage::Qualified, Stage::Staged, Stage::Approved, Stage::Promoted};
    for (Stage destination : remaining) {
        const Result<PromotionEngine::CommitResult> committed = engine.promote(
            make_request(artifact, authority, destination, request_ids.next(), attempt_ids.next()));
        if (!committed || committed.value().outcome != PromotionOutcome::PromotionCommitted) {
            std::cout << "STAGE -> " << to_string(destination) << " outcome="
                      << (committed ? to_string(committed.value().outcome) : committed.status().render()) << '\n';
            return 1;
        }
        std::cout << "STAGE " << to_string(committed.value().record.from) << " -> "
                  << to_string(committed.value().record.to)
                  << " outcome=" << to_string(committed.value().outcome) << '\n';
    }

    const std::vector<PromotionRecord> before_repeat = engine.promotion_history(artifact.id);
    const std::size_t records_before_repeat = before_repeat.size();

    // A second request identity for an artifact that already holds promotion
    // authority: the answer is a fact about current state, not a new commit.
    const Result<PromotionEngine::CommitResult> repeated = engine.promote(
        make_request(artifact, authority, Stage::Promoted, request_ids.next(), attempt_ids.next()));
    if (!repeated) {
        std::cout << "REPEAT status=" << repeated.status().render() << '\n';
        return 1;
    }
    const std::vector<PromotionRecord> after_repeat = engine.promotion_history(artifact.id);
    std::cout << "REPEAT identity=new content=equivalent outcome=" << to_string(repeated.value().outcome)
              << " committed=" << yes_no(repeated.value().has_record)
              << " records_unchanged=" << yes_no(after_repeat.size() == records_before_repeat) << '\n';

    const std::optional<PromotionEngine::ArtifactView> view = engine.inspect_artifact(artifact.id);
    std::cout << "STATE stage=" << (view.has_value() ? to_string(view->artifact.stage) : std::string("(missing)"))
              << " transitions=" << std::to_string(after_repeat.size())
              << " promotion_records=" << std::to_string(promoted_record_count(after_repeat)) << '\n';

    const bool expected = first.value().has_record && same_decision && same_sequence &&
                          !replay.value().has_record && after_replay == after_first && conflict_refused &&
                          repeated.value().outcome == PromotionOutcome::AlreadyPromoted &&
                          !repeated.value().has_record && after_repeat.size() == records_before_repeat &&
                          after_repeat.size() == 5U && promoted_record_count(after_repeat) == 1U &&
                          view.has_value() && view->artifact.currently_authoritative();
    std::cout << "EXPECTATION " << (expected ? "satisfied" : "violated") << '\n';
    return expected ? 0 : 1;
}
