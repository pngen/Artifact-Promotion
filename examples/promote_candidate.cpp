// Artifact Promotion example: a successful CANDIDATE -> PROMOTED promotion.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// One executable artifact is registered, the evidence classes the reference
// policy requires are submitted, and the artifact is then driven one governed
// transition at a time. A stage is reported as reached only after the engine
// has committed the transition, and the final authoritative state is read back
// from the engine instead of being assumed.
//
// Exit codes: 0 success, 1 expectation violated, 2 usage error.

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

// Submits one PASS evidence record bound to the exact artifact identity,
// revision, and digest. Evidence identity, generation, ingestion sequence, and
// the integrity digest are assigned by the runtime, never by the caller.
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

// Issues one promotion request. Nothing here decides eligibility: the engine
// evaluates the active policy and commits only what it revalidates.
Result<PromotionEngine::CommitResult> promote_to(PromotionEngine& engine, const ArtifactRecord& artifact,
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
        std::cout << "USAGE promote_candidate takes no arguments\n";
        return 2;
    }

    PromotionEngine engine;
    const CoordinatorAuthority authority = engine.authority();

    IdentityGenerator<ArtifactIdTag> artifact_ids(0x9E01U);
    IdentityGenerator<PromotionRequestIdTag> request_ids(0x9E02U);
    IdentityGenerator<PromotionAttemptIdTag> attempt_ids(0x9E03U);
    IdentityGenerator<ProvenanceRefTag> provenance_refs(0x9E04U);

    // Provenance is a reference to an adjacent authority. The engine stores the
    // reference and its resolution; it does not own research provenance.
    ProvenanceRecord provenance;
    provenance.reference = provenance_refs.next();
    provenance.source = "research-ledger";
    provenance.subject = "ledger:summon-cli:1.0.0";
    provenance.resolution = ProvenanceResolution::Resolved;

    ArtifactRegistration registration;
    registration.id = artifact_ids.next();
    registration.kind = ArtifactKind::Executable;
    registration.digest = Digest::from_string("artifact:summon-cli:1.0.0");
    registration.size_bytes = 8U * 1024U * 1024U;
    registration.name = "summon-cli";
    registration.provenance.push_back(provenance);

    const Result<ArtifactRecord> registered = engine.register_artifact(registration);
    if (!registered) {
        std::cout << "ARTIFACT registered=false status=" << registered.status().render() << '\n';
        return 1;
    }
    const ArtifactRecord artifact = registered.value();
    std::cout << "ARTIFACT name=" << artifact.name << " kind=" << to_string(artifact.kind)
              << " digest=" << artifact.digest.to_string() << " stage=" << to_string(artifact.stage)
              << " generation=" << artifact.generation.to_string() << '\n';

    struct RequiredEvidence {
        EvidenceType type;
        const char* environment;
    };

    // Exactly the evidence classes the reference policy requires for an
    // executable artifact, including the environment binding the policy
    // declares for unit test evidence.
    const RequiredEvidence required[] = {
        {EvidenceType::ProvenanceComplete, ""},
        {EvidenceType::BuildPass, ""},
        {EvidenceType::UnitTestPass, "windows-x64-msvc"},
        {EvidenceType::IntegrationTestPass, ""},
        {EvidenceType::ReproducibilityPass, ""},
        {EvidenceType::MachineCriticApproval, ""},
        {EvidenceType::SignatureValid, ""},
    };
    for (const RequiredEvidence& item : required) {
        const Result<EvidenceRecord> stored = submit_pass(engine, artifact, item.type, item.environment);
        if (!stored) {
            std::cout << "EVIDENCE type=" << to_string(item.type)
                      << " stored=false status=" << stored.status().render() << '\n';
            return 1;
        }
        std::cout << "EVIDENCE type=" << to_string(stored.value().type)
                  << " result=" << to_string(stored.value().result)
                  << " generation=" << stored.value().generation.to_string()
                  << " environment="
                  << (stored.value().environment.empty() ? std::string("(none)") : stored.value().environment)
                  << '\n';
    }

    const Stage pipeline[] = {Stage::Verified, Stage::Qualified, Stage::Staged, Stage::Approved, Stage::Promoted};
    const std::size_t expected_steps = sizeof(pipeline) / sizeof(pipeline[0]);
    std::size_t committed_steps = 0;

    for (Stage destination : pipeline) {
        const Result<PromotionEngine::CommitResult> result =
            promote_to(engine, artifact, authority, destination, request_ids.next(), attempt_ids.next());
        if (!result) {
            std::cout << "STAGE -> " << to_string(destination) << " status=" << result.status().render() << '\n';
            return 1;
        }
        const PromotionEngine::CommitResult& commit = result.value();
        if (!commit.has_record) {
            std::cout << "STAGE " << to_string(commit.decision.from) << " -> " << to_string(destination)
                      << " outcome=" << to_string(commit.outcome)
                      << " failed_gates=" << std::to_string(commit.decision.failed_gate_count()) << '\n';
            for (const Reason& reason : commit.decision.reasons) {
                std::cout << "REASON code=" << to_string(reason.code) << " subject=" << reason.subject
                          << " detail=" << reason.text.view() << '\n';
            }
            return 1;
        }
        ++committed_steps;
        std::cout << "STAGE " << to_string(commit.record.from) << " -> " << to_string(commit.record.to)
                  << " outcome=" << to_string(commit.outcome)
                  << " commit_sequence=" << commit.record.sequence.to_string()
                  << " gates_evaluated=" << std::to_string(commit.decision.gates.size())
                  << " evidence_snapshot=" << commit.decision.evidence_snapshot_digest.to_string().substr(0, 12)
                  << '\n';
    }

    const std::optional<PromotionEngine::ArtifactView> view = engine.inspect_artifact(artifact.id);
    if (!view.has_value()) {
        std::cout << "STATE artifact_present=false\n";
        return 1;
    }
    const std::vector<PromotionRecord> history = engine.promotion_history(artifact.id);
    const Status invariants = engine.check_invariants();

    std::cout << "STATE stage=" << to_string(view->artifact.stage)
              << " promoted=" << yes_no(view->artifact.promoted)
              << " authoritative=" << yes_no(view->artifact.currently_authoritative())
              << " promotion_records=" << std::to_string(history.size()) << '\n';
    std::cout << "SUMMARY " << render_artifact_summary(view->artifact) << '\n';
    std::cout << "INVARIANTS ok=" << yes_no(invariants.ok()) << '\n';

    const bool expected = committed_steps == expected_steps && view->artifact.stage == Stage::Promoted &&
                          view->artifact.currently_authoritative() && history.size() == expected_steps &&
                          invariants.ok();
    std::cout << "EXPECTATION " << (expected ? "satisfied" : "violated") << '\n';
    return expected ? 0 : 1;
}
