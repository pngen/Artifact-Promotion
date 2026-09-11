// Artifact Promotion example: a promotion rejected for missing evidence.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// An executable artifact that has reached VERIFIED is asked to advance to
// QUALIFIED without the build, unit test, integration test, and environment
// evidence the reference policy requires. The rejection is expected: this
// program exits non-zero only when the rejection does NOT occur.
//
// Exit codes: 0 expected rejection observed, 1 expectation violated, 2 usage error.

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

void print_gate(const GateExplanation& gate) {
    std::cout << "GATE " << to_string(gate.kind) << " status=" << to_string(gate.status)
              << " code=" << to_string(gate.code) << " label=" << gate.label << '\n';
}

}  // namespace

int main(int argc, char*[]) {
    if (argc != 1) {
        std::cout << "USAGE reject_missing_evidence takes no arguments\n";
        return 2;
    }

    PromotionEngine engine;
    const CoordinatorAuthority authority = engine.authority();

    IdentityGenerator<ArtifactIdTag> artifact_ids(0x9E11U);
    IdentityGenerator<PromotionRequestIdTag> request_ids(0x9E12U);
    IdentityGenerator<PromotionAttemptIdTag> attempt_ids(0x9E13U);
    IdentityGenerator<ProvenanceRefTag> provenance_refs(0x9E14U);

    ProvenanceRecord provenance;
    provenance.reference = provenance_refs.next();
    provenance.source = "research-ledger";
    provenance.subject = "ledger:summon-cli:2.0.0";
    provenance.resolution = ProvenanceResolution::Resolved;

    ArtifactRegistration registration;
    registration.id = artifact_ids.next();
    registration.kind = ArtifactKind::Executable;
    registration.digest = Digest::from_string("artifact:summon-cli:2.0.0");
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
              << " stage=" << to_string(artifact.stage) << '\n';

    // Only provenance completeness evidence is supplied: enough for the
    // CANDIDATE -> VERIFIED step, and nothing else.
    const Result<EvidenceRecord> provenance_evidence =
        submit_pass(engine, artifact, EvidenceType::ProvenanceComplete, "");
    if (!provenance_evidence) {
        std::cout << "EVIDENCE type=PROVENANCE_COMPLETE stored=false status="
                  << provenance_evidence.status().render() << '\n';
        return 1;
    }
    std::cout << "EVIDENCE type=" << to_string(provenance_evidence.value().type)
              << " result=" << to_string(provenance_evidence.value().result) << " stored=true\n";

    const Result<PromotionEngine::CommitResult> verified =
        promote_to(engine, artifact, authority, Stage::Verified, request_ids.next(), attempt_ids.next());
    if (!verified || verified.value().outcome != PromotionOutcome::PromotionCommitted) {
        std::cout << "STAGE CANDIDATE -> VERIFIED outcome="
                  << (verified ? to_string(verified.value().outcome) : verified.status().render()) << '\n';
        return 1;
    }
    std::cout << "STAGE " << to_string(verified.value().record.from) << " -> "
              << to_string(verified.value().record.to)
              << " outcome=" << to_string(verified.value().outcome) << '\n';

    // No build, unit test, integration test, or environment evidence exists for
    // this artifact revision.
    const Result<PromotionEngine::CommitResult> rejected =
        promote_to(engine, artifact, authority, Stage::Qualified, request_ids.next(), attempt_ids.next());
    if (!rejected) {
        std::cout << "DECISION transport_status=" << rejected.status().render() << '\n';
        return 1;
    }
    const PromotionEngine::CommitResult& commit = rejected.value();
    const PromotionDecision& decision = commit.decision;

    std::cout << "DECISION outcome=" << to_string(decision.outcome)
              << " transition=" << to_string(decision.from) << "->" << to_string(decision.to)
              << " kind=" << to_string(decision.artifact_kind)
              << " policy_generation=" << decision.policy_generation.to_string()
              << " committed=" << yes_no(commit.has_record) << '\n';
    std::cout << "DECISION failed_gates=" << std::to_string(decision.failed_gate_count())
              << " gates_evaluated=" << std::to_string(decision.gates.size())
              << " findings=" << std::to_string(decision.findings.size())
              << " reasons=" << std::to_string(decision.reasons.size()) << '\n';

    for (const GateExplanation& gate : decision.gates) {
        if (gate.status == GateStatus::Failed || gate.status == GateStatus::Unknown) {
            print_gate(gate);
        }
    }
    for (const Reason& reason : decision.reasons) {
        std::cout << "REASON code=" << to_string(reason.code) << " subject=" << reason.subject
                  << " detail=" << reason.text.view() << '\n';
    }

    // explain() re-derives the same answer without issuing a plan, reserving
    // anything, or writing state.
    const std::optional<PromotionDecision> explained = engine.explain(artifact.id, Stage::Qualified);
    const bool explain_agrees =
        explained.has_value() && explained->outcome == decision.outcome &&
        explained->failed_gate_count() == decision.failed_gate_count();
    std::cout << "EXPLAIN outcome="
              << (explained.has_value() ? to_string(explained->outcome) : std::string("(unavailable)"))
              << " failed_gates="
              << (explained.has_value() ? std::to_string(explained->failed_gate_count()) : std::string("-"))
              << " mutation=none agrees=" << yes_no(explain_agrees) << '\n';

    const std::optional<PromotionEngine::ArtifactView> view = engine.inspect_artifact(artifact.id);
    const std::vector<PromotionRecord> history = engine.promotion_history(artifact.id);
    const bool still_verified = view.has_value() && view->artifact.stage == Stage::Verified;
    std::cout << "STATE stage=" << (view.has_value() ? to_string(view->artifact.stage) : std::string("(missing)"))
              << " promotion_records=" << std::to_string(history.size())
              << " reservation=" << yes_no(engine.pending_transition(artifact.id).has_value()) << '\n';

    const char* const expected_gate_labels[] = {
        "build evidence for the exact artifact digest",
        "unit test evidence for the exact artifact digest",
        "integration test evidence",
        "build evidence is fresh",
        "unit tests ran in the declared environment",
    };
    std::size_t matched_gates = 0;
    for (const char* label : expected_gate_labels) {
        for (const GateExplanation& gate : decision.gates) {
            const bool failing = gate.status == GateStatus::Failed || gate.status == GateStatus::Unknown;
            if (failing && gate.label == label) {
                ++matched_gates;
                break;
            }
        }
    }
    const std::size_t expected_gate_count = sizeof(expected_gate_labels) / sizeof(expected_gate_labels[0]);

    const bool expected = commit.outcome == PromotionOutcome::EvidenceMissing && !commit.has_record &&
                          decision.from == Stage::Verified && decision.to == Stage::Qualified &&
                          decision.failed_gate_count() == expected_gate_count &&
                          decision.reasons.size() == expected_gate_count && matched_gates == expected_gate_count &&
                          explain_agrees && still_verified &&
                          !engine.pending_transition(artifact.id).has_value() && history.size() == 1U;
    std::cout << "EXPECTATION " << (expected ? "satisfied" : "violated") << '\n';
    return expected ? 0 : 1;
}
