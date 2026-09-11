// Artifact Promotion example: a narrow provenance adapter boundary.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Provenance authority lives in an adjacent system. This example consumes an
// authoritative provenance reference from a Research Ledger style source
// through one narrow adapter, and shows how the promotion gate behaves when
// provenance is absent, when the referenced ledger entry describes a different
// artifact, and when the source system has rejected it. No ledger is embedded
// and no ledger logic is reimplemented here: the adapter maps one reference to
// one provenance record and refuses everything else.
//
// Exit codes: 0 expectations observed, 1 expectation violated, 2 usage error.

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "artifact_promotion/engine.hpp"

namespace {

using namespace artifact_promotion;

const char* yes_no(bool value) noexcept { return value ? "true" : "false"; }

// ---------------------------------------------------------------------------
// The ledger-facing side. One reference, one verdict. This stands in for the
// adjacent authority; it is not a ledger implementation.
// ---------------------------------------------------------------------------
enum class LedgerVerdict : std::uint8_t {
    Accepted = 1,
    Superseded = 2,
    Rejected = 3,
};

struct LedgerEntry {
    ProvenanceRef reference{};
    std::string subject{};  // ledger-side locator of the artifact it describes
    LedgerVerdict verdict = LedgerVerdict::Rejected;
};

// ---------------------------------------------------------------------------
// The adapter boundary. A reference that the source does not hold, or that
// describes a different subject than the artifact being registered, never
// becomes resolved provenance.
// ---------------------------------------------------------------------------
class ProvenanceAdapter {
public:
    explicit ProvenanceAdapter(std::vector<LedgerEntry> entries) : entries_(std::move(entries)) {}

    Result<ProvenanceRecord> resolve(ProvenanceRef reference, std::string_view expected_subject) const {
        for (const LedgerEntry& entry : entries_) {
            if (entry.reference != reference) {
                continue;
            }
            if (entry.subject != expected_subject) {
                return Status(ErrorCode::ProvenanceMismatch,
                              "the referenced ledger entry describes a different subject", entry.subject);
            }
            ProvenanceRecord record;
            record.reference = entry.reference;
            record.source = "research-ledger";
            record.subject = entry.subject;
            switch (entry.verdict) {
                case LedgerVerdict::Accepted:
                    record.resolution = ProvenanceResolution::Resolved;
                    break;
                case LedgerVerdict::Superseded:
                    record.resolution = ProvenanceResolution::Superseded;
                    break;
                case LedgerVerdict::Rejected:
                    record.resolution = ProvenanceResolution::Rejected;
                    break;
            }
            return record;
        }
        return Status(ErrorCode::ProvenanceMissing, "the ledger does not hold this provenance reference");
    }

private:
    std::vector<LedgerEntry> entries_;
};

// ---------------------------------------------------------------------------
// Promotion-side helpers.
// ---------------------------------------------------------------------------
Result<ArtifactRecord> register_artifact(PromotionEngine& engine, ArtifactId id, std::string name,
                                         std::string_view digest_seed,
                                         const std::optional<ProvenanceRecord>& provenance) {
    ArtifactRegistration registration;
    registration.id = id;
    registration.kind = ArtifactKind::Model;
    registration.digest = Digest::from_string(digest_seed);
    registration.size_bytes = 1024U * 1024U;
    registration.name = std::move(name);
    if (provenance.has_value()) {
        registration.provenance.push_back(provenance.value());
    }
    return engine.register_artifact(registration);
}

// Submits the provenance completeness evidence the reference policy requires for
// CANDIDATE -> VERIFIED, then requests the transition. The evidence set is
// identical for every case, so the artifact provenance is the only variable.
Result<PromotionEngine::CommitResult> promote_with_provenance_evidence(
    PromotionEngine& engine, const ArtifactRecord& artifact, const CoordinatorAuthority& authority,
    PromotionRequestId request, PromotionAttemptId attempt) {
    EvidenceSubmission submission;
    submission.subject = artifact.id;
    submission.subject_revision = artifact.revision;
    submission.subject_digest = artifact.digest;
    submission.type = EvidenceType::ProvenanceComplete;
    submission.result = EvidenceResult::Pass;
    submission.confidence_milli = 1000;
    submission.measurement = "example-harness";
    submission.detail = "provenance completeness evidence";
    submission.payload_digest =
        Digest::from_string(std::string("payload:provenance:") + artifact.digest.to_string());
    submission.produced_unix_millis = PromotionEngine::now_millis();
    const Result<EvidenceRecord> stored = engine.submit_evidence(submission);
    if (!stored) {
        return detached_status(stored.status());
    }

    PromotionRequest promotion;
    promotion.artifact = artifact.id;
    promotion.expected_revision = artifact.revision;
    promotion.expected_digest = artifact.digest;
    promotion.requested_stage = Stage::Verified;
    promotion.request = request;
    promotion.attempt = attempt;
    promotion.authority = authority;
    return engine.promote(promotion);
}

PromotionOutcome report(const char* label, const Result<PromotionEngine::CommitResult>& result) {
    if (!result) {
        std::cout << label << " outcome=TRANSPORT_FAILURE status=" << result.status().render() << '\n';
        return PromotionOutcome::Invalid;
    }
    const PromotionEngine::CommitResult& commit = result.value();
    std::cout << label << " outcome=" << to_string(commit.outcome)
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
    return commit.outcome;
}

ErrorCode gate_code(const Result<PromotionEngine::CommitResult>& result, GateKind kind) {
    if (!result) {
        return ErrorCode::Ok;
    }
    for (const GateExplanation& gate : result.value().decision.gates) {
        if (gate.kind == kind && (gate.status == GateStatus::Failed || gate.status == GateStatus::Unknown)) {
            return gate.code;
        }
    }
    return ErrorCode::Ok;
}

}  // namespace

int main(int argc, char*[]) {
    if (argc != 1) {
        std::cout << "USAGE provenance_adapter takes no arguments\n";
        return 2;
    }

    PromotionEngine engine;
    const CoordinatorAuthority authority = engine.authority();

    IdentityGenerator<ArtifactIdTag> artifact_ids(0x9E91U);
    IdentityGenerator<PromotionRequestIdTag> request_ids(0x9E92U);
    IdentityGenerator<PromotionAttemptIdTag> attempt_ids(0x9E93U);
    IdentityGenerator<ProvenanceRefTag> provenance_refs(0x9E94U);

    const ProvenanceRef accepted_ref = provenance_refs.next();
    const ProvenanceRef rejected_ref = provenance_refs.next();
    const ProvenanceRef foreign_ref = provenance_refs.next();

    std::vector<LedgerEntry> ledger;
    ledger.push_back(LedgerEntry{accepted_ref, "model-7b", LedgerVerdict::Accepted});
    ledger.push_back(LedgerEntry{rejected_ref, "model-7b", LedgerVerdict::Rejected});
    ledger.push_back(LedgerEntry{foreign_ref, "model-13b", LedgerVerdict::Accepted});
    const ProvenanceAdapter adapter(ledger);

    // The adapter refuses a reference whose ledger entry describes a different
    // artifact than the one being registered.
    const Result<ProvenanceRecord> foreign = adapter.resolve(foreign_ref, "model-7b");
    const bool foreign_refused = !foreign && foreign.code() == ErrorCode::ProvenanceMismatch;
    std::cout << "ADAPTER expected_subject=model-7b reference=foreign refused=" << yes_no(foreign_refused)
              << " code=" << (foreign ? std::string("OK") : to_string(foreign.code())) << " ledger_subject=model-13b"
              << '\n';

    // A ledger entry the source itself rejected is mapped to a rejected
    // provenance record; it is never upgraded to resolved.
    const Result<ProvenanceRecord> rejected = adapter.resolve(rejected_ref, "model-7b");
    if (!rejected || rejected.value().resolution != ProvenanceResolution::Rejected) {
        std::cout << "ADAPTER reference=rejected resolution=unexpected\n";
        return 1;
    }
    std::cout << "ADAPTER expected_subject=model-7b reference=rejected resolution="
              << to_string(rejected.value().resolution) << '\n';

    const Result<ProvenanceRecord> accepted = adapter.resolve(accepted_ref, "model-7b");
    if (!accepted || accepted.value().resolution != ProvenanceResolution::Resolved) {
        std::cout << "ADAPTER reference=accepted resolution=unexpected\n";
        return 1;
    }
    std::cout << "ADAPTER expected_subject=model-7b reference=accepted resolution="
              << to_string(accepted.value().resolution) << '\n';

    // Case 1: no provenance at all.
    const Result<ArtifactRecord> absent = register_artifact(engine, artifact_ids.next(), "model-7b-a",
                                                           "artifact:model-7b:a", std::nullopt);
    if (!absent) {
        std::cout << "ARTIFACT registered=false status=" << absent.status().render() << '\n';
        return 1;
    }
    const Result<PromotionEngine::CommitResult> absent_result = promote_with_provenance_evidence(
        engine, absent.value(), authority, request_ids.next(), attempt_ids.next());
    const PromotionOutcome absent_outcome = report("DECISION case=provenance_absent", absent_result);

    // Case 2: a reference the adapter refused to resolve for this artifact. The
    // foreign reference is attached without a source-system resolution, and the
    // gate will not treat it as resolved provenance for this artifact.
    ProvenanceRecord unresolved_foreign;
    unresolved_foreign.reference = foreign_ref;
    unresolved_foreign.source = "research-ledger";
    unresolved_foreign.subject = "model-13b";
    unresolved_foreign.resolution = ProvenanceResolution::Unknown;
    const Result<ArtifactRecord> foreign_registration =
        register_artifact(engine, artifact_ids.next(), "model-7b-b", "artifact:model-7b:b", unresolved_foreign);
    if (!foreign_registration) {
        std::cout << "ARTIFACT registered=false status=" << foreign_registration.status().render() << '\n';
        return 1;
    }
    const Result<PromotionEngine::CommitResult> foreign_result = promote_with_provenance_evidence(
        engine, foreign_registration.value(), authority, request_ids.next(), attempt_ids.next());
    const PromotionOutcome foreign_outcome = report("DECISION case=foreign_reference", foreign_result);

    // Case 3: a ledger result the source system rejected.
    const Result<ArtifactRecord> rejected_registration =
        register_artifact(engine, artifact_ids.next(), "model-7b-c", "artifact:model-7b:c", rejected.value());
    if (!rejected_registration) {
        std::cout << "ARTIFACT registered=false status=" << rejected_registration.status().render() << '\n';
        return 1;
    }
    const Result<PromotionEngine::CommitResult> rejected_result = promote_with_provenance_evidence(
        engine, rejected_registration.value(), authority, request_ids.next(), attempt_ids.next());
    const PromotionOutcome rejected_outcome = report("DECISION case=rejected_result", rejected_result);

    // Case 4: the adapter produced resolved provenance for this exact subject.
    const Result<ArtifactRecord> accepted_registration =
        register_artifact(engine, artifact_ids.next(), "model-7b-d", "artifact:model-7b:d", accepted.value());
    if (!accepted_registration) {
        std::cout << "ARTIFACT registered=false status=" << accepted_registration.status().render() << '\n';
        return 1;
    }
    const Result<PromotionEngine::CommitResult> accepted_result = promote_with_provenance_evidence(
        engine, accepted_registration.value(), authority, request_ids.next(), attempt_ids.next());
    const PromotionOutcome accepted_outcome = report("DECISION case=resolved_provenance", accepted_result);

    const std::optional<PromotionEngine::ArtifactView> accepted_view =
        engine.inspect_artifact(accepted_registration.value().id);
    std::cout << "STATE case=resolved_provenance stage="
              << (accepted_view.has_value() ? to_string(accepted_view->artifact.stage) : std::string("(missing)"))
              << " provenance_records="
              << (accepted_view.has_value() ? std::to_string(accepted_view->artifact.provenance.size())
                                            : std::string("-"))
              << " stored_resolution="
              << (accepted_view.has_value() && !accepted_view->artifact.provenance.empty()
                      ? to_string(accepted_view->artifact.provenance.front().resolution)
                      : std::string("-"))
              << '\n';

    const bool expected = foreign_refused && absent_outcome == PromotionOutcome::ProvenanceMissing &&
                          gate_code(absent_result, GateKind::ProvenanceResolved) == ErrorCode::ProvenanceMissing &&
                          !absent_result.value().has_record &&
                          foreign_outcome == PromotionOutcome::ProvenanceMissing &&
                          gate_code(foreign_result, GateKind::ProvenanceResolved) == ErrorCode::ProvenanceMissing &&
                          !foreign_result.value().has_record &&
                          rejected_outcome == PromotionOutcome::ProvenanceMissing &&
                          gate_code(rejected_result, GateKind::ProvenanceResolved) == ErrorCode::ProvenanceMismatch &&
                          !rejected_result.value().has_record &&
                          accepted_outcome == PromotionOutcome::PromotionCommitted &&
                          accepted_result.value().has_record && accepted_view.has_value() &&
                          accepted_view->artifact.stage == Stage::Verified;
    std::cout << "EXPECTATION " << (expected ? "satisfied" : "violated") << '\n';
    return expected ? 0 : 1;
}
