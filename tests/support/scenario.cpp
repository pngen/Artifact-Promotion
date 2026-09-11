// Artifact Promotion test support.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <utility>

#include "support/test_context.hpp"

namespace artifact_promotion::test {
namespace {

[[nodiscard]] std::uint64_t scenario_entropy() noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    std::uint64_t mixed = static_cast<std::uint64_t>(now) ^ 0x2545F4914F6CDD1DULL;
    mixed ^= mixed >> 31;
    mixed *= 0x7FEB352DULL;
    mixed ^= mixed >> 29;
    return mixed == 0 ? 1 : mixed;
}

}  // namespace

Scenario::Scenario(ScenarioOptions options)
    : engine_(std::make_unique<PromotionEngine>(options.engine, options.epoch)),
      artifact_generator_(scenario_entropy()),
      request_generator_(scenario_entropy()),
      attempt_generator_(scenario_entropy()),
      boot_generator_(scenario_entropy()),
      provenance_generator_(scenario_entropy()) {}

ArtifactId Scenario::make_artifact_id() noexcept { return artifact_generator_.next(); }

Digest Scenario::make_digest(std::string_view seed) noexcept { return Digest::from_string(seed); }

PromotionRequestId Scenario::make_request_id() noexcept { return request_generator_.next(); }

PromotionAttemptId Scenario::make_attempt_id() noexcept { return attempt_generator_.next(); }

WorkerBootId Scenario::make_boot_id() noexcept { return boot_generator_.next(); }

ArtifactRecord Scenario::register_artifact(ArtifactId id, ArtifactKind kind, std::string_view name,
                                           std::string_view digest_seed,
                                           std::vector<std::string> dependencies) {
    ArtifactRegistration registration;
    registration.id = id;
    registration.kind = kind;
    registration.digest = make_digest(digest_seed);
    registration.size_bytes = 4096;
    registration.name = std::string(name);
    registration.dependencies = std::move(dependencies);

    // Provenance references model a Research Ledger style source that has
    // already resolved the reference. The runtime stores the reference; it does
    // not become the ledger.
    ProvenanceRecord provenance;
    provenance.reference = provenance_generator_.next();
    provenance.source = "research-ledger";
    provenance.subject = "ledger:" + provenance.reference.to_string();
    provenance.resolution = ProvenanceResolution::Resolved;
    registration.provenance.push_back(provenance);

    auto registered = engine_->register_artifact(registration);
    if (!registered) {
        return ArtifactRecord{};
    }
    return registered.value();
}

EvidenceRecord Scenario::submit_spec(ArtifactId id, const EvidenceSpec& spec) {
    const ArtifactRecord artifact = current(id);
    EvidenceSubmission submission;
    submission.subject = id;
    submission.subject_revision = spec.use_current_revision ? artifact.revision : spec.override_revision;
    submission.subject_digest = spec.use_current_digest ? artifact.digest : spec.override_digest;
    submission.type = spec.type;
    submission.custom_type = spec.custom_type;
    submission.result = spec.result;
    submission.confidence_milli = 900;
    submission.measurement = spec.measurement.empty() ? "test-harness" : spec.measurement;
    submission.detail = spec.detail;
    submission.payload_digest = Digest::from_string("payload:" + artifact.digest.to_string());
    submission.produced_unix_millis =
        spec.produced_unix_millis == 0 ? PromotionEngine::now_millis() : spec.produced_unix_millis;
    submission.has_validity_window = spec.has_validity_window;
    submission.valid_from_unix_millis = spec.valid_from_unix_millis;
    submission.valid_until_unix_millis = spec.valid_until_unix_millis;
    submission.environment = spec.environment;
    submission.producer.boot = spec.boot;

    auto stored = engine_->submit_evidence(submission);
    if (!stored) {
        return EvidenceRecord{};
    }
    return stored.value();
}

EvidenceRecord Scenario::submit(ArtifactId id, EvidenceType type, EvidenceResult result,
                                std::string_view digest_seed) {
    EvidenceSpec spec;
    spec.type = type;
    spec.result = result;
    spec.measurement = std::string(digest_seed);
    return submit_spec(id, spec);
}

PromotionOutcome Scenario::step(ArtifactId id, Stage destination) {
    const ArtifactRecord artifact = current(id);
    PromotionRequest request;
    request.artifact = id;
    request.expected_revision = artifact.revision;
    request.expected_digest = artifact.digest;
    request.requested_stage = destination;
    request.request = request_generator_.next();
    request.attempt = attempt_generator_.next();
    request.authority = engine_->authority();

    auto committed = engine_->promote(request);
    if (!committed) {
        return PromotionOutcome::Invalid;
    }
    return committed.value().outcome;
}

Status Scenario::drive_to_promoted(ArtifactId id) {
    const ArtifactRecord initial = current(id);
    if (!initial.id.valid()) {
        return Status(ErrorCode::ArtifactNotFound, "scenario artifact is not registered");
    }
    const ArtifactKind kind = initial.kind;

    // CANDIDATE -> VERIFIED: provenance completeness evidence with a freshness
    // window inside the reference policy bound.
    EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    provenance.result = EvidenceResult::Pass;
    (void)submit_spec(id, provenance);
    if (step(id, Stage::Verified) != PromotionOutcome::PromotionCommitted) {
        return Status(ErrorCode::PolicyViolation, "unable to advance the scenario artifact to VERIFIED");
    }

    // VERIFIED -> QUALIFIED: the required set depends on the artifact class,
    // which is exactly the point of per-class evidence requirements.
    if (kind == ArtifactKind::Executable) {
        EvidenceSpec build;
        build.type = EvidenceType::BuildPass;
        (void)submit_spec(id, build);
        EvidenceSpec unit;
        unit.type = EvidenceType::UnitTestPass;
        unit.environment = "windows-x64-msvc";
        (void)submit_spec(id, unit);
        EvidenceSpec integration;
        integration.type = EvidenceType::IntegrationTestPass;
        (void)submit_spec(id, integration);
    } else if (kind == ArtifactKind::Model) {
        EvidenceSpec evaluation;
        evaluation.type = EvidenceType::ModelEvalPass;
        (void)submit_spec(id, evaluation);
        EvidenceSpec data;
        data.type = EvidenceType::DataValidationPass;
        (void)submit_spec(id, data);
    }
    if (step(id, Stage::Qualified) != PromotionOutcome::PromotionCommitted) {
        return Status(ErrorCode::PolicyViolation, "unable to advance the scenario artifact to QUALIFIED");
    }

    EvidenceSpec reproducibility;
    reproducibility.type = EvidenceType::ReproducibilityPass;
    (void)submit_spec(id, reproducibility);
    if (step(id, Stage::Staged) != PromotionOutcome::PromotionCommitted) {
        return Status(ErrorCode::PolicyViolation, "unable to advance the scenario artifact to STAGED");
    }

    EvidenceSpec approval;
    approval.type = EvidenceType::MachineCriticApproval;
    (void)submit_spec(id, approval);
    if (step(id, Stage::Approved) != PromotionOutcome::PromotionCommitted) {
        return Status(ErrorCode::PolicyViolation, "unable to advance the scenario artifact to APPROVED");
    }

    EvidenceSpec signature;
    signature.type = EvidenceType::SignatureValid;
    (void)submit_spec(id, signature);
    const PromotionOutcome promoted = step(id, Stage::Promoted);
    if (promoted != PromotionOutcome::PromotionCommitted) {
        return Status(ErrorCode::PolicyViolation, "unable to advance the scenario artifact to PROMOTED");
    }
    return Status::success();
}

ArtifactRecord Scenario::current(ArtifactId id) const {
    const auto view = engine_->inspect_artifact(id);
    if (!view.has_value()) {
        return ArtifactRecord{};
    }
    return view.value().artifact;
}

}  // namespace artifact_promotion::test
