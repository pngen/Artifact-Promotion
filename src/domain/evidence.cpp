// Artifact Promotion - first-class promotion evidence.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/evidence.hpp"

#include <algorithm>
#include <array>

#include "artifact_promotion/detail/writer.hpp"

namespace artifact_promotion {
namespace {

struct EvidenceName {
    EvidenceType type;
    const char* name;
};

constexpr std::array<EvidenceName, 20> kEvidenceNames = {{
    {EvidenceType::Invalid, "INVALID"},
    {EvidenceType::BuildPass, "BUILD_PASS"},
    {EvidenceType::UnitTestPass, "UNIT_TEST_PASS"},
    {EvidenceType::IntegrationTestPass, "INTEGRATION_TEST_PASS"},
    {EvidenceType::PropertyTestPass, "PROPERTY_TEST_PASS"},
    {EvidenceType::AdversarialTestPass, "ADVERSARIAL_TEST_PASS"},
    {EvidenceType::SanitizerPass, "SANITIZER_PASS"},
    {EvidenceType::SecurityScanPass, "SECURITY_SCAN_PASS"},
    {EvidenceType::BenchmarkResult, "BENCHMARK_RESULT"},
    {EvidenceType::CompatibilityPass, "COMPATIBILITY_PASS"},
    {EvidenceType::AbiCompatibilityPass, "ABI_COMPATIBILITY_PASS"},
    {EvidenceType::DataValidationPass, "DATA_VALIDATION_PASS"},
    {EvidenceType::ModelEvalPass, "MODEL_EVAL_PASS"},
    {EvidenceType::HumanApproval, "HUMAN_APPROVAL"},
    {EvidenceType::MachineCriticApproval, "MACHINE_CRITIC_APPROVAL"},
    {EvidenceType::ReproducibilityPass, "REPRODUCIBILITY_PASS"},
    {EvidenceType::SignatureValid, "SIGNATURE_VALID"},
    {EvidenceType::ProvenanceComplete, "PROVENANCE_COMPLETE"},
    {EvidenceType::DependencyPolicyPass, "DEPENDENCY_POLICY_PASS"},
    {EvidenceType::Custom, "CUSTOM"},
}};

}  // namespace

const char* to_string(EvidenceType type) noexcept {
    for (const auto& entry : kEvidenceNames) {
        if (entry.type == type) {
            return entry.name;
        }
    }
    return "INVALID";
}

std::optional<EvidenceType> evidence_type_from_string(std::string_view text) noexcept {
    for (const auto& entry : kEvidenceNames) {
        if (text == entry.name) {
            return entry.type;
        }
    }
    return std::nullopt;
}

bool is_valid_evidence_type(std::uint64_t raw) noexcept {
    return raw >= kEvidenceTypeMin && raw <= kEvidenceTypeMax;
}

const char* to_string(EvidenceResult result) noexcept {
    switch (result) {
        case EvidenceResult::Unknown:
            return "UNKNOWN";
        case EvidenceResult::Pass:
            return "PASS";
        case EvidenceResult::Fail:
            return "FAIL";
        case EvidenceResult::Inconclusive:
            return "INCONCLUSIVE";
        case EvidenceResult::NotApplicable:
            return "NOT_APPLICABLE";
    }
    return "UNKNOWN";
}

bool is_valid_evidence_result(std::uint64_t raw) noexcept {
    return raw <= static_cast<std::uint64_t>(EvidenceResult::NotApplicable);
}

bool EvidenceRecord::valid() const noexcept {
    if (id.invalid() || !generation.valid() || !is_valid_evidence_type(static_cast<std::uint64_t>(type))) {
        return false;
    }
    if (type == EvidenceType::Custom && custom_type.empty()) {
        return false;
    }
    if (type != EvidenceType::Custom && !custom_type.empty()) {
        return false;
    }
    if (subject.invalid() || subject_digest.invalid() || !subject_revision.valid()) {
        return false;
    }
    if (!producer.valid()) {
        return false;
    }
    if (!is_valid_evidence_result(static_cast<std::uint64_t>(result))) {
        return false;
    }
    if (confidence_milli > 1000) {
        return false;
    }
    if (payload_digest.invalid() || integrity_digest.invalid()) {
        return false;
    }
    if (!created_sequence.valid()) {
        return false;
    }
    if (has_validity_window && valid_until_unix_millis < valid_from_unix_millis) {
        return false;
    }
    if (revoked && revocation_authority.invalid()) {
        return false;
    }
    return true;
}

Status EvidenceSubmission::validate() const {
    if (subject.invalid()) {
        return Status(ErrorCode::InvalidIdentity, "evidence subject artifact identity is invalid");
    }
    if (subject_digest.invalid()) {
        return Status(ErrorCode::InvalidDigest, "evidence subject digest is the invalid sentinel");
    }
    if (!subject_revision.valid()) {
        return Status(ErrorCode::InvalidIdentity, "evidence subject artifact revision is invalid");
    }
    if (!is_valid_evidence_type(static_cast<std::uint64_t>(type))) {
        return Status(ErrorCode::InvalidEnum, "evidence type is not a known evidence class");
    }
    if (type == EvidenceType::Custom) {
        if (!is_valid_name(custom_type)) {
            return Status(ErrorCode::InvalidName, "custom evidence type name is empty or malformed");
        }
    } else if (!custom_type.empty()) {
        return Status(ErrorCode::InvalidArgument, "a built-in evidence type must not carry a custom type name");
    }
    if (!producer.valid()) {
        return Status(ErrorCode::InvalidIdentity, "evidence producer incarnation is inconsistent");
    }
    if (!is_valid_evidence_result(static_cast<std::uint64_t>(result))) {
        return Status(ErrorCode::InvalidEnum, "evidence result is not a known result class");
    }
    if (confidence_milli > 1000) {
        return Status(ErrorCode::InvalidArgument, "evidence confidence exceeds the documented 0..1000 range");
    }
    if (payload_digest.invalid()) {
        return Status(ErrorCode::InvalidDigest, "evidence payload digest is the invalid sentinel");
    }
    if (!is_valid_text(measurement) || !is_valid_text(detail) || !is_valid_text(environment)) {
        return Status(ErrorCode::InvalidArgument, "evidence text field is too long or contains control characters");
    }
    if (measurement.size() > kMaxTextLength || detail.size() > kMaxTextLength) {
        return Status(ErrorCode::InvalidArgument, "evidence text field exceeds the configured bound");
    }
    if (has_validity_window && valid_until_unix_millis < valid_from_unix_millis) {
        return Status(ErrorCode::InvalidArgument, "evidence validity window ends before it begins");
    }
    return Status::success();
}

bool EvidenceSnapshot::contains(EvidenceId id) const noexcept {
    for (const EvidenceSnapshotEntry& entry : entries) {
        if (entry.id == id) {
            return true;
        }
    }
    return false;
}

bool EvidenceSnapshot::contains_type(EvidenceType type) const noexcept {
    for (const EvidenceSnapshotEntry& entry : entries) {
        if (entry.type == type) {
            return true;
        }
    }
    return false;
}

Digest compute_snapshot_digest(ArtifactId subject, ArtifactRevision revision, const Digest& digest,
                               std::vector<EvidenceSnapshotEntry> entries) {
    std::sort(entries.begin(), entries.end());
    wire::Writer writer(256);
    writer.identity(subject);
    writer.identity(revision);
    writer.digest(digest);
    writer.list(entries.size(), [&](wire::Writer& out, std::size_t index) {
        const EvidenceSnapshotEntry& entry = entries[index];
        out.identity(entry.id);
        out.u8(static_cast<std::uint8_t>(entry.type));
        out.text(entry.custom_type, kMaxNameLength);
        out.counter(entry.generation);
        out.u8(static_cast<std::uint8_t>(entry.result));
        out.digest(entry.subject_digest);
        out.identity(entry.subject_revision);
        out.identity(entry.producer.worker);
        out.identity(entry.producer.boot);
        out.digest(entry.integrity_digest);
    });
    return sha256(writer.buffer());
}

Digest compute_evidence_integrity(const EvidenceRecord& record) {
    wire::Writer writer(256);
    writer.identity(record.id);
    writer.u8(static_cast<std::uint8_t>(record.type));
    writer.text(record.custom_type, kMaxNameLength);
    writer.counter(record.generation);
    writer.identity(record.subject);
    writer.digest(record.subject_digest);
    writer.identity(record.subject_revision);
    writer.identity(record.producer.worker);
    writer.identity(record.producer.boot);
    writer.u8(static_cast<std::uint8_t>(record.result));
    writer.u32(record.confidence_milli);
    writer.text(record.measurement);
    writer.text(record.detail);
    writer.digest(record.payload_digest);
    writer.identity(record.provenance);
    writer.counter(record.created_sequence);
    writer.u64(record.produced_unix_millis);
    writer.boolean(record.has_validity_window);
    writer.u64(record.valid_from_unix_millis);
    writer.u64(record.valid_until_unix_millis);
    writer.text(record.environment);
    writer.boolean(record.revoked);
    return sha256(writer.buffer());
}

}  // namespace artifact_promotion
