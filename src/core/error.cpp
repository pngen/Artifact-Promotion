// Artifact Promotion - typed failure semantics.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/error.hpp"

namespace artifact_promotion {
namespace {

constexpr const char* kCodeNames[] = {
    "Ok",
    "InvalidArgument",
    "InvalidIdentity",
    "InvalidDigest",
    "InvalidName",
    "InvalidCount",
    "InvalidEnum",
    "InvalidStage",
    "InvalidTransition",
    "Unsupported",
    "PayloadTooLarge",
    "NumericOverflow",
    "ArtifactNotFound",
    "EvidenceNotFound",
    "PolicyNotFound",
    "PlanNotFound",
    "DecisionNotFound",
    "RequestNotFound",
    "ReservationNotFound",
    "AlreadyExists",
    "Conflict",
    "DuplicateRequest",
    "EvidenceMissing",
    "EvidenceMismatch",
    "EvidenceStale",
    "EvidenceRevoked",
    "EvidenceSuperseded",
    "EvidenceMalformed",
    "EvidenceIntegrityFailure",
    "EnvironmentMismatch",
    "OrderingViolation",
    "ArtifactMismatch",
    "DigestMismatch",
    "ArtifactGenerationStale",
    "ArtifactQuarantined",
    "ArtifactRevoked",
    "ArtifactSuperseded",
    "ArtifactRetired",
    "PolicyStale",
    "PolicyViolation",
    "PolicyGenerationStale",
    "TransitionIllegal",
    "CompatibilityFailed",
    "ProvenanceMissing",
    "ProvenanceMismatch",
    "SecurityVeto",
    "DependencyVeto",
    "ApprovalRequired",
    "StaleCoordinatorEpoch",
    "StaleWorkerBoot",
    "StaleEvidenceGeneration",
    "AuthorityStale",
    "PlanExpired",
    "PlanConsumed",
    "NotAuthorized",
    "ReservationHeld",
    "ReservationLost",
    "CommitUncertain",
    "Cancelled",
    "ShuttingDown",
    "AdmissionRejected",
    "PersistenceCorrupt",
    "PersistenceIoError",
    "PersistenceFormatError",
    "PersistenceVersionUnsupported",
    "TransportError",
    "ProtocolError",
    "ProtocolTruncated",
    "ProtocolOversized",
    "ProtocolMalformed",
    "ConnectionClosed",
    "InternalError",
    "InvariantViolation",
};

static_assert(sizeof(kCodeNames) / sizeof(kCodeNames[0]) ==
                  static_cast<std::size_t>(ErrorCode::InvariantViolation) + 1,
              "every ErrorCode needs a name");

std::string quote(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 2);
    out.push_back('"');
    out.append(text);
    out.push_back('"');
    return out;
}

}  // namespace

const char* to_string(ErrorCode code) noexcept {
    const auto index = static_cast<std::size_t>(code);
    if (index >= sizeof(kCodeNames) / sizeof(kCodeNames[0])) {
        return "Unknown";
    }
    return kCodeNames[index];
}

bool is_retryable(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::ReservationHeld:
        case ErrorCode::ReservationLost:
        case ErrorCode::CommitUncertain:
        case ErrorCode::TransportError:
        case ErrorCode::ProtocolTruncated:
        case ErrorCode::ConnectionClosed:
        case ErrorCode::ShuttingDown:
        case ErrorCode::AdmissionRejected:
        case ErrorCode::EvidenceStale:
        case ErrorCode::AuthorityStale:
        case ErrorCode::PolicyStale:
        case ErrorCode::PlanExpired:
        case ErrorCode::ArtifactGenerationStale:
        case ErrorCode::PolicyGenerationStale:
        case ErrorCode::StaleEvidenceGeneration:
            return true;
        default:
            return false;
    }
}

bool is_transport_failure(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::TransportError:
        case ErrorCode::ProtocolError:
        case ErrorCode::ProtocolTruncated:
        case ErrorCode::ProtocolOversized:
        case ErrorCode::ProtocolMalformed:
        case ErrorCode::ConnectionClosed:
            return true;
        default:
            return false;
    }
}

bool is_semantic_failure(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::EvidenceMissing:
        case ErrorCode::EvidenceMismatch:
        case ErrorCode::EvidenceRevoked:
        case ErrorCode::EvidenceMalformed:
        case ErrorCode::EvidenceIntegrityFailure:
        case ErrorCode::ArtifactMismatch:
        case ErrorCode::DigestMismatch:
        case ErrorCode::ArtifactQuarantined:
        case ErrorCode::ArtifactRevoked:
        case ErrorCode::ArtifactSuperseded:
        case ErrorCode::ArtifactRetired:
        case ErrorCode::PolicyViolation:
        case ErrorCode::TransitionIllegal:
        case ErrorCode::CompatibilityFailed:
        case ErrorCode::ProvenanceMissing:
        case ErrorCode::ProvenanceMismatch:
        case ErrorCode::SecurityVeto:
        case ErrorCode::DependencyVeto:
        case ErrorCode::ApprovalRequired:
        case ErrorCode::NotAuthorized:
        case ErrorCode::Conflict:
            return true;
        default:
            return false;
    }
}

bool operator==(const StaticString& lhs, const StaticString& rhs) noexcept {
    return lhs.view() == rhs.view();
}

bool operator!=(const StaticString& lhs, const StaticString& rhs) noexcept {
    return !(lhs == rhs);
}

std::string Reason::render() const {
    std::string out;
    out.append(to_string(code));
    if (!text.empty()) {
        out.append(": ");
        out.append(text.view());
    }
    if (!subject.empty()) {
        out.append(" [subject=");
        out.append(subject);
        out.push_back(']');
    }
    return out;
}

std::string Status::render() const {
    std::string out;
    out.append(to_string(code_));
    if (!message_.empty()) {
        out.append(": ");
        out.append(message_.view());
    }
    if (!subject_.empty()) {
        out.append(" [subject=");
        out.append(subject_);
        out.push_back(']');
    }
    return out;
}

}  // namespace artifact_promotion
