// Artifact Promotion - deterministic promotion decisions and explanations.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/decision.hpp"

#include <array>
#include <sstream>

namespace artifact_promotion {
namespace {

struct OutcomeName {
    PromotionOutcome outcome;
    const char* name;
};

constexpr std::array<OutcomeName, 30> kOutcomeNames = {{
    {PromotionOutcome::Invalid, "INVALID"},
    {PromotionOutcome::PromotionEligible, "PROMOTION_ELIGIBLE"},
    {PromotionOutcome::PromotionCommitted, "PROMOTION_COMMITTED"},
    {PromotionOutcome::PromotionIneligible, "PROMOTION_INELIGIBLE"},
    {PromotionOutcome::RevalidationRequired, "REVALIDATION_REQUIRED"},
    {PromotionOutcome::EvidenceMissing, "EVIDENCE_MISSING"},
    {PromotionOutcome::EvidenceStale, "EVIDENCE_STALE"},
    {PromotionOutcome::EvidenceRevoked, "EVIDENCE_REVOKED"},
    {PromotionOutcome::EvidenceMismatch, "EVIDENCE_MISMATCH"},
    {PromotionOutcome::ArtifactMismatch, "ARTIFACT_MISMATCH"},
    {PromotionOutcome::DigestMismatch, "DIGEST_MISMATCH"},
    {PromotionOutcome::TransitionIllegal, "TRANSITION_ILLEGAL"},
    {PromotionOutcome::PolicyStale, "POLICY_STALE"},
    {PromotionOutcome::CompatibilityFailed, "COMPATIBILITY_FAILED"},
    {PromotionOutcome::ApprovalRequired, "APPROVAL_REQUIRED"},
    {PromotionOutcome::Quarantined, "QUARANTINED"},
    {PromotionOutcome::Revoked, "REVOKED"},
    {PromotionOutcome::Superseded, "SUPERSEDED"},
    {PromotionOutcome::Conflict, "CONFLICT"},
    {PromotionOutcome::AlreadyPromoted, "ALREADY_PROMOTED"},
    {PromotionOutcome::OutcomeUnknown, "OUTCOME_UNKNOWN"},
    {PromotionOutcome::Unsupported, "UNSUPPORTED"},
    {PromotionOutcome::ArtifactNotFound, "ARTIFACT_NOT_FOUND"},
    {PromotionOutcome::PolicyNotFound, "POLICY_NOT_FOUND"},
    {PromotionOutcome::Cancelled, "CANCELLED"},
    {PromotionOutcome::AuthorityStale, "AUTHORITY_STALE"},
    {PromotionOutcome::ProvenanceMissing, "PROVENANCE_MISSING"},
    {PromotionOutcome::SecurityVeto, "SECURITY_VETO"},
    {PromotionOutcome::DependencyVeto, "DEPENDENCY_VETO"},
    {PromotionOutcome::AdmissionRejected, "ADMISSION_REJECTED"},
}};

}  // namespace

const char* to_string(PromotionOutcome outcome) noexcept {
    for (const auto& entry : kOutcomeNames) {
        if (entry.outcome == outcome) {
            return entry.name;
        }
    }
    return "INVALID";
}

bool is_valid_promotion_outcome(std::uint64_t raw) noexcept {
    return raw >= 1 && raw <= static_cast<std::uint64_t>(PromotionOutcome::AdmissionRejected);
}

const char* to_string(GateStatus status) noexcept {
    switch (status) {
        case GateStatus::NotEvaluated:
            return "NOT_EVALUATED";
        case GateStatus::Satisfied:
            return "SATISFIED";
        case GateStatus::Failed:
            return "FAILED";
        case GateStatus::Unknown:
            return "UNKNOWN";
        case GateStatus::NotApplicable:
            return "NOT_APPLICABLE";
    }
    return "NOT_EVALUATED";
}

std::string GateExplanation::render() const {
    std::ostringstream out;
    out << to_string(kind) << ' ' << to_string(status);
    if (!label.empty()) {
        out << " (" << label << ')';
    }
    if (code != ErrorCode::Ok) {
        out << " code=" << to_string(code);
    }
    if (!detail.empty()) {
        out << " detail=" << detail;
    }
    return out.str();
}

std::size_t PromotionDecision::failed_gate_count() const noexcept {
    std::size_t count = 0;
    for (const GateExplanation& gate : gates) {
        if (gate.status == GateStatus::Failed || gate.status == GateStatus::Unknown) {
            ++count;
        }
    }
    return count;
}

std::vector<std::string> PromotionDecision::failed_gate_labels() const {
    std::vector<std::string> labels;
    for (const GateExplanation& gate : gates) {
        if (gate.status == GateStatus::Failed || gate.status == GateStatus::Unknown) {
            labels.push_back(gate.label.empty() ? std::string(to_string(gate.kind)) : gate.label);
        }
    }
    return labels;
}

std::string PromotionDecision::render() const {
    std::ostringstream out;
    out << "decision=" << id.to_string() << " outcome=" << to_string(outcome)
        << " artifact=" << artifact.to_string() << " revision=" << artifact_revision.to_string()
        << " digest=" << artifact_digest.to_string() << " transition=" << to_string(from) << "->"
        << to_string(to) << " policy=" << policy.to_string() << "#" << policy_generation.to_string()
        << " authority=" << authority.coordinator.to_string() << "@" << authority.epoch.to_string()
        << " sequence=" << sequence.to_string() << " authoritative=" << (authoritative ? "true" : "false");
    for (const GateExplanation& gate : gates) {
        out << '\n' << "  gate " << gate.render();
    }
    for (const Reason& reason : reasons) {
        out << '\n' << "  reason " << reason.render();
    }
    for (const EvidenceFinding& finding : findings) {
        out << '\n' << "  evidence " << finding.id.to_string() << " type=" << to_string(finding.type)
            << " subject_revision=" << finding.subject_revision.to_string()
            << " subject_digest=" << finding.subject_digest.to_string() << " code=" << to_string(finding.code)
            << " detail=" << finding.detail;
    }
    return out.str();
}

bool PromotionPlan::valid() const noexcept {
    return id.valid() && request.valid() && attempt.valid() && decision.valid() && artifact.valid() &&
           artifact_revision.valid() && artifact_generation.valid() && artifact_digest.valid() &&
           artifact_kind != ArtifactKind::Invalid && from != Stage::Invalid && to != Stage::Invalid &&
           stage_generation.valid() && policy.valid() && policy_generation.valid() && policy_digest.valid() &&
           lifecycle_digest.valid() && authority.valid() && evidence_snapshot_digest.valid() &&
           created_sequence.valid() && decision_sequence.valid();
}

std::string PromotionPlan::render() const {
    std::ostringstream out;
    out << "plan=" << id.to_string() << " artifact=" << artifact.to_string()
        << " revision=" << artifact_revision.to_string() << " generation=" << artifact_generation.to_string()
        << " digest=" << artifact_digest.to_string() << " transition=" << to_string(from) << "->"
        << to_string(to) << " stage_generation=" << stage_generation.to_string()
        << " policy=" << policy.to_string() << "#" << policy_generation.to_string()
        << " authority=" << authority.coordinator.to_string() << "@" << authority.epoch.to_string()
        << " evidence_snapshot=" << evidence_snapshot_digest.to_string()
        << " compatibility=" << compatibility_profile.to_string() << "#"
        << compatibility_generation.to_string() << " created_sequence=" << created_sequence.to_string();
    if (has_expiry) {
        out << " expires_unix_millis=" << expires_unix_millis;
    }
    return out.str();
}

bool PromotionRecord::valid() const noexcept {
    // A record that promotes an artifact must name the decision that authorized
    // it: that is the whole point of the audit trail. A record that describes a
    // supersession, a retirement, or a quarantine release is not produced by a
    // promotion decision and therefore does not fabricate one.
    const bool decision_requirement = to != Stage::Promoted || decision.valid();
    return transition.valid() && artifact.valid() && artifact_revision.valid() && artifact_digest.valid() &&
           from != Stage::Invalid && to != Stage::Invalid && decision_requirement && policy.valid() &&
           policy_generation.valid() && authority.valid() && evidence_snapshot_digest.valid() &&
           sequence.valid();
}

}  // namespace artifact_promotion
