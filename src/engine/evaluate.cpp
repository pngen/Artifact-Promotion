// Artifact Promotion - hard gate evaluation and deterministic decisions.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <sstream>

#include "artifact_promotion/detail/writer.hpp"
#include "artifact_promotion/engine.hpp"

namespace artifact_promotion {
namespace {

[[nodiscard]] Status detached(ErrorCode code, std::string_view message, std::string subject = {}) {
    return Status(code, message, std::move(subject));
}

[[nodiscard]] std::string evidence_label(EvidenceType type, const std::string& custom) {
    if (type == EvidenceType::Custom) {
        return custom.empty() ? std::string("CUSTOM") : custom;
    }
    return std::string(to_string(type));
}

[[nodiscard]] bool gate_targets(EvidenceType gate_type, const std::string& gate_custom, const EvidenceRecord& record) {
    if (gate_type != record.type) {
        return false;
    }
    if (gate_type == EvidenceType::Custom) {
        return gate_custom == record.custom_type;
    }
    return true;
}

// Deterministic order over current evidence for one artifact revision. The
// order is total and independent of container iteration order.
[[nodiscard]] std::vector<const EvidenceRecord*> gather_evidence(const CoordinatorState& state, ArtifactId subject,
                                                                 ArtifactRevision revision) {
    std::vector<const EvidenceRecord*> found;
    for (const auto& [id, record] : state.evidence) {
        (void)id;
        if (record.subject != subject || record.subject_revision != revision) {
            continue;
        }
        found.push_back(&record);
    }
    std::sort(found.begin(), found.end(), [](const EvidenceRecord* lhs, const EvidenceRecord* rhs) {
        if (lhs->type != rhs->type) {
            return lhs->type < rhs->type;
        }
        if (lhs->custom_type != rhs->custom_type) {
            return lhs->custom_type < rhs->custom_type;
        }
        return lhs->id < rhs->id;
    });
    return found;
}

// The newest non-revoked, non-superseded evidence of a given class for the
// exact artifact revision, selected by ingestion sequence.
[[nodiscard]] const EvidenceRecord* newest_evidence(const std::vector<const EvidenceRecord*>& evidence,
                                                    EvidenceType type, const std::string& custom) {
    const EvidenceRecord* best = nullptr;
    for (const EvidenceRecord* record : evidence) {
        if (!gate_targets(type, custom, *record)) {
            continue;
        }
        if (record->revoked || record->superseded) {
            continue;
        }
        if (best == nullptr || best->created_sequence < record->created_sequence) {
            best = record;
        }
    }
    return best;
}

[[nodiscard]] const EvidenceRecord* newest_evidence(const std::vector<const EvidenceRecord*>& evidence,
                                                    EvidenceType type) {
    return newest_evidence(evidence, type, std::string{});
}

struct Finding {
    EvidenceId id{};
    EvidenceType type = EvidenceType::Invalid;
    std::string custom_type{};
    EvidenceGeneration generation{};
    EvidenceResult result = EvidenceResult::Unknown;
    Digest subject_digest{};
    ArtifactRevision subject_revision{};
    ErrorCode code = ErrorCode::Ok;
    std::string detail{};
};

[[nodiscard]] Finding make_finding(const EvidenceRecord& record, ErrorCode code, std::string detail) {
    Finding finding;
    finding.id = record.id;
    finding.type = record.type;
    finding.custom_type = record.custom_type;
    finding.generation = record.generation;
    finding.result = record.result;
    finding.subject_digest = record.subject_digest;
    finding.subject_revision = record.subject_revision;
    finding.code = code;
    finding.detail = std::move(detail);
    return finding;
}

// Selects the best available evidence of a class for a gate. Evidence for a
// different revision or a different digest is never silently substituted: the
// best match is reported so the caller can produce a precise explanation.
[[nodiscard]] const EvidenceRecord* select_evidence_for_gate(const std::vector<const EvidenceRecord*>& evidence,
                                                             const Gate& gate, const Digest& artifact_digest,
                                                             ArtifactRevision revision,
                                                             ErrorCode& code, std::string& detail) {
    const EvidenceRecord* exact = nullptr;
    const EvidenceRecord* mismatched_digest = nullptr;
    const EvidenceRecord* stale_revision = nullptr;
    const EvidenceRecord* revoked = nullptr;
    const EvidenceRecord* superseded = nullptr;

    for (const EvidenceRecord* record : evidence) {
        if (!gate_targets(gate.evidence_type, gate.custom_evidence_type, *record)) {
            continue;
        }
        if (record->subject_digest != artifact_digest) {
            if (mismatched_digest == nullptr || mismatched_digest->created_sequence < record->created_sequence) {
                mismatched_digest = record;
            }
            continue;
        }
        if (record->subject_revision != revision) {
            if (stale_revision == nullptr || stale_revision->created_sequence < record->created_sequence) {
                stale_revision = record;
            }
            continue;
        }
        if (record->revoked) {
            if (revoked == nullptr || revoked->created_sequence < record->created_sequence) {
                revoked = record;
            }
            continue;
        }
        if (record->superseded) {
            if (superseded == nullptr || superseded->created_sequence < record->created_sequence) {
                superseded = record;
            }
            continue;
        }
        if (exact == nullptr || exact->created_sequence < record->created_sequence) {
            exact = record;
        }
    }

    if (exact != nullptr) {
        code = ErrorCode::Ok;
        detail.clear();
        return exact;
    }
    if (revoked != nullptr) {
        code = ErrorCode::EvidenceRevoked;
        detail = "the matching evidence record was explicitly revoked";
        return revoked;
    }
    if (superseded != nullptr) {
        code = ErrorCode::EvidenceSuperseded;
        detail = "the matching evidence record was superseded by a newer record";
        return superseded;
    }
    if (mismatched_digest != nullptr) {
        code = ErrorCode::EvidenceMismatch;
        detail = "evidence exists for this artifact but for a different content digest";
        return mismatched_digest;
    }
    if (stale_revision != nullptr) {
        code = ErrorCode::ArtifactGenerationStale;
        detail = "evidence exists only for a previous revision of this artifact";
        return stale_revision;
    }
    code = ErrorCode::EvidenceMissing;
    detail = "no evidence of the required class exists for this artifact revision";
    return nullptr;
}

[[nodiscard]] PromotionOutcome outcome_for_requirement(ErrorCode code) {
    switch (code) {
        case ErrorCode::EvidenceMissing:
        case ErrorCode::EvidenceMalformed:
            return PromotionOutcome::EvidenceMissing;
        case ErrorCode::EvidenceStale:
            return PromotionOutcome::EvidenceStale;
        case ErrorCode::EvidenceRevoked:
            return PromotionOutcome::EvidenceRevoked;
        case ErrorCode::EvidenceMismatch:
            return PromotionOutcome::EvidenceMismatch;
        case ErrorCode::ArtifactGenerationStale:
            return PromotionOutcome::RevalidationRequired;
        case ErrorCode::EvidenceIntegrityFailure:
            return PromotionOutcome::EvidenceMismatch;
        case ErrorCode::EnvironmentMismatch:
            return PromotionOutcome::EvidenceMismatch;
        case ErrorCode::OrderingViolation:
            return PromotionOutcome::RevalidationRequired;
        case ErrorCode::CompatibilityFailed:
            return PromotionOutcome::CompatibilityFailed;
        case ErrorCode::ProvenanceMissing:
            return PromotionOutcome::ProvenanceMissing;
        case ErrorCode::ProvenanceMismatch:
            return PromotionOutcome::ProvenanceMissing;
        case ErrorCode::ApprovalRequired:
            return PromotionOutcome::ApprovalRequired;
        case ErrorCode::SecurityVeto:
            return PromotionOutcome::SecurityVeto;
        case ErrorCode::DependencyVeto:
            return PromotionOutcome::DependencyVeto;
        case ErrorCode::ArtifactQuarantined:
            return PromotionOutcome::Quarantined;
        case ErrorCode::ArtifactRevoked:
            return PromotionOutcome::Revoked;
        case ErrorCode::ArtifactSuperseded:
            return PromotionOutcome::Superseded;
        case ErrorCode::PolicyGenerationStale:
        case ErrorCode::PolicyStale:
            return PromotionOutcome::PolicyStale;
        case ErrorCode::StaleCoordinatorEpoch:
            return PromotionOutcome::AuthorityStale;
        case ErrorCode::Conflict:
        case ErrorCode::ReservationHeld:
            return PromotionOutcome::Conflict;
        case ErrorCode::ArtifactMismatch:
        case ErrorCode::DigestMismatch:
        case ErrorCode::InvalidDigest:
            return PromotionOutcome::DigestMismatch;
        case ErrorCode::TransitionIllegal:
            return PromotionOutcome::TransitionIllegal;
        case ErrorCode::Unsupported:
            return PromotionOutcome::Unsupported;
        default:
            return PromotionOutcome::PromotionIneligible;
    }
}

[[nodiscard]] ErrorCode gate_error_code(GateKind kind, ErrorCode default_code) {
    switch (kind) {
        case GateKind::ArtifactIdentity:
            return ErrorCode::InvalidIdentity;
        case GateKind::EvidenceIntegrity:
            return ErrorCode::EvidenceIntegrityFailure;
        case GateKind::ArtifactNotQuarantined:
            return ErrorCode::ArtifactQuarantined;
        case GateKind::ArtifactNotRevoked:
            return ErrorCode::ArtifactRevoked;
        case GateKind::ArtifactNotSuperseded:
            return ErrorCode::ArtifactSuperseded;
        case GateKind::ProvenanceRequired:
        case GateKind::ProvenanceResolved:
            return ErrorCode::ProvenanceMissing;
        case GateKind::CompatibilityGenerationCurrent:
            return ErrorCode::CompatibilityFailed;
        case GateKind::EnvironmentBinding:
            return ErrorCode::EnvironmentMismatch;
        case GateKind::DependentArtifactPromoted:
            return ErrorCode::DependencyVeto;
        case GateKind::ApprovalRequired:
            return ErrorCode::ApprovalRequired;
        case GateKind::SecurityVetoClear:
            return ErrorCode::SecurityVeto;
        case GateKind::DependencyVetoClear:
            return ErrorCode::DependencyVeto;
        case GateKind::PolicyGenerationCurrent:
            return ErrorCode::PolicyGenerationStale;
        case GateKind::CoordinatorEpochCurrent:
            return ErrorCode::StaleCoordinatorEpoch;
        case GateKind::NoConflictingTransition:
            return ErrorCode::Conflict;
        default:
            return default_code;
    }
}

}  // namespace

Digest compute_request_digest(const PromotionRequest& request) {
    wire::Writer writer(128);
    writer.identity(request.artifact);
    writer.identity(request.expected_revision);
    writer.digest(request.expected_digest);
    writer.u8(static_cast<std::uint8_t>(request.requested_stage));
    return sha256(writer.buffer());
}

PromotionEngine::GateOutcome PromotionEngine::evaluate_gates(const CoordinatorState& state,
                                                             const PromotionRequest& request, std::uint64_t now,
                                                             PromotionDecision& decision,
                                                             std::vector<EvidenceSnapshotEntry>& snapshot_entries) const {
    GateOutcome result;

    const ArtifactRecord* artifact = state.find_revision(request.artifact, request.expected_revision);
    if (artifact == nullptr) {
        result.failed = true;
        result.outcome = PromotionOutcome::ArtifactNotFound;
        decision.reasons.push_back(Reason(ErrorCode::ArtifactNotFound,
                                          "the requested artifact revision is not registered under this coordinator",
                                          request.artifact.to_string()));
        return result;
    }

    decision.artifact = artifact->id;
    decision.artifact_revision = artifact->revision;
    decision.artifact_generation = artifact->generation;
    decision.artifact_digest = artifact->digest;
    decision.artifact_kind = artifact->kind;
    decision.from = artifact->stage;
    decision.to = request.requested_stage;

    const PromotionPolicy& policy = state.policy();
    const PolicyRule* rule = policy.find_rule(artifact->kind, artifact->stage, request.requested_stage);

    // Legal transition and policy coverage are hard requirements that precede
    // every other gate: an artifact cannot be evaluated against a rule that
    // does not exist.
    if (rule == nullptr) {
        const bool graph_allows = policy.graph.has_edge(artifact->stage, request.requested_stage);
        result.failed = true;
        result.outcome = graph_allows ? PromotionOutcome::Unsupported : PromotionOutcome::TransitionIllegal;
        decision.reasons.push_back(
            Reason(graph_allows ? ErrorCode::Unsupported : ErrorCode::TransitionIllegal,
                   graph_allows ? "the lifecycle permits this transition but no active policy rule governs it"
                                : "the lifecycle graph does not permit this transition",
                   std::string(to_string(artifact->stage)) + "->" + to_string(request.requested_stage)));
        return result;
    }

    // Evidence snapshot of the exact artifact revision.
    const std::vector<const EvidenceRecord*> evidence = gather_evidence(state, artifact->id, artifact->revision);
    for (const EvidenceRecord* record : evidence) {
        if (record->revoked || record->superseded) {
            continue;
        }
        EvidenceSnapshotEntry entry;
        entry.id = record->id;
        entry.type = record->type;
        entry.custom_type = record->custom_type;
        entry.generation = record->generation;
        entry.result = record->result;
        entry.subject_digest = record->subject_digest;
        entry.subject_revision = record->subject_revision;
        entry.producer = record->producer;
        entry.integrity_digest = record->integrity_digest;
        snapshot_entries.push_back(entry);
    }
    decision.evidence_snapshot_digest =
        compute_snapshot_digest(artifact->id, artifact->revision, artifact->digest, snapshot_entries);

    const VetoState* vetoes = nullptr;
    const auto veto_it = state.vetoes.find(artifact->id);
    if (veto_it != state.vetoes.end()) {
        vetoes = &veto_it->second;
    }

    // Resolves the evidence a gate refers to. The resolution code is part of the
    // answer, not a side channel: a record that exists but is revoked,
    // superseded, or bound to a different digest must fail the gate even though
    // a record object was returned for the explanation. Treating "a record was
    // found" as "the gate is satisfied" is the exact failure mode that would let
    // a withdrawn security scan, signature, or approval keep authorizing a
    // promotion.
    const auto resolve_gate_evidence = [&](const Gate& gate, ErrorCode& code, std::string& detail,
                                           const EvidenceRecord*& record) {
        record = nullptr;
        code = ErrorCode::Ok;
        detail.clear();
        if (!is_valid_evidence_type(static_cast<std::uint64_t>(gate.evidence_type)) ||
            gate.evidence_type == EvidenceType::Invalid) {
            code = ErrorCode::InvalidEnum;
            detail = "policy gate names no evidence class";
            return;
        }
        const EvidenceRecord* found = select_evidence_for_gate(evidence, gate, artifact->digest,
                                                              artifact->revision, code, detail);
        if (found == nullptr) {
            // code and detail already describe why nothing applied.
            return;
        }
        record = found;
        if (code != ErrorCode::Ok) {
            // The record exists but is not applicable: it is revoked, superseded,
            // bound to a different digest, or bound to another revision.
            return;
        }
        if (found->result != EvidenceResult::Pass) {
            code = ErrorCode::PolicyViolation;
            detail = std::string("evidence result is ") + to_string(found->result);
        }
    };

    bool first_failure = true;
    for (const Gate& gate : rule->requirements) {
        GateExplanation explanation;
        explanation.kind = gate.kind;
        explanation.label = gate.label;
        explanation.status = GateStatus::Satisfied;
        explanation.code = ErrorCode::Ok;

        ErrorCode code = ErrorCode::Ok;
        std::string detail;
        const EvidenceRecord* referenced = nullptr;

        switch (gate.kind) {
            case GateKind::ArtifactIdentity: {
                if (artifact->id.invalid() || artifact->digest.invalid() || artifact->revision.invalid() ||
                    artifact->kind == ArtifactKind::Invalid) {
                    code = ErrorCode::InvalidIdentity;
                    detail = "artifact identity, digest, revision, or class is not well formed";
                }
                break;
            }
            case GateKind::EvidenceIntegrity: {
                for (const EvidenceRecord* record : evidence) {
                    if (record->revoked || record->superseded) {
                        continue;
                    }
                    if (compute_evidence_integrity(*record) != record->integrity_digest) {
                        code = ErrorCode::EvidenceIntegrityFailure;
                        detail = "an evidence record failed its integrity check";
                        referenced = record;
                        break;
                    }
                }
                break;
            }
            case GateKind::ArtifactNotQuarantined: {
                if (artifact->quarantine.active) {
                    code = ErrorCode::ArtifactQuarantined;
                    detail = "artifact is quarantined: " + artifact->quarantine.reason_class;
                }
                break;
            }
            case GateKind::ArtifactNotRevoked: {
                if (artifact->revocation.active) {
                    code = ErrorCode::ArtifactRevoked;
                    detail = "artifact promotion authority was revoked: " + artifact->revocation.reason_class;
                }
                break;
            }
            case GateKind::ArtifactNotSuperseded: {
                if (artifact->supersession.active) {
                    code = ErrorCode::ArtifactSuperseded;
                    detail = "artifact was superseded by a newer artifact";
                }
                break;
            }
            case GateKind::ProvenanceRequired: {
                bool present = false;
                bool rejected = false;
                for (const ProvenanceRecord& record : artifact->provenance) {
                    if (record.reference != gate.required_provenance) {
                        continue;
                    }
                    present = true;
                    if (record.resolution == ProvenanceResolution::Rejected) {
                        rejected = true;
                    }
                }
                if (!present) {
                    code = ErrorCode::ProvenanceMissing;
                    detail = "the required provenance reference is not attached to this artifact revision";
                } else if (rejected) {
                    code = ErrorCode::ProvenanceMismatch;
                    detail = "the required provenance reference was rejected by its source system";
                }
                break;
            }
            case GateKind::ProvenanceResolved: {
                if (artifact->provenance.empty()) {
                    code = ErrorCode::ProvenanceMissing;
                    detail = "the artifact revision carries no provenance references";
                    break;
                }
                bool rejected = false;
                bool unresolved = false;
                for (const ProvenanceRecord& record : artifact->provenance) {
                    if (record.resolution == ProvenanceResolution::Rejected) {
                        rejected = true;
                    }
                    if (record.resolution != ProvenanceResolution::Resolved) {
                        unresolved = true;
                    }
                }
                if (rejected) {
                    code = ErrorCode::ProvenanceMismatch;
                    detail = "a provenance reference was rejected by its source system";
                } else if (unresolved) {
                    code = ErrorCode::ProvenanceMissing;
                    detail = "a provenance reference has not been resolved by its source system";
                }
                break;
            }
            case GateKind::CompatibilityGenerationCurrent: {
                if (state.compatibility_generation != gate.required_compatibility_generation) {
                    code = ErrorCode::CompatibilityFailed;
                    detail = "compatibility generation " + state.compatibility_generation.to_string() +
                             " does not match the generation the policy requires (" +
                             gate.required_compatibility_generation.to_string() + ')';
                }
                break;
            }
            case GateKind::EnvironmentBinding: {
                ErrorCode select_code = ErrorCode::Ok;
                std::string select_detail;
                const EvidenceRecord* record = nullptr;
                resolve_gate_evidence(gate, select_code, select_detail, record);
                if (select_code != ErrorCode::Ok) {
                    code = select_code;
                    detail = select_detail;
                    referenced = record;
                } else if (record != nullptr && record->environment != gate.required_environment) {
                    code = ErrorCode::EnvironmentMismatch;
                    detail = "evidence was produced in environment '" + record->environment +
                             "' but the policy requires '" + gate.required_environment + "'";
                    referenced = record;
                }
                break;
            }
            case GateKind::DependentArtifactPromoted: {
                for (const std::string& dependency : artifact->dependencies) {
                    bool matched = false;
                    for (const auto& [dependency_id, revisions] : state.artifacts) {
                        (void)dependency_id;
                        if (revisions.empty()) {
                            continue;
                        }
                        const ArtifactRecord& current = revisions.back();
                        if (current.name != dependency) {
                            continue;
                        }
                        matched = true;
                        if (!current.currently_authoritative()) {
                            code = ErrorCode::DependencyVeto;
                            detail = "dependency '" + dependency + "' exists but is not currently promoted";
                            break;
                        }
                    }
                    if (code != ErrorCode::Ok) {
                        break;
                    }
                    if (!matched) {
                        result.failed = true;
                        result.outcome = PromotionOutcome::ProvenanceMissing;
                        explanation.status = GateStatus::Unknown;
                        explanation.code = ErrorCode::OrderingViolation;
                        explanation.detail = "dependency '" + dependency + "' has never been registered";
                        decision.gates.push_back(explanation);
                        decision.reasons.push_back(Reason(ErrorCode::OrderingViolation,
                                                          "a declared dependency has never been registered",
                                                          dependency));
                        return result;
                    }
                }
                break;
            }
            case GateKind::ApprovalRequired: {
                ErrorCode select_code = ErrorCode::Ok;
                std::string select_detail;
                const EvidenceRecord* record = nullptr;
                resolve_gate_evidence(gate, select_code, select_detail, record);
                if (select_code != ErrorCode::Ok) {
                    code = select_code == ErrorCode::PolicyViolation ? ErrorCode::ApprovalRequired : select_code;
                    detail = select_detail;
                    referenced = record;
                }
                break;
            }
            case GateKind::SecurityVetoClear: {
                if (vetoes != nullptr && vetoes->security_veto) {
                    code = ErrorCode::SecurityVeto;
                    detail = "an open security veto blocks promotion: " + vetoes->security_reason;
                }
                break;
            }
            case GateKind::DependencyVetoClear: {
                if (vetoes != nullptr && vetoes->dependency_veto) {
                    code = ErrorCode::DependencyVeto;
                    detail = "an open dependency veto blocks promotion: " + vetoes->dependency_reason;
                }
                break;
            }
            case GateKind::PolicyGenerationCurrent: {
                if (!request.authority.epoch.valid()) {
                    code = ErrorCode::StaleCoordinatorEpoch;
                    detail = "the request carries no coordinator epoch";
                    break;
                }
                if (decision.policy_generation != state.active_policy_generation) {
                    code = ErrorCode::PolicyGenerationStale;
                    detail = "the decision was formed under policy generation " +
                             decision.policy_generation.to_string() + " but the active generation is " +
                             state.active_policy_generation.to_string();
                }
                break;
            }
            case GateKind::CoordinatorEpochCurrent: {
                if (request.authority.coordinator != state.coordinator) {
                    code = ErrorCode::StaleCoordinatorEpoch;
                    detail = "the request was addressed to a different coordinator identity";
                    break;
                }
                if (request.authority.epoch != state.epoch) {
                    code = ErrorCode::StaleCoordinatorEpoch;
                    detail = "the request carries coordinator epoch " + request.authority.epoch.to_string() +
                             " but the current epoch is " + state.epoch.to_string();
                }
                break;
            }
            case GateKind::NoConflictingTransition: {
                const auto pending_it = state.pending.find(artifact->id);
                if (pending_it != state.pending.end()) {
                    const PendingTransition& pending = pending_it->second;
                    const bool same_attempt = pending.request == request.request &&
                                              pending.attempt == request.attempt;
                    if (!same_attempt) {
                        code = ErrorCode::ReservationHeld;
                        detail = "another promotion attempt holds a reservation on this artifact";
                    }
                }
                break;
            }
            case GateKind::EvidenceRequired:
            case GateKind::EvidenceFreshness: {
                ErrorCode select_code = ErrorCode::Ok;
                std::string select_detail;
                const EvidenceRecord* record = nullptr;
                resolve_gate_evidence(gate, select_code, select_detail, record);
                referenced = record;
                if (select_code != ErrorCode::Ok) {
                    code = select_code;
                    detail = select_detail;
                    break;
                }
                if (record == nullptr) {
                    code = ErrorCode::EvidenceMissing;
                    detail = "no evidence of the required class exists for this artifact revision";
                    break;
                }
                if (gate.kind == GateKind::EvidenceFreshness) {
                    const std::uint64_t produced = record->produced_unix_millis;
                    const std::uint64_t skew = config_.future_skew_tolerance_millis;
                    if (produced > now + skew) {
                        code = ErrorCode::EvidenceStale;
                        detail = "evidence was produced after the evaluation instant and cannot be trusted";
                        break;
                    }
                    const std::uint64_t age = now - produced;
                    if (age > gate.max_age_millis) {
                        code = ErrorCode::EvidenceStale;
                        detail = "evidence age " + std::to_string(age) + " ms exceeds the policy limit " +
                                 std::to_string(gate.max_age_millis) + " ms";
                        break;
                    }
                }
                if (record->has_validity_window) {
                    if (now < record->valid_from_unix_millis || now > record->valid_until_unix_millis) {
                        code = ErrorCode::EvidenceStale;
                        detail = "the evaluation instant is outside the evidence validity window";
                    }
                }
                break;
            }
            case GateKind::Invalid:
                code = ErrorCode::InvalidEnum;
                detail = "policy contains an invalid gate";
                break;
        }

        if (code != ErrorCode::Ok) {
            explanation.status = (code == ErrorCode::EvidenceMissing || code == ErrorCode::ProvenanceMissing)
                                     ? GateStatus::Unknown
                                     : GateStatus::Failed;
            explanation.code = code;
            explanation.detail = detail;
            decision.gates.push_back(explanation);
            decision.reasons.push_back(Reason(code, detail, gate.label));
            if (referenced != nullptr) {
                const Finding finding = make_finding(*referenced, code, detail);
                decision.findings.push_back(EvidenceFinding{finding.id,
                                                            finding.type,
                                                            finding.custom_type,
                                                            finding.generation,
                                                            finding.result,
                                                            finding.subject_digest,
                                                            finding.subject_revision,
                                                            finding.code,
                                                            finding.detail});
            }
            if (first_failure) {
                first_failure = false;
                result.failed = true;
                result.outcome = outcome_for_requirement(gate_error_code(gate.kind, code));
            }
            continue;
        }

        decision.gates.push_back(explanation);
    }

    if (!result.failed) {
        result.outcome = PromotionOutcome::PromotionEligible;
    }
    return result;
}

}  // namespace artifact_promotion
