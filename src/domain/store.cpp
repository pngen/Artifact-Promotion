// Artifact Promotion - authoritative coordinator state.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/store.hpp"

#include <set>

namespace artifact_promotion {

const char* to_string(HistoryEventKind kind) noexcept {
    switch (kind) {
        case HistoryEventKind::Invalid:
            return "INVALID";
        case HistoryEventKind::ArtifactRegistered:
            return "ARTIFACT_REGISTERED";
        case HistoryEventKind::ArtifactSupersededRegistration:
            return "ARTIFACT_SUPERSEDED_REGISTRATION";
        case HistoryEventKind::EvidenceSubmitted:
            return "EVIDENCE_SUBMITTED";
        case HistoryEventKind::EvidenceSuperseded:
            return "EVIDENCE_SUPERSEDED";
        case HistoryEventKind::EvidenceRevoked:
            return "EVIDENCE_REVOKED";
        case HistoryEventKind::PolicyPublished:
            return "POLICY_PUBLISHED";
        case HistoryEventKind::PromotionEvaluated:
            return "PROMOTION_EVALUATED";
        case HistoryEventKind::PromotionCommitted:
            return "PROMOTION_COMMITTED";
        case HistoryEventKind::PromotionRejected:
            return "PROMOTION_REJECTED";
        case HistoryEventKind::Quarantined:
            return "QUARANTINED";
        case HistoryEventKind::QuarantineReleased:
            return "QUARANTINE_RELEASED";
        case HistoryEventKind::Revoked:
            return "REVOKED";
        case HistoryEventKind::Superseded:
            return "SUPERSEDED";
        case HistoryEventKind::Retired:
            return "RETIRED";
        case HistoryEventKind::RecoveryNote:
            return "RECOVERY_NOTE";
    }
    return "INVALID";
}

const ArtifactRecord* CoordinatorState::find_current(ArtifactId id) const {
    const auto it = artifacts.find(id);
    if (it == artifacts.end() || it->second.empty()) {
        return nullptr;
    }
    return &it->second.back();
}

const ArtifactRecord* CoordinatorState::find_revision(ArtifactId id, ArtifactRevision revision) const {
    const auto it = artifacts.find(id);
    if (it == artifacts.end()) {
        return nullptr;
    }
    for (const ArtifactRecord& record : it->second) {
        if (record.revision == revision) {
            return &record;
        }
    }
    return nullptr;
}

ArtifactRecord* CoordinatorState::find_current(ArtifactId id) {
    const auto it = artifacts.find(id);
    if (it == artifacts.end() || it->second.empty()) {
        return nullptr;
    }
    return &it->second.back();
}

ArtifactRecord* CoordinatorState::find_revision(ArtifactId id, ArtifactRevision revision) {
    const auto it = artifacts.find(id);
    if (it == artifacts.end()) {
        return nullptr;
    }
    for (ArtifactRecord& record : it->second) {
        if (record.revision == revision) {
            return &record;
        }
    }
    return nullptr;
}

void CoordinatorState::set_active_policy(PromotionPolicy policy) {
    active_policy = policy.id;
    active_policy_id = policy.id;
    active_policy_generation = policy.generation;
    active_policy_body_ = std::move(policy);
    active_policy_digest = active_policy_body_.policy_digest;
}

Status CoordinatorState::verify_consistency() const {
    if (coordinator.invalid()) {
        return Status(ErrorCode::PersistenceCorrupt, "coordinator identity is the invalid sentinel");
    }
    if (!epoch.valid()) {
        return Status(ErrorCode::PersistenceCorrupt, "coordinator epoch is zero");
    }
    if (!active_policy_body_.id.valid() || active_policy_body_.id != active_policy) {
        return Status(ErrorCode::PersistenceCorrupt,
                      "active policy body does not match the recorded policy identity");
    }
    if (active_policy_body_.generation != active_policy_generation) {
        return Status(ErrorCode::PersistenceCorrupt, "active policy generation does not match the policy body");
    }
    if (active_policy_body_.policy_digest != active_policy_digest) {
        return Status(ErrorCode::PersistenceCorrupt, "active policy digest does not match the policy body");
    }
    const Status policy_status = active_policy_body_.validate();
    if (policy_status.failed()) {
        return policy_status;
    }

    // Artifact revision chains: identities and generations must line up, and a
    // promoted revision must name the decision that authorized it.
    for (const auto& [id, revisions] : artifacts) {
        if (id.invalid() || revisions.empty()) {
            return Status(ErrorCode::PersistenceCorrupt, "artifact entry has an invalid identity or no revisions");
        }
        std::set<ArtifactRevision> seen;
        for (std::size_t index = 0; index < revisions.size(); ++index) {
            const ArtifactRecord& record = revisions[index];
            if (!record.valid() || record.id != id) {
                return Status(ErrorCode::PersistenceCorrupt, "artifact revision record is malformed");
            }
            if (!seen.insert(record.revision).second) {
                return Status(ErrorCode::PersistenceCorrupt, "artifact identity has a duplicate revision");
            }
            if (record.generation.value() != index + 1) {
                return Status(ErrorCode::PersistenceCorrupt,
                              "artifact revision generation does not match its position in the revision chain");
            }
            if (record.promoted && record.promotion_decision.invalid()) {
                return Status(ErrorCode::PersistenceCorrupt, "promoted artifact has no promotion decision");
            }
        }
    }

    // Evidence must reference a real artifact revision, match its digest, and
    // still satisfy its own integrity digest.
    for (const auto& [id, record] : evidence) {
        if (id.invalid() || record.id != id || !record.valid()) {
            return Status(ErrorCode::PersistenceCorrupt, "evidence record is malformed");
        }
        const ArtifactRecord* subject = find_revision(record.subject, record.subject_revision);
        if (subject == nullptr) {
            return Status(ErrorCode::PersistenceCorrupt, "evidence references an unknown artifact revision");
        }
        if (subject->digest != record.subject_digest) {
            return Status(ErrorCode::PersistenceCorrupt,
                          "evidence subject digest does not match the artifact revision");
        }
        if (compute_evidence_integrity(record) != record.integrity_digest) {
            return Status(ErrorCode::PersistenceCorrupt, "evidence integrity digest does not match its content");
        }
    }

    for (const auto& [id, plan] : plans) {
        if (id.invalid() || plan.id != id || !plan.valid()) {
            return Status(ErrorCode::PersistenceCorrupt, "promotion plan is malformed");
        }
    }
    for (const auto& [id, decision] : decisions) {
        if (id.invalid() || decision.id != id) {
            return Status(ErrorCode::PersistenceCorrupt, "promotion decision identity mismatch");
        }
        if (!is_valid_promotion_outcome(static_cast<std::uint64_t>(decision.outcome))) {
            return Status(ErrorCode::PersistenceCorrupt, "promotion decision carries an unknown outcome");
        }
    }
    for (const auto& [id, record] : records) {
        if (id.invalid() || record.transition != id || !record.valid()) {
            return Status(ErrorCode::PersistenceCorrupt, "promotion record is malformed");
        }
        if (!record.sequence.valid()) {
            return Status(ErrorCode::PersistenceCorrupt, "promotion record has no commit sequence");
        }
        if (record.to == Stage::Promoted && record.decision.invalid()) {
            return Status(ErrorCode::PersistenceCorrupt, "promotion record names no promotion decision");
        }
        const ArtifactRecord* subject = find_revision(record.artifact, record.artifact_revision);
        if (subject == nullptr) {
            return Status(ErrorCode::PersistenceCorrupt,
                          "promotion record references an unknown artifact revision");
        }
        if (subject->digest != record.artifact_digest) {
            return Status(ErrorCode::PersistenceCorrupt,
                          "promotion record digest does not match the artifact revision");
        }
    }

    // History must be strictly increasing in commit sequence.
    CommitSequence previous{};
    for (const auto& [sequence, event] : history) {
        if (!sequence.valid() || event.sequence != sequence) {
            return Status(ErrorCode::PersistenceCorrupt, "history event sequence mismatch");
        }
        if (previous.valid() && !(previous < sequence)) {
            return Status(ErrorCode::PersistenceCorrupt, "history is not strictly increasing");
        }
        previous = sequence;
    }

    // Revocations and supersessions must reference state that exists.
    for (const auto& [id, revisions] : artifacts) {
        (void)id;
        for (const ArtifactRecord& record : revisions) {
            if (record.revocation.active) {
                if (record.revocation.decision.invalid()) {
                    return Status(ErrorCode::PersistenceCorrupt, "active revocation names no promotion decision");
                }
                if (!decisions.count(record.revocation.decision)) {
                    return Status(ErrorCode::PersistenceCorrupt,
                                  "active revocation references an unknown promotion decision");
                }
            }
            if (record.supersession.active) {
                const ArtifactRecord* successor =
                    find_revision(record.supersession.successor, record.supersession.successor_revision);
                if (successor == nullptr) {
                    return Status(ErrorCode::PersistenceCorrupt, "supersession references an unknown successor");
                }
            }
        }
    }
    return Status::success();
}

}  // namespace artifact_promotion
