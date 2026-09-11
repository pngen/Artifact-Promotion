// Artifact Promotion - first-class promotion evidence.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_EVIDENCE_HPP
#define ARTIFACT_PROMOTION_EVIDENCE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "artifact_promotion/artifact.hpp"
#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/error.hpp"
#include "artifact_promotion/identity.hpp"
#include "artifact_promotion/sha256.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// EvidenceType
//
// A closed set of reference evidence classes plus an explicit extension slot.
// The set is not a requirement list: policy decides which classes an artifact
// class needs for a given transition.
// ---------------------------------------------------------------------------
enum class EvidenceType : std::uint8_t {
    Invalid = 0,
    BuildPass = 1,
    UnitTestPass = 2,
    IntegrationTestPass = 3,
    PropertyTestPass = 4,
    AdversarialTestPass = 5,
    SanitizerPass = 6,
    SecurityScanPass = 7,
    BenchmarkResult = 8,
    CompatibilityPass = 9,
    AbiCompatibilityPass = 10,
    DataValidationPass = 11,
    ModelEvalPass = 12,
    HumanApproval = 13,
    MachineCriticApproval = 14,
    ReproducibilityPass = 15,
    SignatureValid = 16,
    ProvenanceComplete = 17,
    DependencyPolicyPass = 18,
    Custom = 63,
};

inline constexpr std::uint8_t kEvidenceTypeMin = static_cast<std::uint8_t>(EvidenceType::BuildPass);
inline constexpr std::uint8_t kEvidenceTypeMax = static_cast<std::uint8_t>(EvidenceType::Custom);

[[nodiscard]] const char* to_string(EvidenceType type) noexcept;
[[nodiscard]] std::optional<EvidenceType> evidence_type_from_string(std::string_view text) noexcept;
[[nodiscard]] bool is_valid_evidence_type(std::uint64_t raw) noexcept;

// ---------------------------------------------------------------------------
// EvidenceResult
//
// Only Pass satisfies a mandatory gate. Inconclusive and Unknown are
// deliberately distinct from Fail and from Pass: unknown is not pass, and an
// unresolved result forces revalidation rather than eligibility.
// ---------------------------------------------------------------------------
enum class EvidenceResult : std::uint8_t {
    Unknown = 0,
    Pass = 1,
    Fail = 2,
    Inconclusive = 3,
    NotApplicable = 4,
};

[[nodiscard]] const char* to_string(EvidenceResult result) noexcept;
[[nodiscard]] bool is_valid_evidence_result(std::uint64_t raw) noexcept;
[[nodiscard]] inline bool satisfies_mandatory_gate(EvidenceResult result) noexcept {
    return result == EvidenceResult::Pass;
}

// ---------------------------------------------------------------------------
// EvidenceRecord
//
// Evidence is durable governed state. It is bound to the exact artifact
// identity AND the exact artifact revision it validated. Evidence carrying a
// different digest is not "similar evidence": it is inapplicable evidence and
// can never promote the artifact it does not describe.
// ---------------------------------------------------------------------------
struct EvidenceRecord {
    EvidenceId id{};
    EvidenceType type = EvidenceType::Invalid;
    EvidenceGeneration generation{};
    std::string custom_type{};  // required when type == Custom

    ArtifactId subject{};
    Digest subject_digest{};
    ArtifactRevision subject_revision{};

    ProducerIncarnation producer{};
    EvidenceResult result = EvidenceResult::Unknown;
    std::uint32_t confidence_milli = 0;  // 0..1000, advisory only
    std::string measurement{};           // producer supplied measurement label
    std::string detail{};

    Digest payload_digest{};  // content identity of the producer's raw result payload
    Digest integrity_digest{};  // coordinator computed over the canonical record

    ProvenanceRef provenance{};  // ledger style reference, when the evidence cites one
    CommitSequence created_sequence{};
    std::uint64_t produced_unix_millis = 0;

    bool has_validity_window = false;
    std::uint64_t valid_from_unix_millis = 0;
    std::uint64_t valid_until_unix_millis = 0;

    std::string environment{};  // environment binding, when the producer declares one

    bool revoked = false;
    std::string revocation_reason{};
    AuthorityId revocation_authority{};
    CommitSequence revocation_sequence{};

    bool superseded = false;
    EvidenceId superseded_by{};

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] bool validity_window_well_formed() const noexcept {
        return !has_validity_window || valid_until_unix_millis >= valid_from_unix_millis;
    }
};

// The exact tuple that identifies at most one current evidence record.
struct EvidenceKey {
    ArtifactId subject{};
    ArtifactRevision subject_revision{};
    EvidenceType type = EvidenceType::Invalid;
    std::string custom_type{};
    ProducerIncarnation producer{};

    [[nodiscard]] friend bool operator==(const EvidenceKey& lhs, const EvidenceKey& rhs) noexcept {
        return lhs.subject == rhs.subject && lhs.subject_revision == rhs.subject_revision &&
               lhs.type == rhs.type && lhs.custom_type == rhs.custom_type && lhs.producer == rhs.producer;
    }
    [[nodiscard]] friend bool operator<(const EvidenceKey& lhs, const EvidenceKey& rhs) noexcept {
        if (lhs.subject != rhs.subject) {
            return lhs.subject < rhs.subject;
        }
        if (lhs.subject_revision != rhs.subject_revision) {
            return lhs.subject_revision < rhs.subject_revision;
        }
        if (lhs.type != rhs.type) {
            return lhs.type < rhs.type;
        }
        if (lhs.custom_type != rhs.custom_type) {
            return lhs.custom_type < rhs.custom_type;
        }
        return lhs.producer < rhs.producer;
    }
    [[nodiscard]] static EvidenceKey of(const EvidenceRecord& record) noexcept {
        EvidenceKey key;
        key.subject = record.subject;
        key.subject_revision = record.subject_revision;
        key.type = record.type;
        key.custom_type = record.custom_type;
        key.producer = record.producer;
        return key;
    }
};

// ---------------------------------------------------------------------------
// EvidenceSubmission
//
// A producer supplied candidate evidence record. The runtime assigns identity,
// generation, ingestion sequence, and integrity digest; the submitter supplies
// everything that describes the observation.
// ---------------------------------------------------------------------------
struct EvidenceSubmission {
    ArtifactId subject{};
    Digest subject_digest{};
    ArtifactRevision subject_revision{};
    EvidenceType type = EvidenceType::Invalid;
    std::string custom_type{};
    ProducerIncarnation producer{};
    EvidenceResult result = EvidenceResult::Unknown;
    std::uint32_t confidence_milli = 0;
    std::string measurement{};
    std::string detail{};
    Digest payload_digest{};
    ProvenanceRef provenance{};
    std::uint64_t produced_unix_millis = 0;
    bool has_validity_window = false;
    std::uint64_t valid_from_unix_millis = 0;
    std::uint64_t valid_until_unix_millis = 0;
    std::string environment{};

    [[nodiscard]] Status validate() const;
};

// ---------------------------------------------------------------------------
// EvidenceSnapshot
//
// A canonical, ordered view of the evidence set that a promotion plan is bound
// to. The plan cites the snapshot digest, so any later evidence mutation makes
// the snapshot stale instead of silently changing what the plan was based on.
// ---------------------------------------------------------------------------
struct EvidenceSnapshotEntry {
    EvidenceId id{};
    EvidenceType type = EvidenceType::Invalid;
    std::string custom_type{};
    EvidenceGeneration generation{};
    EvidenceResult result = EvidenceResult::Unknown;
    Digest subject_digest{};
    ArtifactRevision subject_revision{};
    ProducerIncarnation producer{};
    Digest integrity_digest{};

    [[nodiscard]] friend bool operator<(const EvidenceSnapshotEntry& lhs,
                                        const EvidenceSnapshotEntry& rhs) noexcept {
        if (lhs.type != rhs.type) {
            return lhs.type < rhs.type;
        }
        if (lhs.custom_type != rhs.custom_type) {
            return lhs.custom_type < rhs.custom_type;
        }
        return lhs.id < rhs.id;
    }
};

struct EvidenceSnapshot {
    ArtifactId subject{};
    ArtifactRevision subject_revision{};
    Digest subject_digest{};
    std::vector<EvidenceSnapshotEntry> entries{};
    Digest snapshot_digest{};

    [[nodiscard]] std::size_t size() const noexcept { return entries.size(); }
    [[nodiscard]] bool contains(EvidenceId id) const noexcept;
    [[nodiscard]] bool contains_type(EvidenceType type) const noexcept;
};

// Computes the canonical digest of a snapshot entry list. Entries are sorted
// before hashing so hash iteration order can never leak into the digest.
[[nodiscard]] Digest compute_snapshot_digest(ArtifactId subject, ArtifactRevision revision, const Digest& digest,
                                             std::vector<EvidenceSnapshotEntry> entries);
[[nodiscard]] Digest compute_evidence_integrity(const EvidenceRecord& record);

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_EVIDENCE_HPP
