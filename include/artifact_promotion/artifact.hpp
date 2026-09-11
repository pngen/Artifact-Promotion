// Artifact Promotion - governed artifact metadata and lifecycle state.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_ARTIFACT_HPP
#define ARTIFACT_PROMOTION_ARTIFACT_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/error.hpp"
#include "artifact_promotion/identity.hpp"
#include "artifact_promotion/sha256.hpp"
#include "artifact_promotion/stage.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// ArtifactKind
//
// Artifact classes are a closed set so that policy can attach different gate
// requirements per class without the runtime embedding product-specific
// business logic. A policy may require unit tests for an executable and require
// nothing of the same shape for a dataset snapshot.
// ---------------------------------------------------------------------------
enum class ArtifactKind : std::uint8_t {
    Invalid = 0,
    Model = 1,
    Kernel = 2,
    Executable = 3,
    Library = 4,
    Configuration = 5,
    Dataset = 6,
    ResearchResult = 7,
    BenchmarkBundle = 8,
    GeneratedCode = 9,
    DeploymentManifest = 10,
    Opaque = 11,
};

inline constexpr std::uint8_t kArtifactKindMin = static_cast<std::uint8_t>(ArtifactKind::Model);
inline constexpr std::uint8_t kArtifactKindMax = static_cast<std::uint8_t>(ArtifactKind::Opaque);

[[nodiscard]] const char* to_string(ArtifactKind kind) noexcept;
[[nodiscard]] std::optional<ArtifactKind> artifact_kind_from_string(std::string_view text) noexcept;
[[nodiscard]] bool is_valid_artifact_kind(std::uint64_t raw) noexcept;

// ---------------------------------------------------------------------------
// ProducerIncarnation
//
// Identifies the process that produced or validated something. WorkerBootId is
// part of the identity: a restarted process with the same logical WorkerId is a
// different incarnation and cannot inherit the authority of its predecessor.
// An empty WorkerId means "not process bound" (offline or operator supplied).
// ---------------------------------------------------------------------------
struct ProducerIncarnation {
    WorkerId worker{};
    WorkerBootId boot{};

    [[nodiscard]] bool process_bound() const noexcept { return worker.valid(); }
    [[nodiscard]] bool valid() const noexcept {
        // A boot identity without a worker identity is meaningless.
        return worker.valid() == boot.valid();
    }

    [[nodiscard]] friend bool operator==(const ProducerIncarnation& lhs, const ProducerIncarnation& rhs) noexcept {
        return lhs.worker == rhs.worker && lhs.boot == rhs.boot;
    }
    [[nodiscard]] friend bool operator!=(const ProducerIncarnation& lhs, const ProducerIncarnation& rhs) noexcept {
        return !(lhs == rhs);
    }
    [[nodiscard]] friend bool operator<(const ProducerIncarnation& lhs, const ProducerIncarnation& rhs) noexcept {
        if (lhs.worker != rhs.worker) {
            return lhs.worker < rhs.worker;
        }
        return lhs.boot < rhs.boot;
    }
};

// ---------------------------------------------------------------------------
// ProvenanceRef / ProvenanceRecord
//
// A narrow, adapter-shaped reference to authoritative provenance owned by an
// adjacent system (a Research Ledger style source). Artifact Promotion stores
// the reference and a resolution state; it never becomes the ledger and never
// re-derives research truth.
// ---------------------------------------------------------------------------
enum class ProvenanceResolution : std::uint8_t {
    Unknown = 0,
    Resolved = 1,
    Superseded = 2,
    Rejected = 3,
};

[[nodiscard]] const char* to_string(ProvenanceResolution resolution) noexcept;

struct ProvenanceRecord {
    ProvenanceRef reference{};
    std::string source{};   // adapter name, e.g. "research-ledger"
    std::string subject{};  // ledger-side subject locator
    ProvenanceResolution resolution = ProvenanceResolution::Unknown;

    [[nodiscard]] friend bool operator==(const ProvenanceRecord& lhs, const ProvenanceRecord& rhs) noexcept {
        return lhs.reference == rhs.reference && lhs.source == rhs.source && lhs.subject == rhs.subject &&
               lhs.resolution == rhs.resolution;
    }
    [[nodiscard]] friend bool operator<(const ProvenanceRecord& lhs, const ProvenanceRecord& rhs) noexcept {
        if (lhs.reference != rhs.reference) {
            return lhs.reference < rhs.reference;
        }
        if (lhs.source != rhs.source) {
            return lhs.source < rhs.source;
        }
        return lhs.subject < rhs.subject;
    }
};

// ---------------------------------------------------------------------------
// CompatibilityDescriptor
//
// Identity of a compatibility profile plus the generation of the external
// compatibility knowledge the profile was evaluated against. Promotion authority
// is bound to CompatibilityGeneration: a plan created under one generation does
// not survive a change to another.
// ---------------------------------------------------------------------------
struct CompatibilityDescriptor {
    CompatibilityProfileId profile{};
    CompatibilityGeneration generation{};

    [[nodiscard]] bool valid() const noexcept { return profile.valid() && generation.valid(); }

    [[nodiscard]] friend bool operator==(const CompatibilityDescriptor& lhs,
                                         const CompatibilityDescriptor& rhs) noexcept {
        return lhs.profile == rhs.profile && lhs.generation == rhs.generation;
    }
    [[nodiscard]] friend bool operator<(const CompatibilityDescriptor& lhs,
                                        const CompatibilityDescriptor& rhs) noexcept {
        if (lhs.profile != rhs.profile) {
            return lhs.profile < rhs.profile;
        }
        return lhs.generation < rhs.generation;
    }
};

// ---------------------------------------------------------------------------
// QuarantineRecord
// ---------------------------------------------------------------------------
struct QuarantineRecord {
    bool active = false;
    std::string reason_class{};  // security_finding, integrity_mismatch, ...
    std::string detail{};
    AuthorityId authority{};
    CommitSequence sequence{};
    PolicyGeneration policy_generation{};

    [[nodiscard]] bool valid() const noexcept { return !active || (authority.valid() && sequence.valid()); }
};

// ---------------------------------------------------------------------------
// RevocationRecord
// ---------------------------------------------------------------------------
struct RevocationRecord {
    bool active = false;
    PromotionDecisionId decision{};   // the promotion decision being invalidated
    std::string reason_class{};
    std::string detail{};
    AuthorityId authority{};
    CommitSequence sequence{};
    PolicyGeneration policy_generation{};
    EvidenceId cause{};  // evidence that triggered the revocation, when any

    [[nodiscard]] bool valid() const noexcept { return !active || (authority.valid() && sequence.valid()); }
};

// ---------------------------------------------------------------------------
// SupersessionRecord
//
// Supersession means a newer artifact replaces an older one. It deliberately
// does not assert that the older artifact is invalid: the superseded artifact
// keeps its history and can still be a rollback candidate when policy allows.
// ---------------------------------------------------------------------------
struct SupersessionRecord {
    bool active = false;
    ArtifactId successor{};
    ArtifactRevision successor_revision{};
    std::string reason{};
    AuthorityId authority{};
    CommitSequence sequence{};

    [[nodiscard]] bool valid() const noexcept {
        return !active || (successor.valid() && successor_revision.valid() && sequence.valid());
    }
};

// ---------------------------------------------------------------------------
// ArtifactRecord
//
// One immutable revision of one artifact identity. Registering the same
// ArtifactId with a different digest creates a new revision and a new
// ArtifactGeneration; the previous revision keeps its own history and its own
// promotion or revocation outcome.
// ---------------------------------------------------------------------------
struct ArtifactRecord {
    static constexpr std::size_t kMaxProvenanceRefs = 64;
    static constexpr std::size_t kMaxDependencies = 64;

    ArtifactId id{};
    ArtifactRevision revision{};
    ArtifactGeneration generation{};
    ArtifactKind kind = ArtifactKind::Invalid;
    Digest digest{};
    std::uint64_t size_bytes = 0;
    std::string name{};
    ProducerIncarnation producer{};
    CommitSequence created_sequence{};
    std::uint64_t created_unix_millis = 0;
    std::vector<ProvenanceRecord> provenance{};
    std::vector<std::string> dependencies{};

    Stage stage = Stage::Invalid;
    StageGeneration stage_generation{};

    bool promoted = false;
    PromotionDecisionId promotion_decision{};
    AuthorityId promotion_authority{};
    CommitSequence promotion_sequence{};
    CommitSequence last_sequence{};

    QuarantineRecord quarantine{};
    RevocationRecord revocation{};
    SupersessionRecord supersession{};

    [[nodiscard]] bool valid() const noexcept {
        return id.valid() && revision.valid() && generation.valid() && kind != ArtifactKind::Invalid &&
               digest.valid() && stage != Stage::Invalid && stage_generation.valid() && producer.valid() &&
               quarantine.valid() && revocation.valid() && supersession.valid() &&
               provenance.size() <= kMaxProvenanceRefs && dependencies.size() <= kMaxDependencies;
    }

    [[nodiscard]] bool has_provenance(ProvenanceRef reference) const noexcept;

    // True when the artifact currently holds promotion authority. Revoked and
    // retired artifacts never do, even though their promotion history remains.
    [[nodiscard]] bool currently_authoritative() const noexcept {
        return promoted && stage == Stage::Promoted && !revocation.active;
    }

    [[nodiscard]] bool blocked_by_quarantine() const noexcept { return quarantine.active; }
};

[[nodiscard]] std::string render_artifact_summary(const ArtifactRecord& record);

// ---------------------------------------------------------------------------
// ArtifactRegistration
//
// The caller supplied description of a new artifact revision. Registry-assigned
// fields (revision, generation, sequence) are not part of it.
// ---------------------------------------------------------------------------
struct ArtifactRegistration {
    ArtifactId id{};
    ArtifactKind kind = ArtifactKind::Invalid;
    Digest digest{};
    std::uint64_t size_bytes = 0;
    std::string name{};
    ProducerIncarnation producer{};
    std::vector<ProvenanceRecord> provenance{};
    std::vector<std::string> dependencies{};

    [[nodiscard]] Status validate() const;
};

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_ARTIFACT_HPP
