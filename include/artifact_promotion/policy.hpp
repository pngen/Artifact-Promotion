// Artifact Promotion - versioned promotion policy.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_POLICY_HPP
#define ARTIFACT_PROMOTION_POLICY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "artifact_promotion/artifact.hpp"
#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/error.hpp"
#include "artifact_promotion/evidence.hpp"
#include "artifact_promotion/identity.hpp"
#include "artifact_promotion/sha256.hpp"
#include "artifact_promotion/stage.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// GateKind
//
// A closed set of machine-evaluated hard gates. A policy is data: it selects
// gates and supplies parameters. Parameters were validated when the policy was
// published, so evaluation performs no parsing and cannot fail spuriously.
// ---------------------------------------------------------------------------
enum class GateKind : std::uint8_t {
    Invalid = 0,
    EvidenceRequired = 1,
    EvidenceFreshness = 2,
    EvidenceIntegrity = 3,
    ArtifactIdentity = 4,
    ArtifactNotQuarantined = 5,
    ArtifactNotRevoked = 6,
    ArtifactNotSuperseded = 7,
    ProvenanceRequired = 8,
    ProvenanceResolved = 9,
    CompatibilityGenerationCurrent = 10,
    EnvironmentBinding = 11,
    DependentArtifactPromoted = 12,
    ApprovalRequired = 13,
    SecurityVetoClear = 14,
    DependencyVetoClear = 15,
    PolicyGenerationCurrent = 16,
    CoordinatorEpochCurrent = 17,
    NoConflictingTransition = 18,
};

inline constexpr std::uint8_t kGateKindMin = static_cast<std::uint8_t>(GateKind::EvidenceRequired);
inline constexpr std::uint8_t kGateKindMax = static_cast<std::uint8_t>(GateKind::NoConflictingTransition);

[[nodiscard]] const char* to_string(GateKind kind) noexcept;
[[nodiscard]] std::optional<GateKind> gate_kind_from_string(std::string_view text) noexcept;
[[nodiscard]] bool is_valid_gate_kind(std::uint64_t raw) noexcept;

// ---------------------------------------------------------------------------
// OrderingRule
//
// Optional, deterministic preference applied only after every hard gate has
// passed. Ranking is a tie-break between artifacts that are already eligible;
// it can never make an ineligible artifact eligible.
// ---------------------------------------------------------------------------
enum class OrderingRule : std::uint8_t {
    None = 0,
    LowerCommitSequence = 1,
    HigherCommitSequence = 2,
    LexicographicArtifactId = 3,
    LexicographicDigest = 4,
};

[[nodiscard]] const char* to_string(OrderingRule rule) noexcept;
[[nodiscard]] bool is_valid_ordering_rule(std::uint64_t raw) noexcept;

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------
struct Gate {
    GateKind kind = GateKind::Invalid;
    // EvidenceRequired / EvidenceFreshness / ApprovalRequired / EnvironmentBinding
    EvidenceType evidence_type = EvidenceType::Invalid;
    // Custom evidence type name when evidence_type == Custom
    std::string custom_evidence_type{};
    // EvidenceFreshness: maximum age in milliseconds.
    std::uint64_t max_age_millis = 0;
    // CompatibilityGenerationCurrent: the generation the policy requires.
    CompatibilityGeneration required_compatibility_generation{};
    // EnvironmentBinding: the environment string the evidence must declare.
    std::string required_environment{};
    // ProvenanceRequired: a specific provenance reference that must be present.
    ProvenanceRef required_provenance{};
    // Human readable gate label; part of the policy digest and explanation order.
    std::string label{};

    [[nodiscard]] Status validate() const;
    [[nodiscard]] std::string describe() const;

    [[nodiscard]] friend bool operator==(const Gate& lhs, const Gate& rhs) noexcept {
        return lhs.kind == rhs.kind && lhs.evidence_type == rhs.evidence_type &&
               lhs.custom_evidence_type == rhs.custom_evidence_type && lhs.max_age_millis == rhs.max_age_millis &&
               lhs.required_compatibility_generation == rhs.required_compatibility_generation &&
               lhs.required_environment == rhs.required_environment &&
               lhs.required_provenance == rhs.required_provenance && lhs.label == rhs.label;
    }
};

// ---------------------------------------------------------------------------
// PolicyRule
//
// One policy-governed transition. Requirements are distinguished from
// preferences: requirements are hard gates, preferences only order artifacts
// that already cleared every hard gate.
// ---------------------------------------------------------------------------
struct PolicyRule {
    static constexpr std::size_t kMaxGates = 32;

    ArtifactId artifact_type_scope{};  // reserved; ArtifactKind is the real scope
    bool has_kind_scope = false;
    ArtifactKind kind_scope = ArtifactKind::Invalid;

    Stage from = Stage::Invalid;
    Stage to = Stage::Invalid;

    std::vector<Gate> requirements{};
    std::vector<GateKind> preferences{};
    OrderingRule ordering = OrderingRule::None;

    bool allow_idempotent_replay = true;
    bool allow_rollback_eligibility = false;
    bool supersedes_previous = false;

    [[nodiscard]] bool matches(ArtifactKind kind, Stage source, Stage destination) const noexcept;
    [[nodiscard]] Status validate() const;

    [[nodiscard]] friend bool operator==(const PolicyRule& lhs, const PolicyRule& rhs) noexcept {
        return lhs.has_kind_scope == rhs.has_kind_scope && lhs.kind_scope == rhs.kind_scope && lhs.from == rhs.from &&
               lhs.to == rhs.to && lhs.requirements == rhs.requirements && lhs.preferences == rhs.preferences &&
               lhs.ordering == rhs.ordering && lhs.allow_idempotent_replay == rhs.allow_idempotent_replay &&
               lhs.allow_rollback_eligibility == rhs.allow_rollback_eligibility &&
               lhs.supersedes_previous == rhs.supersedes_previous;
    }
};

// ---------------------------------------------------------------------------
// PromotionPolicy
//
// An immutable, versioned policy revision. PolicyGeneration is part of every
// promotion plan's authority, so a plan built under one generation cannot
// commit under another without explicit revalidation.
// ---------------------------------------------------------------------------
struct PromotionPolicy {
    static constexpr std::size_t kMaxRules = 64;

    PromotionPolicyId id{};
    PolicyGeneration generation{};
    std::string name{};
    std::string description{};
    LifecycleGraph graph{};
    Stage entry_stage = Stage::Candidate;
    std::vector<PolicyRule> rules{};
    Digest policy_digest{};

    [[nodiscard]] Status validate() const;
    [[nodiscard]] Digest compute_digest() const;

    // Returns the first rule, in declared order, that governs this transition.
    // Determinism comes from declaration order, never from hash iteration.
    [[nodiscard]] const PolicyRule* find_rule(ArtifactKind kind, Stage from, Stage to) const noexcept;

    [[nodiscard]] bool allows_transition(ArtifactKind kind, Stage from, Stage to) const noexcept {
        return find_rule(kind, from, to) != nullptr;
    }

    [[nodiscard]] friend bool operator==(const PromotionPolicy& lhs, const PromotionPolicy& rhs) noexcept {
        return lhs.id == rhs.id && lhs.generation == rhs.generation && lhs.entry_stage == rhs.entry_stage &&
               lhs.rules == rhs.rules && lhs.graph == rhs.graph;
    }
};

// The reference policy: a strict executable pipeline and a deliberately
// different model pipeline, proving that evidence requirements are per artifact
// class rather than one universal "everything needs tests" assumption.
[[nodiscard]] PromotionPolicy make_reference_policy(PromotionPolicyId id, PolicyGeneration generation);

// ---------------------------------------------------------------------------
// Promotion authority binding
// ---------------------------------------------------------------------------
struct CoordinatorAuthority {
    CoordinatorId coordinator{};
    CoordinatorEpoch epoch{};

    [[nodiscard]] bool valid() const noexcept { return coordinator.valid() && epoch.valid(); }

    [[nodiscard]] friend bool operator==(const CoordinatorAuthority& lhs,
                                         const CoordinatorAuthority& rhs) noexcept {
        return lhs.coordinator == rhs.coordinator && lhs.epoch == rhs.epoch;
    }
    [[nodiscard]] friend bool operator!=(const CoordinatorAuthority& lhs,
                                         const CoordinatorAuthority& rhs) noexcept {
        return !(lhs == rhs);
    }
    [[nodiscard]] friend bool operator<(const CoordinatorAuthority& lhs,
                                        const CoordinatorAuthority& rhs) noexcept {
        if (lhs.coordinator != rhs.coordinator) {
            return lhs.coordinator < rhs.coordinator;
        }
        return lhs.epoch < rhs.epoch;
    }
};

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_POLICY_HPP
