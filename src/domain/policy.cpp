// Artifact Promotion - versioned promotion policy.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/policy.hpp"

#include <algorithm>
#include <array>
#include <sstream>

#include "artifact_promotion/detail/writer.hpp"

namespace artifact_promotion {
namespace {

struct GateKindName {
    GateKind kind;
    const char* name;
};

constexpr std::array<GateKindName, 19> kGateKindNames = {{
    {GateKind::Invalid, "INVALID"},
    {GateKind::EvidenceRequired, "EVIDENCE_REQUIRED"},
    {GateKind::EvidenceFreshness, "EVIDENCE_FRESHNESS"},
    {GateKind::EvidenceIntegrity, "EVIDENCE_INTEGRITY"},
    {GateKind::ArtifactIdentity, "ARTIFACT_IDENTITY"},
    {GateKind::ArtifactNotQuarantined, "ARTIFACT_NOT_QUARANTINED"},
    {GateKind::ArtifactNotRevoked, "ARTIFACT_NOT_REVOKED"},
    {GateKind::ArtifactNotSuperseded, "ARTIFACT_NOT_SUPERSEDED"},
    {GateKind::ProvenanceRequired, "PROVENANCE_REQUIRED"},
    {GateKind::ProvenanceResolved, "PROVENANCE_RESOLVED"},
    {GateKind::CompatibilityGenerationCurrent, "COMPATIBILITY_GENERATION_CURRENT"},
    {GateKind::EnvironmentBinding, "ENVIRONMENT_BINDING"},
    {GateKind::DependentArtifactPromoted, "DEPENDENT_ARTIFACT_PROMOTED"},
    {GateKind::ApprovalRequired, "APPROVAL_REQUIRED"},
    {GateKind::SecurityVetoClear, "SECURITY_VETO_CLEAR"},
    {GateKind::DependencyVetoClear, "DEPENDENCY_VETO_CLEAR"},
    {GateKind::PolicyGenerationCurrent, "POLICY_GENERATION_CURRENT"},
    {GateKind::CoordinatorEpochCurrent, "COORDINATOR_EPOCH_CURRENT"},
    {GateKind::NoConflictingTransition, "NO_CONFLICTING_TRANSITION"},
}};

}  // namespace

const char* to_string(GateKind kind) noexcept {
    for (const auto& entry : kGateKindNames) {
        if (entry.kind == kind) {
            return entry.name;
        }
    }
    return "INVALID";
}

std::optional<GateKind> gate_kind_from_string(std::string_view text) noexcept {
    for (const auto& entry : kGateKindNames) {
        if (text == entry.name) {
            return entry.kind;
        }
    }
    return std::nullopt;
}

bool is_valid_gate_kind(std::uint64_t raw) noexcept {
    return raw >= kGateKindMin && raw <= kGateKindMax;
}

const char* to_string(OrderingRule rule) noexcept {
    switch (rule) {
        case OrderingRule::None:
            return "NONE";
        case OrderingRule::LowerCommitSequence:
            return "LOWER_COMMIT_SEQUENCE";
        case OrderingRule::HigherCommitSequence:
            return "HIGHER_COMMIT_SEQUENCE";
        case OrderingRule::LexicographicArtifactId:
            return "LEXICOGRAPHIC_ARTIFACT_ID";
        case OrderingRule::LexicographicDigest:
            return "LEXICOGRAPHIC_DIGEST";
    }
    return "NONE";
}

bool is_valid_ordering_rule(std::uint64_t raw) noexcept {
    return raw <= static_cast<std::uint64_t>(OrderingRule::LexicographicDigest);
}

Status Gate::validate() const {
    if (!is_valid_gate_kind(static_cast<std::uint64_t>(kind))) {
        return Status(ErrorCode::InvalidEnum, "gate kind is not a known gate class");
    }
    if (!is_valid_text(label) || label.empty()) {
        return Status(ErrorCode::InvalidName, "gate label is empty, too long, or contains control characters");
    }
    switch (kind) {
        case GateKind::EvidenceRequired:
        case GateKind::EvidenceFreshness:
        case GateKind::ApprovalRequired:
            if (!is_valid_evidence_type(static_cast<std::uint64_t>(evidence_type)) ||
                evidence_type == EvidenceType::Invalid) {
                return Status(ErrorCode::InvalidEnum, "gate requires a specific evidence type");
            }
            if (evidence_type == EvidenceType::Custom && !is_valid_name(custom_evidence_type)) {
                return Status(ErrorCode::InvalidName, "custom evidence gate requires a valid custom type name");
            }
            if (evidence_type != EvidenceType::Custom && !custom_evidence_type.empty()) {
                return Status(ErrorCode::InvalidArgument, "built-in evidence gate must not name a custom type");
            }
            if (kind == GateKind::EvidenceFreshness && max_age_millis == 0) {
                return Status(ErrorCode::InvalidArgument, "freshness gate requires a non-zero maximum age");
            }
            break;
        case GateKind::EnvironmentBinding:
            if (evidence_type == EvidenceType::Invalid ||
                !is_valid_evidence_type(static_cast<std::uint64_t>(evidence_type))) {
                return Status(ErrorCode::InvalidEnum, "environment binding gate requires an evidence type");
            }
            if (!is_valid_text(required_environment) || required_environment.empty()) {
                return Status(ErrorCode::InvalidName, "environment binding gate requires a non-empty environment");
            }
            break;
        case GateKind::ProvenanceRequired:
            if (required_provenance.invalid()) {
                return Status(ErrorCode::InvalidIdentity, "provenance gate requires a provenance reference");
            }
            break;
        case GateKind::CompatibilityGenerationCurrent:
            if (!required_compatibility_generation.valid()) {
                return Status(ErrorCode::InvalidCount, "compatibility gate requires a non-zero generation");
            }
            break;
        case GateKind::EvidenceIntegrity:
        case GateKind::ArtifactIdentity:
        case GateKind::ArtifactNotQuarantined:
        case GateKind::ArtifactNotRevoked:
        case GateKind::ArtifactNotSuperseded:
        case GateKind::ProvenanceResolved:
        case GateKind::DependentArtifactPromoted:
        case GateKind::SecurityVetoClear:
        case GateKind::DependencyVetoClear:
        case GateKind::PolicyGenerationCurrent:
        case GateKind::CoordinatorEpochCurrent:
        case GateKind::NoConflictingTransition:
            break;
        case GateKind::Invalid:
            return Status(ErrorCode::InvalidEnum, "gate kind is INVALID");
    }
    return Status::success();
}

std::string Gate::describe() const {
    std::ostringstream out;
    out << to_string(kind);
    if (is_valid_evidence_type(static_cast<std::uint64_t>(evidence_type)) &&
        evidence_type != EvidenceType::Invalid) {
        out << '(' << (evidence_type == EvidenceType::Custom ? custom_evidence_type
                                                             : std::string(to_string(evidence_type)));
        if (kind == GateKind::EvidenceFreshness) {
            out << ", max_age_ms=" << max_age_millis;
        }
        if (kind == GateKind::EnvironmentBinding) {
            out << ", environment=" << required_environment;
        }
        out << ')';
    }
    return out.str();
}

bool PolicyRule::matches(ArtifactKind kind, Stage source, Stage destination) const noexcept {
    if (from != source || to != destination) {
        return false;
    }
    if (has_kind_scope && kind_scope != kind) {
        return false;
    }
    return true;
}

Status PolicyRule::validate() const {
    if (from == Stage::Invalid || to == Stage::Invalid) {
        return Status(ErrorCode::InvalidStage, "policy rule references an invalid stage");
    }
    if (from == to) {
        return Status(ErrorCode::InvalidTransition, "policy rule declares a self transition");
    }
    if (has_kind_scope && !is_valid_artifact_kind(static_cast<std::uint64_t>(kind_scope))) {
        return Status(ErrorCode::InvalidEnum, "policy rule scope references an unknown artifact kind");
    }
    if (requirements.size() > kMaxGates) {
        return Status(ErrorCode::InvalidCount, "policy rule exceeds the configured gate bound");
    }
    if (preferences.size() > kMaxGates) {
        return Status(ErrorCode::InvalidCount, "policy rule exceeds the configured preference bound");
    }
    if (!is_valid_ordering_rule(static_cast<std::uint64_t>(ordering))) {
        return Status(ErrorCode::InvalidEnum, "policy rule declares an unknown ordering rule");
    }
    for (const Gate& gate : requirements) {
        const Status status = gate.validate();
        if (status.failed()) {
            return status;
        }
    }
    for (const GateKind kind : preferences) {
        if (!is_valid_gate_kind(static_cast<std::uint64_t>(kind))) {
            return Status(ErrorCode::InvalidEnum, "policy rule preference references an unknown gate kind");
        }
    }
    return Status::success();
}

Digest PromotionPolicy::compute_digest() const {
    wire::Writer writer(1024);
    writer.identity(id);
    writer.counter(generation);
    writer.u8(static_cast<std::uint8_t>(entry_stage));
    writer.list(graph.edges().size(), [&](wire::Writer& out, std::size_t index) {
        const LifecycleGraph::Edge& edge = graph.edges()[index];
        out.u8(static_cast<std::uint8_t>(edge.from));
        out.u8(static_cast<std::uint8_t>(edge.to));
    });
    writer.list(rules.size(), [&](wire::Writer& out, std::size_t index) {
        const PolicyRule& rule = rules[index];
        out.boolean(rule.has_kind_scope);
        out.u8(static_cast<std::uint8_t>(rule.kind_scope));
        out.u8(static_cast<std::uint8_t>(rule.from));
        out.u8(static_cast<std::uint8_t>(rule.to));
        out.u8(static_cast<std::uint8_t>(rule.ordering));
        out.boolean(rule.allow_idempotent_replay);
        out.boolean(rule.allow_rollback_eligibility);
        out.boolean(rule.supersedes_previous);
        for (const Gate& gate : rule.requirements) {
            out.u8(static_cast<std::uint8_t>(gate.kind));
            out.u8(static_cast<std::uint8_t>(gate.evidence_type));
            out.text(gate.custom_evidence_type, kMaxNameLength);
            out.u64(gate.max_age_millis);
            out.counter(gate.required_compatibility_generation);
            out.text(gate.required_environment);
            out.identity(gate.required_provenance);
            out.text(gate.label, kMaxNameLength);
        }
        for (const GateKind kind : rule.preferences) {
            out.u8(static_cast<std::uint8_t>(kind));
        }
    });
    return sha256(writer.buffer());
}

Status PromotionPolicy::validate() const {
    if (id.invalid()) {
        return Status(ErrorCode::InvalidIdentity, "policy identity is the invalid sentinel");
    }
    if (!generation.valid()) {
        return Status(ErrorCode::InvalidCount, "policy generation must be non-zero");
    }
    if (!is_valid_name(name)) {
        return Status(ErrorCode::InvalidName, "policy name is empty, too long, or malformed");
    }
    if (rules.size() > kMaxRules) {
        return Status(ErrorCode::InvalidCount, "policy rule count exceeds the configured bound");
    }
    const Status graph_status = graph.validate(entry_stage);
    if (graph_status.failed()) {
        return graph_status;
    }
    for (const PolicyRule& rule : rules) {
        const Status status = rule.validate();
        if (status.failed()) {
            return status;
        }
        if (!graph.has_edge(rule.from, rule.to)) {
            return Status(ErrorCode::InvalidTransition, "policy rule declares a transition the lifecycle graph forbids");
        }
    }
    if (rules.empty()) {
        return Status(ErrorCode::InvalidCount, "policy declares no rules");
    }
    return Status::success();
}

const PolicyRule* PromotionPolicy::find_rule(ArtifactKind kind, Stage from, Stage to) const noexcept {
    for (const PolicyRule& rule : rules) {
        if (rule.matches(kind, from, to)) {
            return &rule;
        }
    }
    return nullptr;
}

namespace {

Gate make_evidence_gate(EvidenceType type, std::string label) {
    Gate gate;
    gate.kind = GateKind::EvidenceRequired;
    gate.evidence_type = type;
    gate.label = std::move(label);
    return gate;
}

Gate make_freshness_gate(EvidenceType type, std::uint64_t max_age_millis, std::string label) {
    Gate gate;
    gate.kind = GateKind::EvidenceFreshness;
    gate.evidence_type = type;
    gate.max_age_millis = max_age_millis;
    gate.label = std::move(label);
    return gate;
}

Gate make_simple_gate(GateKind kind, std::string label) {
    Gate gate;
    gate.kind = kind;
    gate.label = std::move(label);
    return gate;
}

constexpr std::uint64_t kHourMillis = 60ULL * 60ULL * 1000ULL;
constexpr std::uint64_t kDayMillis = 24ULL * kHourMillis;

Gate make_environment_gate(EvidenceType type, std::string environment, std::string label) {
    Gate gate;
    gate.kind = GateKind::EnvironmentBinding;
    gate.evidence_type = type;
    gate.required_environment = std::move(environment);
    gate.label = std::move(label);
    return gate;
}

Gate make_compatibility_gate(CompatibilityGeneration generation, std::string label) {
    Gate gate;
    gate.kind = GateKind::CompatibilityGenerationCurrent;
    gate.required_compatibility_generation = generation;
    gate.label = std::move(label);
    return gate;
}

Gate make_provenance_gate(ProvenanceRef reference, std::string label) {
    Gate gate;
    gate.kind = GateKind::ProvenanceRequired;
    gate.required_provenance = reference;
    gate.label = std::move(label);
    return gate;
}

Gate make_approval_gate(EvidenceType type, std::string label) {
    Gate gate;
    gate.kind = GateKind::ApprovalRequired;
    gate.evidence_type = type;
    gate.label = std::move(label);
    return gate;
}

std::vector<Gate> common_hard_gates() {
    std::vector<Gate> gates;
    gates.push_back(make_simple_gate(GateKind::ArtifactIdentity, "artifact identity and digest are valid"));
    gates.push_back(make_simple_gate(GateKind::EvidenceIntegrity, "candidate evidence passes integrity checks"));
    gates.push_back(make_simple_gate(GateKind::ArtifactNotQuarantined, "artifact is not quarantined"));
    gates.push_back(make_simple_gate(GateKind::ArtifactNotRevoked, "artifact is not revoked"));
    gates.push_back(make_simple_gate(GateKind::SecurityVetoClear, "no open security veto"));
    gates.push_back(make_simple_gate(GateKind::DependencyVetoClear, "no open dependency veto"));
    gates.push_back(make_simple_gate(GateKind::NoConflictingTransition, "no conflicting committed transition"));
    return gates;
}

}  // namespace

PromotionPolicy make_reference_policy(PromotionPolicyId id, PolicyGeneration generation) {
    PromotionPolicy policy;
    policy.id = id;
    policy.generation = generation;
    policy.name = "reference-policy";
    policy.description =
        "Reference promotion policy: a strict executable pipeline, a distinct model pipeline, and opaque artifacts "
        "that require provenance rather than test evidence.";
    policy.graph = LifecycleGraph::reference();
    policy.entry_stage = Stage::Candidate;

    // Independent candidate -> verified step that applies to every artifact
    // class and requires complete provenance.
    PolicyRule verify_any;
    verify_any.from = Stage::Candidate;
    verify_any.to = Stage::Verified;
    verify_any.requirements = common_hard_gates();
    verify_any.requirements.push_back(make_simple_gate(GateKind::ProvenanceResolved, "provenance references resolve"));
    verify_any.requirements.push_back(make_freshness_gate(EvidenceType::ProvenanceComplete, 30ULL * kDayMillis,
                                                          "provenance completeness evidence is fresh"));
    verify_any.preferences.push_back(GateKind::ArtifactNotSuperseded);
    verify_any.ordering = OrderingRule::LowerCommitSequence;
    policy.rules.push_back(verify_any);

    // Executable artifacts: verified -> qualified requires build, unit, and
    // integration evidence produced in a declared environment.
    PolicyRule qualified_executable;
    qualified_executable.has_kind_scope = true;
    qualified_executable.kind_scope = ArtifactKind::Executable;
    qualified_executable.from = Stage::Verified;
    qualified_executable.to = Stage::Qualified;
    qualified_executable.requirements = common_hard_gates();
    qualified_executable.requirements.push_back(
        make_evidence_gate(EvidenceType::BuildPass, "build evidence for the exact artifact digest"));
    qualified_executable.requirements.push_back(
        make_evidence_gate(EvidenceType::UnitTestPass, "unit test evidence for the exact artifact digest"));
    qualified_executable.requirements.push_back(
        make_evidence_gate(EvidenceType::IntegrationTestPass, "integration test evidence"));
    qualified_executable.requirements.push_back(
        make_freshness_gate(EvidenceType::BuildPass, 7ULL * kDayMillis, "build evidence is fresh"));
    qualified_executable.requirements.push_back(
        make_environment_gate(EvidenceType::UnitTestPass, "windows-x64-msvc", "unit tests ran in the declared environment"));
    qualified_executable.requirements.push_back(make_compatibility_gate(CompatibilityGeneration(1),
                                                                       "compatibility generation is current"));
    // Dependency constraints belong to qualification: reaching VERIFIED only
    // asserts that the artifact itself is complete and well evidenced, while
    // QUALIFIED is the stage at which its place among other artifacts, including
    // its declared dependencies, is established.
    qualified_executable.requirements.push_back(make_simple_gate(
        GateKind::DependentArtifactPromoted, "declared dependencies are promoted or absent"));
    qualified_executable.ordering = OrderingRule::LowerCommitSequence;
    policy.rules.push_back(qualified_executable);

    // Model artifacts: verified -> qualified requires model evaluation and data
    // validation. Unit tests are deliberately not required, and are not even
    // considered: a policy defines evidence requirements per artifact class and
    // transition rather than assuming every artifact needs the same proof.
    PolicyRule qualified_model;
    qualified_model.has_kind_scope = true;
    qualified_model.kind_scope = ArtifactKind::Model;
    qualified_model.from = Stage::Verified;
    qualified_model.to = Stage::Qualified;
    qualified_model.requirements = common_hard_gates();
    qualified_model.requirements.push_back(
        make_evidence_gate(EvidenceType::ModelEvalPass, "model evaluation evidence"));
    qualified_model.requirements.push_back(
        make_evidence_gate(EvidenceType::DataValidationPass, "training data validation evidence"));
    qualified_model.requirements.push_back(
        make_freshness_gate(EvidenceType::ModelEvalPass, 14ULL * kDayMillis, "model evaluation evidence is fresh"));
    qualified_model.requirements.push_back(make_compatibility_gate(CompatibilityGeneration(1),
                                                                  "compatibility generation is current"));
    qualified_model.requirements.push_back(make_simple_gate(
        GateKind::DependentArtifactPromoted, "declared dependencies are promoted or absent"));
    qualified_model.ordering = OrderingRule::LowerCommitSequence;
    policy.rules.push_back(qualified_model);

    // Generic fallback for every other artifact class: provenance and an
    // explicit verification pass are enough to qualify.
    PolicyRule qualified_generic;
    qualified_generic.from = Stage::Verified;
    qualified_generic.to = Stage::Qualified;
    qualified_generic.requirements = common_hard_gates();
    qualified_generic.requirements.push_back(
        make_evidence_gate(EvidenceType::ProvenanceComplete, "provenance completeness evidence"));
    qualified_generic.requirements.push_back(make_simple_gate(
        GateKind::DependentArtifactPromoted, "declared dependencies are promoted or absent"));
    policy.rules.push_back(qualified_generic);

    // Qualified -> staged applies to every class and adds sanitizer evidence.
    PolicyRule staged_any;
    staged_any.from = Stage::Qualified;
    staged_any.to = Stage::Staged;
    staged_any.requirements = common_hard_gates();
    staged_any.requirements.push_back(
        make_evidence_gate(EvidenceType::ReproducibilityPass, "reproducibility evidence"));
    staged_any.requirements.push_back(
        make_simple_gate(GateKind::CoordinatorEpochCurrent, "coordinator epoch is current"));
    staged_any.preferences.push_back(GateKind::PolicyGenerationCurrent);
    policy.rules.push_back(staged_any);

    // Staged -> approved requires an explicit machine critic approval bound to
    // the exact digest and transition.
    PolicyRule approved_any;
    approved_any.from = Stage::Staged;
    approved_any.to = Stage::Approved;
    approved_any.requirements = common_hard_gates();
    approved_any.requirements.push_back(make_approval_gate(
        EvidenceType::MachineCriticApproval, "machine critic approval bound to the exact artifact and transition"));
    policy.rules.push_back(approved_any);

    // Approved -> promoted is the only rule that yields promotion authority.
    PolicyRule promoted_any;
    promoted_any.from = Stage::Approved;
    promoted_any.to = Stage::Promoted;
    promoted_any.requirements = common_hard_gates();
    promoted_any.requirements.push_back(
        make_simple_gate(GateKind::PolicyGenerationCurrent, "governing policy generation is current"));
    promoted_any.requirements.push_back(make_simple_gate(
        GateKind::CoordinatorEpochCurrent, "coordinator epoch that produced the plan is current"));
    promoted_any.requirements.push_back(
        make_evidence_gate(EvidenceType::SignatureValid, "artifact signature evidence"));
    promoted_any.supersedes_previous = true;
    promoted_any.allow_rollback_eligibility = true;
    policy.rules.push_back(promoted_any);

    // Quarantine release returns an artifact to CANDIDATE for full
    // re-evaluation rather than restoring its prior stage.
    PolicyRule quarantine_release;
    quarantine_release.from = Stage::Quarantined;
    quarantine_release.to = Stage::Candidate;
    quarantine_release.requirements.push_back(
        make_evidence_gate(EvidenceType::SecurityScanPass, "security scan evidence for the release decision"));
    quarantine_release.requirements.push_back(make_evidence_gate(
        EvidenceType::HumanApproval, "authorized human approval of the quarantine release"));
    policy.rules.push_back(quarantine_release);

    // Revocation and supersession are governed transitions recorded by explicit
    // operations rather than by a promotion request.
    PolicyRule revoke_any;
    revoke_any.from = Stage::Promoted;
    revoke_any.to = Stage::Revoked;
    revoke_any.requirements.push_back(make_simple_gate(GateKind::ArtifactIdentity, "artifact identity is valid"));
    policy.rules.push_back(revoke_any);

    PolicyRule supersede_any;
    supersede_any.from = Stage::Promoted;
    supersede_any.to = Stage::Superseded;
    supersede_any.requirements.push_back(make_simple_gate(GateKind::ArtifactIdentity, "artifact identity is valid"));
    policy.rules.push_back(supersede_any);

    policy.policy_digest = policy.compute_digest();
    policy.rules.shrink_to_fit();
    return policy;
}

}  // namespace artifact_promotion
