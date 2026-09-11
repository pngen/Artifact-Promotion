// Artifact Promotion - canonical wire codecs for governed records.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/detail/codec.hpp"

namespace artifact_promotion::wire {
namespace {

// Fixed bounds for nested collections inside one record. They are independent
// of the engine's admission limits because they bound a single decode step.
constexpr std::size_t kMaxProvenance = 64;
constexpr std::size_t kMaxDependencies = 64;
constexpr std::size_t kMaxGraphEdges = 64;
constexpr std::size_t kMaxPolicyRules = 64;
constexpr std::size_t kMaxRuleGates = 32;
constexpr std::size_t kMaxRulePreferences = 32;
constexpr std::size_t kMaxDecisionGates = 64;
constexpr std::size_t kMaxDecisionReasons = 64;
constexpr std::size_t kMaxDecisionFindings = 64;

[[nodiscard]] Result<Gate> read_gate(Reader& reader) {
    Gate gate;
    auto kind = read_gate_kind(reader);
    if (!kind) {
        return kind.status();
    }
    gate.kind = kind.value();
    auto evidence_raw = reader.u8();
    if (!evidence_raw) {
        return evidence_raw.status();
    }
    if (evidence_raw.value() == 0) {
        gate.evidence_type = EvidenceType::Invalid;
    } else {
        if (!is_valid_evidence_type(evidence_raw.value())) {
            return Status(ErrorCode::InvalidEnum, "encoded evidence type is not a known evidence class");
        }
        gate.evidence_type = static_cast<EvidenceType>(evidence_raw.value());
    }
    auto custom = reader.text(kMaxNameLength);
    if (!custom) {
        return custom.status();
    }
    gate.custom_evidence_type = custom.value();
    auto max_age = reader.u64();
    if (!max_age) {
        return max_age.status();
    }
    gate.max_age_millis = max_age.value();
    auto compatibility = reader.counter<CompatibilityGenerationTag>();
    if (!compatibility) {
        return compatibility.status();
    }
    gate.required_compatibility_generation = compatibility.value();
    auto environment = reader.text(kMaxTextLength);
    if (!environment) {
        return environment.status();
    }
    gate.required_environment = environment.value();
    auto provenance = reader.identity<ProvenanceRefTag>();
    if (!provenance) {
        return provenance.status();
    }
    gate.required_provenance = provenance.value();
    auto label = reader.text(kMaxNameLength);
    if (!label) {
        return label.status();
    }
    gate.label = label.value();
    // A decoded gate is checked against the same rules a published gate obeys.
    // This is what turns "the bytes parsed" into "the policy means something".
    const Status gate_status = gate.validate();
    if (gate_status.failed()) {
        return Status(ErrorCode::PersistenceCorrupt,
                      std::string("decoded policy gate is not valid: ") + gate_status.render());
    }
    return gate;
}

[[nodiscard]] Result<GateExplanation> read_gate_explanation(Reader& reader) {
    GateExplanation explanation;
    auto kind = read_gate_kind(reader);
    if (!kind) {
        return kind.status();
    }
    explanation.kind = kind.value();
    auto label = reader.text(kMaxNameLength);
    if (!label) {
        return label.status();
    }
    explanation.label = label.value();
    auto status = read_gate_status(reader);
    if (!status) {
        return status.status();
    }
    explanation.status = status.value();
    auto code = read_error_code(reader);
    if (!code) {
        return code.status();
    }
    explanation.code = code.value();
    auto detail = reader.text(kMaxTextLength);
    if (!detail) {
        return detail.status();
    }
    explanation.detail = detail.value();
    return explanation;
}

[[nodiscard]] Result<Reason> read_reason(Reader& reader) {
    Reason reason;
    auto code = read_error_code(reader);
    if (!code) {
        return code.status();
    }
    reason.code = code.value();
    // Reason text is bounded by StaticString's fixed capacity, which is smaller
    // than the general text limit, so the stricter of the two is applied here.
    auto text = reader.text(StaticString::kCapacity);
    if (!text) {
        return text.status();
    }
    reason.text = StaticString(text.value().c_str());
    auto subject = reader.text(kMaxReferenceLength);
    if (!subject) {
        return subject.status();
    }
    reason.subject = subject.value();
    return reason;
}

[[nodiscard]] Result<EvidenceFinding> read_finding(Reader& reader) {
    EvidenceFinding finding;
    auto id = reader.identity<EvidenceIdTag>();
    if (!id) {
        return id.status();
    }
    finding.id = id.value();
    auto type = read_evidence_type(reader);
    if (!type) {
        return type.status();
    }
    finding.type = type.value();
    auto custom = reader.text(kMaxNameLength);
    if (!custom) {
        return custom.status();
    }
    finding.custom_type = custom.value();
    auto generation = reader.counter<EvidenceGenerationTag>();
    if (!generation) {
        return generation.status();
    }
    finding.generation = generation.value();
    auto result = read_evidence_result(reader);
    if (!result) {
        return result.status();
    }
    finding.result = result.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    finding.subject_digest = digest.value();
    auto revision = reader.identity<ArtifactRevisionTag>();
    if (!revision) {
        return revision.status();
    }
    finding.subject_revision = revision.value();
    auto code = read_error_code(reader);
    if (!code) {
        return code.status();
    }
    finding.code = code.value();
    auto detail = reader.text(kMaxTextLength);
    if (!detail) {
        return detail.status();
    }
    finding.detail = detail.value();
    return finding;
}

[[nodiscard]] Result<GateKind> require_gate_kind(std::uint64_t raw) {
    if (!is_valid_gate_kind(raw)) {
        return Status(ErrorCode::InvalidEnum, "encoded gate kind is not a known gate class");
    }
    return static_cast<GateKind>(raw);
}

// Reads a stage that may legitimately be absent. Only a history event uses this:
// an event such as an evidence submission or a recovery note records no
// lifecycle transition, so it has no source or destination stage. Every other
// stage field in the format must be a real stage.
[[nodiscard]] Result<Stage> read_optional_stage(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    if (raw.value() == 0) {
        return Stage::Invalid;
    }
    if (!is_valid_stage_value(raw.value())) {
        return Status(ErrorCode::InvalidStage, "encoded lifecycle stage is not a known stage");
    }
    return static_cast<Stage>(raw.value());
}

}  // namespace

Result<Stage> read_stage(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    if (!is_valid_stage_value(raw.value())) {
        return Status(ErrorCode::InvalidStage, "encoded lifecycle stage is not a known stage");
    }
    return static_cast<Stage>(raw.value());
}

Result<ArtifactKind> read_kind(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    if (!is_valid_artifact_kind(raw.value())) {
        return Status(ErrorCode::InvalidEnum, "encoded artifact kind is not a known artifact class");
    }
    return static_cast<ArtifactKind>(raw.value());
}

Result<EvidenceType> read_evidence_type(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    if (!is_valid_evidence_type(raw.value())) {
        return Status(ErrorCode::InvalidEnum, "encoded evidence type is not a known evidence class");
    }
    return static_cast<EvidenceType>(raw.value());
}

Result<EvidenceResult> read_evidence_result(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    if (!is_valid_evidence_result(raw.value())) {
        return Status(ErrorCode::InvalidEnum, "encoded evidence result is not a known result class");
    }
    return static_cast<EvidenceResult>(raw.value());
}

Result<ProvenanceResolution> read_provenance_resolution(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    if (raw.value() > static_cast<std::uint8_t>(ProvenanceResolution::Rejected)) {
        return Status(ErrorCode::InvalidEnum, "encoded provenance resolution is not a known value");
    }
    return static_cast<ProvenanceResolution>(raw.value());
}

Result<GateKind> read_gate_kind(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    return require_gate_kind(raw.value());
}

Result<OrderingRule> read_ordering_rule(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    if (!is_valid_ordering_rule(raw.value())) {
        return Status(ErrorCode::InvalidEnum, "encoded ordering rule is not a known rule");
    }
    return static_cast<OrderingRule>(raw.value());
}

Result<HistoryEventKind> read_history_kind(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    if (raw.value() > static_cast<std::uint8_t>(HistoryEventKind::RecoveryNote)) {
        return Status(ErrorCode::InvalidEnum, "encoded history event kind is not a known kind");
    }
    return static_cast<HistoryEventKind>(raw.value());
}

Result<PromotionOutcome> read_outcome(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    if (!is_valid_promotion_outcome(raw.value())) {
        return Status(ErrorCode::InvalidEnum, "encoded promotion outcome is not a known outcome");
    }
    return static_cast<PromotionOutcome>(raw.value());
}

Result<GateStatus> read_gate_status(Reader& reader) {
    auto raw = reader.u8();
    if (!raw) {
        return raw.status();
    }
    if (raw.value() > static_cast<std::uint8_t>(GateStatus::NotApplicable)) {
        return Status(ErrorCode::InvalidEnum, "encoded gate status is not a known status");
    }
    return static_cast<GateStatus>(raw.value());
}

Result<ErrorCode> read_error_code(Reader& reader) {
    auto raw = reader.u16();
    if (!raw) {
        return raw.status();
    }
    if (raw.value() > static_cast<std::uint16_t>(ErrorCode::InvariantViolation)) {
        return Status(ErrorCode::InvalidEnum, "encoded error code is not a known code");
    }
    return static_cast<ErrorCode>(raw.value());
}

void write_producer(Writer& writer, const ProducerIncarnation& value) {
    writer.identity(value.worker);
    writer.identity(value.boot);
}

Result<ProducerIncarnation> read_producer(Reader& reader) {
    ProducerIncarnation value;
    auto worker = reader.identity<WorkerIdTag>();
    if (!worker) {
        return worker.status();
    }
    value.worker = worker.value();
    auto boot = reader.identity<WorkerBootIdTag>();
    if (!boot) {
        return boot.status();
    }
    value.boot = boot.value();
    if (!value.valid()) {
        return Status(ErrorCode::InvalidIdentity,
                      "encoded producer incarnation has a boot identity without a worker identity");
    }
    return value;
}

void write_provenance(Writer& writer, const ProvenanceRecord& value, std::size_t limit) {
    writer.identity(value.reference);
    writer.text(value.source, limit);
    writer.text(value.subject, limit);
    writer.u8(static_cast<std::uint8_t>(value.resolution));
}

Result<ProvenanceRecord> read_provenance(Reader& reader, std::size_t limit) {
    ProvenanceRecord value;
    auto reference = reader.identity<ProvenanceRefTag>();
    if (!reference) {
        return reference.status();
    }
    value.reference = reference.value();
    auto source = reader.text(limit);
    if (!source) {
        return source.status();
    }
    value.source = source.value();
    auto subject = reader.text(limit);
    if (!subject) {
        return subject.status();
    }
    value.subject = subject.value();
    auto resolution = read_provenance_resolution(reader);
    if (!resolution) {
        return resolution.status();
    }
    value.resolution = resolution.value();
    return value;
}

void write_compatibility(Writer& writer, const CompatibilityDescriptor& value) {
    writer.identity(value.profile);
    writer.counter(value.generation);
}

Result<CompatibilityDescriptor> read_compatibility(Reader& reader) {
    CompatibilityDescriptor value;
    auto profile = reader.identity<CompatibilityProfileIdTag>();
    if (!profile) {
        return profile.status();
    }
    value.profile = profile.value();
    auto generation = reader.counter<CompatibilityGenerationTag>();
    if (!generation) {
        return generation.status();
    }
    value.generation = generation.value();
    return value;
}

void write_lifecycle_graph(Writer& writer, const LifecycleGraph& value) {
    writer.list(value.edges().size(), [&](Writer& out, std::size_t index) {
        const LifecycleGraph::Edge& edge = value.edges()[index];
        out.u8(static_cast<std::uint8_t>(edge.from));
        out.u8(static_cast<std::uint8_t>(edge.to));
    });
}

Result<LifecycleGraph> read_lifecycle_graph(Reader& reader) {
    auto count = reader.count(kMaxGraphEdges);
    if (!count) {
        return count.status();
    }
    LifecycleGraph graph;
    for (std::size_t i = 0; i < count.value(); ++i) {
        auto from = read_stage(reader);
        if (!from) {
            return from.status();
        }
        auto to = read_stage(reader);
        if (!to) {
            return to.status();
        }
        if (from.value() == Stage::Invalid || to.value() == Stage::Invalid) {
            return Status(ErrorCode::InvalidStage, "encoded lifecycle graph contains the INVALID stage");
        }
        if (!graph.add_edge(from.value(), to.value())) {
            return Status(ErrorCode::InvalidTransition,
                          "encoded lifecycle graph contains a duplicate or self-referential edge");
        }
    }
    graph.canonicalize();
    return graph;
}

void write_policy(Writer& writer, const PromotionPolicy& value) {
    writer.identity(value.id);
    writer.counter(value.generation);
    writer.text(value.name, kMaxNameLength);
    writer.text(value.description, kMaxTextLength);
    writer.u8(static_cast<std::uint8_t>(value.entry_stage));
    write_lifecycle_graph(writer, value.graph);
    writer.digest(value.policy_digest);
    writer.list(value.rules.size(), [&](Writer& out, std::size_t index) {
        const PolicyRule& rule = value.rules[index];
        out.boolean(rule.has_kind_scope);
        // An unscoped rule carries no artifact class. That state is written as
        // the explicit zero sentinel rather than an arbitrary class, and the
        // reader accepts it only in that position.
        out.u8(static_cast<std::uint8_t>(rule.has_kind_scope ? rule.kind_scope : ArtifactKind::Invalid));
        out.u8(static_cast<std::uint8_t>(rule.from));
        out.u8(static_cast<std::uint8_t>(rule.to));
        out.u8(static_cast<std::uint8_t>(rule.ordering));
        out.boolean(rule.allow_idempotent_replay);
        out.boolean(rule.allow_rollback_eligibility);
        out.boolean(rule.supersedes_previous);
        out.u32(static_cast<std::uint32_t>(rule.requirements.size()));
        out.u32(static_cast<std::uint32_t>(rule.preferences.size()));
        for (const Gate& gate : rule.requirements) {
            out.u8(static_cast<std::uint8_t>(gate.kind));
            // A gate that does not reference evidence writes the explicit zero
            // sentinel. It is not an evidence class, and the reader accepts it
            // only for a gate kind that carries no evidence reference.
            const bool has_evidence = gate.evidence_type != EvidenceType::Invalid;
            out.u8(has_evidence ? static_cast<std::uint8_t>(gate.evidence_type) : std::uint8_t{0});
            out.text(gate.custom_evidence_type, kMaxNameLength);
            out.u64(gate.max_age_millis);
            out.counter(gate.required_compatibility_generation);
            out.text(gate.required_environment, kMaxTextLength);
            out.identity(gate.required_provenance);
            out.text(gate.label, kMaxNameLength);
        }
        for (const GateKind preference : rule.preferences) {
            out.u8(static_cast<std::uint8_t>(preference));
        }
    });
}

Result<PromotionPolicy> read_policy(Reader& reader) {
    PromotionPolicy policy;
    auto id = reader.identity<PromotionPolicyIdTag>();
    if (!id) {
        return id.status();
    }
    policy.id = id.value();
    auto generation = reader.counter<PolicyGenerationTag>();
    if (!generation) {
        return generation.status();
    }
    policy.generation = generation.value();
    auto name = reader.text(kMaxNameLength);
    if (!name) {
        return name.status();
    }
    policy.name = name.value();
    auto description = reader.text(kMaxTextLength);
    if (!description) {
        return description.status();
    }
    policy.description = description.value();
    auto entry = read_stage(reader);
    if (!entry) {
        return entry.status();
    }
    policy.entry_stage = entry.value();
    auto graph = read_lifecycle_graph(reader);
    if (!graph) {
        return graph.status();
    }
    policy.graph = graph.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    policy.policy_digest = digest.value();

    auto rule_count = reader.count(kMaxPolicyRules);
    if (!rule_count) {
        return rule_count.status();
    }
    for (std::size_t i = 0; i < rule_count.value(); ++i) {
        PolicyRule rule;
        auto has_scope = reader.boolean();
        if (!has_scope) {
            return has_scope.status();
        }
        rule.has_kind_scope = has_scope.value();
        auto scope_raw = reader.u8();
        if (!scope_raw) {
            return scope_raw.status();
        }
        if (scope_raw.value() == 0) {
            // The zero sentinel means "this rule is not scoped to an artifact
            // class". It is only valid when the scope flag says so.
            if (rule.has_kind_scope) {
                return Status(ErrorCode::PersistenceCorrupt,
                              "policy rule claims an artifact class scope but carries the empty sentinel");
            }
            rule.kind_scope = ArtifactKind::Invalid;
        } else {
            if (!is_valid_artifact_kind(scope_raw.value())) {
                return Status(ErrorCode::InvalidEnum, "encoded artifact kind is not a known artifact class");
            }
            if (!rule.has_kind_scope) {
                return Status(ErrorCode::PersistenceCorrupt,
                              "policy rule carries an artifact class without a scope flag");
            }
            rule.kind_scope = static_cast<ArtifactKind>(scope_raw.value());
        }
        auto from = read_stage(reader);
        if (!from) {
            return from.status();
        }
        rule.from = from.value();
        auto to = read_stage(reader);
        if (!to) {
            return to.status();
        }
        rule.to = to.value();
        auto ordering = read_ordering_rule(reader);
        if (!ordering) {
            return ordering.status();
        }
        rule.ordering = ordering.value();
        auto idempotent = reader.boolean();
        if (!idempotent) {
            return idempotent.status();
        }
        rule.allow_idempotent_replay = idempotent.value();
        auto rollback = reader.boolean();
        if (!rollback) {
            return rollback.status();
        }
        rule.allow_rollback_eligibility = rollback.value();
        auto supersedes = reader.boolean();
        if (!supersedes) {
            return supersedes.status();
        }
        rule.supersedes_previous = supersedes.value();

        auto requirement_count = reader.count(kMaxRuleGates);
        if (!requirement_count) {
            return requirement_count.status();
        }
        auto preference_count = reader.count(kMaxRulePreferences);
        if (!preference_count) {
            return preference_count.status();
        }
        // The declared counts are advisory: the actual number of encoded
        // elements is read below, and any mismatch is caught by the section
        // length check when the enclosing section is verified.
        for (std::size_t gate_index = 0; gate_index < requirement_count.value(); ++gate_index) {
            auto gate = read_gate(reader);
            if (!gate) {
                return gate.status();
            }
            rule.requirements.push_back(gate.value());
        }
        for (std::size_t preference_index = 0; preference_index < preference_count.value(); ++preference_index) {
            auto preference = read_gate_kind(reader);
            if (!preference) {
                return preference.status();
            }
            rule.preferences.push_back(preference.value());
        }
        policy.rules.push_back(std::move(rule));
    }
    return policy;
}

void write_artifact(Writer& writer, const ArtifactRecord& value) {
    writer.identity(value.id);
    writer.identity(value.revision);
    writer.counter(value.generation);
    writer.u8(static_cast<std::uint8_t>(value.kind));
    writer.digest(value.digest);
    writer.u64(value.size_bytes);
    writer.text(value.name, kMaxNameLength);
    write_producer(writer, value.producer);
    writer.counter(value.created_sequence);
    writer.u64(value.created_unix_millis);
    writer.list(value.provenance.size(), [&](Writer& out, std::size_t index) {
        write_provenance(out, value.provenance[index], kMaxReferenceLength);
    });
    writer.list(value.dependencies.size(), [&](Writer& out, std::size_t index) {
        out.text(value.dependencies[index], kMaxNameLength);
    });
    writer.u8(static_cast<std::uint8_t>(value.stage));
    writer.counter(value.stage_generation);
    writer.boolean(value.promoted);
    writer.identity(value.promotion_decision);
    writer.identity(value.promotion_authority);
    writer.counter(value.promotion_sequence);
    writer.counter(value.last_sequence);

    writer.boolean(value.quarantine.active);
    writer.text(value.quarantine.reason_class, kMaxNameLength);
    writer.text(value.quarantine.detail, kMaxTextLength);
    writer.identity(value.quarantine.authority);
    writer.counter(value.quarantine.sequence);
    writer.counter(value.quarantine.policy_generation);

    writer.boolean(value.revocation.active);
    writer.identity(value.revocation.decision);
    writer.text(value.revocation.reason_class, kMaxNameLength);
    writer.text(value.revocation.detail, kMaxTextLength);
    writer.identity(value.revocation.authority);
    writer.counter(value.revocation.sequence);
    writer.counter(value.revocation.policy_generation);
    writer.identity(value.revocation.cause);

    writer.boolean(value.supersession.active);
    writer.identity(value.supersession.successor);
    writer.identity(value.supersession.successor_revision);
    writer.text(value.supersession.reason, kMaxTextLength);
    writer.identity(value.supersession.authority);
    writer.counter(value.supersession.sequence);
}

Result<ArtifactRecord> read_artifact(Reader& reader) {
    ArtifactRecord value;
    auto id = reader.identity<ArtifactIdTag>();
    if (!id) {
        return id.status();
    }
    value.id = id.value();
    auto revision = reader.identity<ArtifactRevisionTag>();
    if (!revision) {
        return revision.status();
    }
    value.revision = revision.value();
    auto generation = reader.counter<ArtifactGenerationTag>();
    if (!generation) {
        return generation.status();
    }
    value.generation = generation.value();
    auto kind = read_kind(reader);
    if (!kind) {
        return kind.status();
    }
    value.kind = kind.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    value.digest = digest.value();
    auto size = reader.u64();
    if (!size) {
        return size.status();
    }
    value.size_bytes = size.value();
    auto name = reader.text(kMaxNameLength);
    if (!name) {
        return name.status();
    }
    value.name = name.value();
    auto producer = read_producer(reader);
    if (!producer) {
        return producer.status();
    }
    value.producer = producer.value();
    auto created_sequence = reader.counter<CommitSequenceTag>();
    if (!created_sequence) {
        return created_sequence.status();
    }
    value.created_sequence = created_sequence.value();
    auto created_time = reader.u64();
    if (!created_time) {
        return created_time.status();
    }
    value.created_unix_millis = created_time.value();

    auto provenance_count = reader.count(kMaxProvenance);
    if (!provenance_count) {
        return provenance_count.status();
    }
    for (std::size_t i = 0; i < provenance_count.value(); ++i) {
        auto record = read_provenance(reader, kMaxReferenceLength);
        if (!record) {
            return record.status();
        }
        value.provenance.push_back(std::move(record.value()));
    }
    auto dependency_count = reader.count(kMaxDependencies);
    if (!dependency_count) {
        return dependency_count.status();
    }
    for (std::size_t i = 0; i < dependency_count.value(); ++i) {
        auto dependency = reader.text(kMaxNameLength);
        if (!dependency) {
            return dependency.status();
        }
        value.dependencies.push_back(dependency.value());
    }

    auto stage = read_stage(reader);
    if (!stage) {
        return stage.status();
    }
    value.stage = stage.value();
    auto stage_generation = reader.counter<StageGenerationTag>();
    if (!stage_generation) {
        return stage_generation.status();
    }
    value.stage_generation = stage_generation.value();
    auto promoted = reader.boolean();
    if (!promoted) {
        return promoted.status();
    }
    value.promoted = promoted.value();
    auto decision = reader.identity<PromotionDecisionIdTag>();
    if (!decision) {
        return decision.status();
    }
    value.promotion_decision = decision.value();
    auto authority = reader.identity<AuthorityIdTag>();
    if (!authority) {
        return authority.status();
    }
    value.promotion_authority = authority.value();
    auto promotion_sequence = reader.counter<CommitSequenceTag>();
    if (!promotion_sequence) {
        return promotion_sequence.status();
    }
    value.promotion_sequence = promotion_sequence.value();
    auto last_sequence = reader.counter<CommitSequenceTag>();
    if (!last_sequence) {
        return last_sequence.status();
    }
    value.last_sequence = last_sequence.value();

    auto quarantine_active = reader.boolean();
    if (!quarantine_active) {
        return quarantine_active.status();
    }
    value.quarantine.active = quarantine_active.value();
    auto quarantine_class = reader.text(kMaxNameLength);
    if (!quarantine_class) {
        return quarantine_class.status();
    }
    value.quarantine.reason_class = quarantine_class.value();
    auto quarantine_detail = reader.text(kMaxTextLength);
    if (!quarantine_detail) {
        return quarantine_detail.status();
    }
    value.quarantine.detail = quarantine_detail.value();
    auto quarantine_authority = reader.identity<AuthorityIdTag>();
    if (!quarantine_authority) {
        return quarantine_authority.status();
    }
    value.quarantine.authority = quarantine_authority.value();
    auto quarantine_sequence = reader.counter<CommitSequenceTag>();
    if (!quarantine_sequence) {
        return quarantine_sequence.status();
    }
    value.quarantine.sequence = quarantine_sequence.value();
    auto quarantine_policy = reader.counter<PolicyGenerationTag>();
    if (!quarantine_policy) {
        return quarantine_policy.status();
    }
    value.quarantine.policy_generation = quarantine_policy.value();

    auto revocation_active = reader.boolean();
    if (!revocation_active) {
        return revocation_active.status();
    }
    value.revocation.active = revocation_active.value();
    auto revocation_decision = reader.identity<PromotionDecisionIdTag>();
    if (!revocation_decision) {
        return revocation_decision.status();
    }
    value.revocation.decision = revocation_decision.value();
    auto revocation_class = reader.text(kMaxNameLength);
    if (!revocation_class) {
        return revocation_class.status();
    }
    value.revocation.reason_class = revocation_class.value();
    auto revocation_detail = reader.text(kMaxTextLength);
    if (!revocation_detail) {
        return revocation_detail.status();
    }
    value.revocation.detail = revocation_detail.value();
    auto revocation_authority = reader.identity<AuthorityIdTag>();
    if (!revocation_authority) {
        return revocation_authority.status();
    }
    value.revocation.authority = revocation_authority.value();
    auto revocation_sequence = reader.counter<CommitSequenceTag>();
    if (!revocation_sequence) {
        return revocation_sequence.status();
    }
    value.revocation.sequence = revocation_sequence.value();
    auto revocation_policy = reader.counter<PolicyGenerationTag>();
    if (!revocation_policy) {
        return revocation_policy.status();
    }
    value.revocation.policy_generation = revocation_policy.value();
    auto revocation_cause = reader.identity<EvidenceIdTag>();
    if (!revocation_cause) {
        return revocation_cause.status();
    }
    value.revocation.cause = revocation_cause.value();

    auto supersession_active = reader.boolean();
    if (!supersession_active) {
        return supersession_active.status();
    }
    value.supersession.active = supersession_active.value();
    auto successor = reader.identity<ArtifactIdTag>();
    if (!successor) {
        return successor.status();
    }
    value.supersession.successor = successor.value();
    auto successor_revision = reader.identity<ArtifactRevisionTag>();
    if (!successor_revision) {
        return successor_revision.status();
    }
    value.supersession.successor_revision = successor_revision.value();
    auto supersession_reason = reader.text(kMaxTextLength);
    if (!supersession_reason) {
        return supersession_reason.status();
    }
    value.supersession.reason = supersession_reason.value();
    auto supersession_authority = reader.identity<AuthorityIdTag>();
    if (!supersession_authority) {
        return supersession_authority.status();
    }
    value.supersession.authority = supersession_authority.value();
    auto supersession_sequence = reader.counter<CommitSequenceTag>();
    if (!supersession_sequence) {
        return supersession_sequence.status();
    }
    value.supersession.sequence = supersession_sequence.value();

    if (!value.valid()) {
        return Status(ErrorCode::PersistenceCorrupt, "decoded artifact record fails its own validity rules");
    }
    return value;
}

void write_evidence(Writer& writer, const EvidenceRecord& value) {
    writer.identity(value.id);
    writer.u8(static_cast<std::uint8_t>(value.type));
    writer.text(value.custom_type, kMaxNameLength);
    writer.counter(value.generation);
    writer.identity(value.subject);
    writer.digest(value.subject_digest);
    writer.identity(value.subject_revision);
    write_producer(writer, value.producer);
    writer.u8(static_cast<std::uint8_t>(value.result));
    writer.u32(value.confidence_milli);
    writer.text(value.measurement, kMaxTextLength);
    writer.text(value.detail, kMaxTextLength);
    writer.digest(value.payload_digest);
    writer.digest(value.integrity_digest);
    writer.identity(value.provenance);
    writer.counter(value.created_sequence);
    writer.u64(value.produced_unix_millis);
    writer.boolean(value.has_validity_window);
    writer.u64(value.valid_from_unix_millis);
    writer.u64(value.valid_until_unix_millis);
    writer.text(value.environment, kMaxTextLength);
    writer.boolean(value.revoked);
    writer.text(value.revocation_reason, kMaxTextLength);
    writer.identity(value.revocation_authority);
    writer.counter(value.revocation_sequence);
    writer.boolean(value.superseded);
    writer.identity(value.superseded_by);
}

Result<EvidenceRecord> read_evidence(Reader& reader) {
    EvidenceRecord value;
    auto id = reader.identity<EvidenceIdTag>();
    if (!id) {
        return id.status();
    }
    value.id = id.value();
    auto type = read_evidence_type(reader);
    if (!type) {
        return type.status();
    }
    value.type = type.value();
    auto custom = reader.text(kMaxNameLength);
    if (!custom) {
        return custom.status();
    }
    value.custom_type = custom.value();
    auto generation = reader.counter<EvidenceGenerationTag>();
    if (!generation) {
        return generation.status();
    }
    value.generation = generation.value();
    auto subject = reader.identity<ArtifactIdTag>();
    if (!subject) {
        return subject.status();
    }
    value.subject = subject.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    value.subject_digest = digest.value();
    auto revision = reader.identity<ArtifactRevisionTag>();
    if (!revision) {
        return revision.status();
    }
    value.subject_revision = revision.value();
    auto producer = read_producer(reader);
    if (!producer) {
        return producer.status();
    }
    value.producer = producer.value();
    auto result = read_evidence_result(reader);
    if (!result) {
        return result.status();
    }
    value.result = result.value();
    auto confidence = reader.u32();
    if (!confidence) {
        return confidence.status();
    }
    value.confidence_milli = confidence.value();
    auto measurement = reader.text(kMaxTextLength);
    if (!measurement) {
        return measurement.status();
    }
    value.measurement = measurement.value();
    auto detail = reader.text(kMaxTextLength);
    if (!detail) {
        return detail.status();
    }
    value.detail = detail.value();
    auto payload = reader.digest();
    if (!payload) {
        return payload.status();
    }
    value.payload_digest = payload.value();
    auto integrity = reader.digest();
    if (!integrity) {
        return integrity.status();
    }
    value.integrity_digest = integrity.value();
    auto provenance = reader.identity<ProvenanceRefTag>();
    if (!provenance) {
        return provenance.status();
    }
    value.provenance = provenance.value();
    auto created = reader.counter<CommitSequenceTag>();
    if (!created) {
        return created.status();
    }
    value.created_sequence = created.value();
    auto produced = reader.u64();
    if (!produced) {
        return produced.status();
    }
    value.produced_unix_millis = produced.value();
    auto has_window = reader.boolean();
    if (!has_window) {
        return has_window.status();
    }
    value.has_validity_window = has_window.value();
    auto from_time = reader.u64();
    if (!from_time) {
        return from_time.status();
    }
    value.valid_from_unix_millis = from_time.value();
    auto until_time = reader.u64();
    if (!until_time) {
        return until_time.status();
    }
    value.valid_until_unix_millis = until_time.value();
    auto environment = reader.text(kMaxTextLength);
    if (!environment) {
        return environment.status();
    }
    value.environment = environment.value();
    auto revoked = reader.boolean();
    if (!revoked) {
        return revoked.status();
    }
    value.revoked = revoked.value();
    auto revocation_reason = reader.text(kMaxTextLength);
    if (!revocation_reason) {
        return revocation_reason.status();
    }
    value.revocation_reason = revocation_reason.value();
    auto revocation_authority = reader.identity<AuthorityIdTag>();
    if (!revocation_authority) {
        return revocation_authority.status();
    }
    value.revocation_authority = revocation_authority.value();
    auto revocation_sequence = reader.counter<CommitSequenceTag>();
    if (!revocation_sequence) {
        return revocation_sequence.status();
    }
    value.revocation_sequence = revocation_sequence.value();
    auto superseded = reader.boolean();
    if (!superseded) {
        return superseded.status();
    }
    value.superseded = superseded.value();
    auto superseded_by = reader.identity<EvidenceIdTag>();
    if (!superseded_by) {
        return superseded_by.status();
    }
    value.superseded_by = superseded_by.value();

    if (!value.valid()) {
        return Status(ErrorCode::PersistenceCorrupt, "decoded evidence record fails its own validity rules");
    }
    if (compute_evidence_integrity(value) != value.integrity_digest) {
        return Status(ErrorCode::PersistenceCorrupt, "decoded evidence record fails its integrity check");
    }
    return value;
}

void write_authority(Writer& writer, const CoordinatorAuthority& value) {
    writer.identity(value.coordinator);
    writer.counter(value.epoch);
}

Result<CoordinatorAuthority> read_authority(Reader& reader) {
    CoordinatorAuthority value;
    auto coordinator = reader.identity<CoordinatorIdTag>();
    if (!coordinator) {
        return coordinator.status();
    }
    value.coordinator = coordinator.value();
    auto epoch = reader.counter<CoordinatorEpochTag>();
    if (!epoch) {
        return epoch.status();
    }
    value.epoch = epoch.value();
    return value;
}

void write_plan(Writer& writer, const PromotionPlan& value) {
    writer.identity(value.id);
    writer.identity(value.request);
    writer.identity(value.attempt);
    writer.identity(value.decision);
    writer.identity(value.artifact);
    writer.identity(value.artifact_revision);
    writer.counter(value.artifact_generation);
    writer.digest(value.artifact_digest);
    writer.u8(static_cast<std::uint8_t>(value.artifact_kind));
    writer.u8(static_cast<std::uint8_t>(value.from));
    writer.u8(static_cast<std::uint8_t>(value.to));
    writer.counter(value.stage_generation);
    writer.identity(value.policy);
    writer.counter(value.policy_generation);
    writer.digest(value.policy_digest);
    writer.digest(value.lifecycle_digest);
    write_authority(writer, value.authority);
    writer.digest(value.evidence_snapshot_digest);
    writer.u32(static_cast<std::uint32_t>(value.evidence_entry_count));
    writer.identity(value.compatibility_profile);
    writer.counter(value.compatibility_generation);
    writer.counter(value.artifact_sequence);
    writer.counter(value.created_sequence);
    writer.counter(value.decision_sequence);
    writer.boolean(value.has_expiry);
    writer.u64(value.expires_unix_millis);
}

Result<PromotionPlan> read_plan(Reader& reader) {
    PromotionPlan value;
    auto id = reader.identity<PromotionPlanIdTag>();
    if (!id) {
        return id.status();
    }
    value.id = id.value();
    auto request = reader.identity<PromotionRequestIdTag>();
    if (!request) {
        return request.status();
    }
    value.request = request.value();
    auto attempt = reader.identity<PromotionAttemptIdTag>();
    if (!attempt) {
        return attempt.status();
    }
    value.attempt = attempt.value();
    auto decision = reader.identity<PromotionDecisionIdTag>();
    if (!decision) {
        return decision.status();
    }
    value.decision = decision.value();
    auto artifact = reader.identity<ArtifactIdTag>();
    if (!artifact) {
        return artifact.status();
    }
    value.artifact = artifact.value();
    auto revision = reader.identity<ArtifactRevisionTag>();
    if (!revision) {
        return revision.status();
    }
    value.artifact_revision = revision.value();
    auto generation = reader.counter<ArtifactGenerationTag>();
    if (!generation) {
        return generation.status();
    }
    value.artifact_generation = generation.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    value.artifact_digest = digest.value();
    auto kind = read_kind(reader);
    if (!kind) {
        return kind.status();
    }
    value.artifact_kind = kind.value();
    auto from = read_stage(reader);
    if (!from) {
        return from.status();
    }
    value.from = from.value();
    auto to = read_stage(reader);
    if (!to) {
        return to.status();
    }
    value.to = to.value();
    auto stage_generation = reader.counter<StageGenerationTag>();
    if (!stage_generation) {
        return stage_generation.status();
    }
    value.stage_generation = stage_generation.value();
    auto policy = reader.identity<PromotionPolicyIdTag>();
    if (!policy) {
        return policy.status();
    }
    value.policy = policy.value();
    auto policy_generation = reader.counter<PolicyGenerationTag>();
    if (!policy_generation) {
        return policy_generation.status();
    }
    value.policy_generation = policy_generation.value();
    auto policy_digest = reader.digest();
    if (!policy_digest) {
        return policy_digest.status();
    }
    value.policy_digest = policy_digest.value();
    auto lifecycle_digest = reader.digest();
    if (!lifecycle_digest) {
        return lifecycle_digest.status();
    }
    value.lifecycle_digest = lifecycle_digest.value();
    auto authority = read_authority(reader);
    if (!authority) {
        return authority.status();
    }
    value.authority = authority.value();
    auto snapshot = reader.digest();
    if (!snapshot) {
        return snapshot.status();
    }
    value.evidence_snapshot_digest = snapshot.value();
    auto entries = reader.u32();
    if (!entries) {
        return entries.status();
    }
    value.evidence_entry_count = entries.value();
    auto profile = reader.identity<CompatibilityProfileIdTag>();
    if (!profile) {
        return profile.status();
    }
    value.compatibility_profile = profile.value();
    auto compatibility = reader.counter<CompatibilityGenerationTag>();
    if (!compatibility) {
        return compatibility.status();
    }
    value.compatibility_generation = compatibility.value();
    auto artifact_sequence = reader.counter<CommitSequenceTag>();
    if (!artifact_sequence) {
        return artifact_sequence.status();
    }
    value.artifact_sequence = artifact_sequence.value();
    auto created = reader.counter<CommitSequenceTag>();
    if (!created) {
        return created.status();
    }
    value.created_sequence = created.value();
    auto decision_sequence = reader.counter<DecisionSequenceTag>();
    if (!decision_sequence) {
        return decision_sequence.status();
    }
    value.decision_sequence = decision_sequence.value();
    auto has_expiry = reader.boolean();
    if (!has_expiry) {
        return has_expiry.status();
    }
    value.has_expiry = has_expiry.value();
    auto expires = reader.u64();
    if (!expires) {
        return expires.status();
    }
    value.expires_unix_millis = expires.value();

    if (!value.valid()) {
        return Status(ErrorCode::PersistenceCorrupt, "decoded promotion plan fails its own validity rules");
    }
    return value;
}

void write_decision(Writer& writer, const PromotionDecision& value) {
    writer.identity(value.id);
    writer.identity(value.request);
    writer.identity(value.attempt);
    writer.identity(value.artifact);
    writer.identity(value.artifact_revision);
    writer.counter(value.artifact_generation);
    writer.digest(value.artifact_digest);
    writer.u8(static_cast<std::uint8_t>(value.artifact_kind));
    writer.u8(static_cast<std::uint8_t>(value.from));
    writer.u8(static_cast<std::uint8_t>(value.to));
    writer.u8(static_cast<std::uint8_t>(value.outcome));
    writer.identity(value.policy);
    writer.counter(value.policy_generation);
    writer.digest(value.policy_digest);
    write_authority(writer, value.authority);
    writer.counter(value.sequence);
    writer.digest(value.evidence_snapshot_digest);
    writer.identity(value.plan);
    writer.boolean(value.authoritative);
    writer.boolean(value.decided_unix_millis.has_value());
    writer.u64(value.decided_unix_millis.value_or(0));
    writer.list(value.gates.size(), [&](Writer& out, std::size_t index) {
        const GateExplanation& gate = value.gates[index];
        out.u8(static_cast<std::uint8_t>(gate.kind));
        out.text(gate.label, kMaxNameLength);
        out.u8(static_cast<std::uint8_t>(gate.status));
        out.u16(static_cast<std::uint16_t>(gate.code));
        out.text(gate.detail, kMaxTextLength);
    });
    writer.list(value.findings.size(), [&](Writer& out, std::size_t index) {
        const EvidenceFinding& finding = value.findings[index];
        out.identity(finding.id);
        out.u8(static_cast<std::uint8_t>(finding.type));
        out.text(finding.custom_type, kMaxNameLength);
        out.counter(finding.generation);
        out.u8(static_cast<std::uint8_t>(finding.result));
        out.digest(finding.subject_digest);
        out.identity(finding.subject_revision);
        out.u16(static_cast<std::uint16_t>(finding.code));
        out.text(finding.detail, kMaxTextLength);
    });
    writer.list(value.reasons.size(), [&](Writer& out, std::size_t index) {
        const Reason& reason = value.reasons[index];
        out.u16(static_cast<std::uint16_t>(reason.code));
        out.text(reason.text.view(), kMaxTextLength);
        out.text(reason.subject, kMaxReferenceLength);
    });
}

Result<PromotionDecision> read_decision(Reader& reader) {
    PromotionDecision value;
    auto id = reader.identity<PromotionDecisionIdTag>();
    if (!id) {
        return id.status();
    }
    value.id = id.value();
    auto request = reader.identity<PromotionRequestIdTag>();
    if (!request) {
        return request.status();
    }
    value.request = request.value();
    auto attempt = reader.identity<PromotionAttemptIdTag>();
    if (!attempt) {
        return attempt.status();
    }
    value.attempt = attempt.value();
    auto artifact = reader.identity<ArtifactIdTag>();
    if (!artifact) {
        return artifact.status();
    }
    value.artifact = artifact.value();
    auto revision = reader.identity<ArtifactRevisionTag>();
    if (!revision) {
        return revision.status();
    }
    value.artifact_revision = revision.value();
    auto generation = reader.counter<ArtifactGenerationTag>();
    if (!generation) {
        return generation.status();
    }
    value.artifact_generation = generation.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    value.artifact_digest = digest.value();
    auto kind = read_kind(reader);
    if (!kind) {
        return kind.status();
    }
    value.artifact_kind = kind.value();
    auto from = read_stage(reader);
    if (!from) {
        return from.status();
    }
    value.from = from.value();
    auto to = read_stage(reader);
    if (!to) {
        return to.status();
    }
    value.to = to.value();
    auto outcome = read_outcome(reader);
    if (!outcome) {
        return outcome.status();
    }
    value.outcome = outcome.value();
    auto policy = reader.identity<PromotionPolicyIdTag>();
    if (!policy) {
        return policy.status();
    }
    value.policy = policy.value();
    auto policy_generation = reader.counter<PolicyGenerationTag>();
    if (!policy_generation) {
        return policy_generation.status();
    }
    value.policy_generation = policy_generation.value();
    auto policy_digest = reader.digest();
    if (!policy_digest) {
        return policy_digest.status();
    }
    value.policy_digest = policy_digest.value();
    auto authority = read_authority(reader);
    if (!authority) {
        return authority.status();
    }
    value.authority = authority.value();
    auto sequence = reader.counter<DecisionSequenceTag>();
    if (!sequence) {
        return sequence.status();
    }
    value.sequence = sequence.value();
    auto snapshot = reader.digest();
    if (!snapshot) {
        return snapshot.status();
    }
    value.evidence_snapshot_digest = snapshot.value();
    auto plan = reader.identity<PromotionPlanIdTag>();
    if (!plan) {
        return plan.status();
    }
    value.plan = plan.value();
    auto authoritative = reader.boolean();
    if (!authoritative) {
        return authoritative.status();
    }
    value.authoritative = authoritative.value();
    auto has_decided = reader.boolean();
    if (!has_decided) {
        return has_decided.status();
    }
    auto decided = reader.u64();
    if (!decided) {
        return decided.status();
    }
    if (has_decided.value()) {
        value.decided_unix_millis = decided.value();
    }

    auto gate_count = reader.count(kMaxDecisionGates);
    if (!gate_count) {
        return gate_count.status();
    }
    for (std::size_t i = 0; i < gate_count.value(); ++i) {
        auto gate = read_gate_explanation(reader);
        if (!gate) {
            return gate.status();
        }
        value.gates.push_back(std::move(gate.value()));
    }
    auto finding_count = reader.count(kMaxDecisionFindings);
    if (!finding_count) {
        return finding_count.status();
    }
    for (std::size_t i = 0; i < finding_count.value(); ++i) {
        auto finding = read_finding(reader);
        if (!finding) {
            return finding.status();
        }
        value.findings.push_back(std::move(finding.value()));
    }
    auto reason_count = reader.count(kMaxDecisionReasons);
    if (!reason_count) {
        return reason_count.status();
    }
    for (std::size_t i = 0; i < reason_count.value(); ++i) {
        auto reason = read_reason(reader);
        if (!reason) {
            return reason.status();
        }
        value.reasons.push_back(std::move(reason.value()));
    }
    return value;
}

void write_promotion_record(Writer& writer, const PromotionRecord& value) {
    writer.identity(value.transition);
    writer.identity(value.artifact);
    writer.identity(value.artifact_revision);
    writer.digest(value.artifact_digest);
    writer.u8(static_cast<std::uint8_t>(value.from));
    writer.u8(static_cast<std::uint8_t>(value.to));
    writer.identity(value.decision);
    writer.identity(value.plan);
    writer.identity(value.request);
    writer.identity(value.attempt);
    writer.identity(value.policy);
    writer.counter(value.policy_generation);
    write_authority(writer, value.authority);
    writer.digest(value.evidence_snapshot_digest);
    writer.counter(value.sequence);
    writer.u64(value.committed_unix_millis);
    writer.text(value.note, kMaxTextLength);
}

Result<PromotionRecord> read_promotion_record(Reader& reader) {
    PromotionRecord value;
    auto transition = reader.identity<TransitionIdTag>();
    if (!transition) {
        return transition.status();
    }
    value.transition = transition.value();
    auto artifact = reader.identity<ArtifactIdTag>();
    if (!artifact) {
        return artifact.status();
    }
    value.artifact = artifact.value();
    auto revision = reader.identity<ArtifactRevisionTag>();
    if (!revision) {
        return revision.status();
    }
    value.artifact_revision = revision.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    value.artifact_digest = digest.value();
    auto from = read_stage(reader);
    if (!from) {
        return from.status();
    }
    value.from = from.value();
    auto to = read_stage(reader);
    if (!to) {
        return to.status();
    }
    value.to = to.value();
    auto decision = reader.identity<PromotionDecisionIdTag>();
    if (!decision) {
        return decision.status();
    }
    value.decision = decision.value();
    auto plan = reader.identity<PromotionPlanIdTag>();
    if (!plan) {
        return plan.status();
    }
    value.plan = plan.value();
    auto request = reader.identity<PromotionRequestIdTag>();
    if (!request) {
        return request.status();
    }
    value.request = request.value();
    auto attempt = reader.identity<PromotionAttemptIdTag>();
    if (!attempt) {
        return attempt.status();
    }
    value.attempt = attempt.value();
    auto policy = reader.identity<PromotionPolicyIdTag>();
    if (!policy) {
        return policy.status();
    }
    value.policy = policy.value();
    auto policy_generation = reader.counter<PolicyGenerationTag>();
    if (!policy_generation) {
        return policy_generation.status();
    }
    value.policy_generation = policy_generation.value();
    auto authority = read_authority(reader);
    if (!authority) {
        return authority.status();
    }
    value.authority = authority.value();
    auto snapshot = reader.digest();
    if (!snapshot) {
        return snapshot.status();
    }
    value.evidence_snapshot_digest = snapshot.value();
    auto sequence = reader.counter<CommitSequenceTag>();
    if (!sequence) {
        return sequence.status();
    }
    value.sequence = sequence.value();
    auto committed = reader.u64();
    if (!committed) {
        return committed.status();
    }
    value.committed_unix_millis = committed.value();
    auto note = reader.text(kMaxTextLength);
    if (!note) {
        return note.status();
    }
    value.note = note.value();
    return value;
}

void write_idempotency(Writer& writer, const IdempotencyRecord& value) {
    writer.identity(value.request);
    writer.identity(value.attempt);
    writer.identity(value.decision);
    writer.u8(static_cast<std::uint8_t>(value.outcome));
    writer.identity(value.plan);
    writer.digest(value.request_digest);
    writer.counter(value.created_sequence);
}

Result<IdempotencyRecord> read_idempotency(Reader& reader) {
    IdempotencyRecord value;
    auto request = reader.identity<PromotionRequestIdTag>();
    if (!request) {
        return request.status();
    }
    value.request = request.value();
    auto attempt = reader.identity<PromotionAttemptIdTag>();
    if (!attempt) {
        return attempt.status();
    }
    value.attempt = attempt.value();
    auto decision = reader.identity<PromotionDecisionIdTag>();
    if (!decision) {
        return decision.status();
    }
    value.decision = decision.value();
    auto outcome = read_outcome(reader);
    if (!outcome) {
        return outcome.status();
    }
    value.outcome = outcome.value();
    auto plan = reader.identity<PromotionPlanIdTag>();
    if (!plan) {
        return plan.status();
    }
    value.plan = plan.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    value.request_digest = digest.value();
    auto created = reader.counter<CommitSequenceTag>();
    if (!created) {
        return created.status();
    }
    value.created_sequence = created.value();
    return value;
}

void write_history_event(Writer& writer, const HistoryEvent& value) {
    writer.counter(value.sequence);
    writer.u8(static_cast<std::uint8_t>(value.kind));
    writer.identity(value.artifact);
    writer.identity(value.artifact_revision);
    writer.identity(value.evidence);
    writer.identity(value.decision);
    writer.u8(static_cast<std::uint8_t>(value.outcome));
    writer.u8(static_cast<std::uint8_t>(value.from));
    writer.u8(static_cast<std::uint8_t>(value.to));
    write_authority(writer, value.authority);
    writer.text(value.note, kMaxTextLength);
}

Result<HistoryEvent> read_history_event(Reader& reader) {
    HistoryEvent value;
    auto sequence = reader.counter<CommitSequenceTag>();
    if (!sequence) {
        return sequence.status();
    }
    value.sequence = sequence.value();
    auto kind = read_history_kind(reader);
    if (!kind) {
        return kind.status();
    }
    value.kind = kind.value();
    auto artifact = reader.identity<ArtifactIdTag>();
    if (!artifact) {
        return artifact.status();
    }
    value.artifact = artifact.value();
    auto revision = reader.identity<ArtifactRevisionTag>();
    if (!revision) {
        return revision.status();
    }
    value.artifact_revision = revision.value();
    auto evidence = reader.identity<EvidenceIdTag>();
    if (!evidence) {
        return evidence.status();
    }
    value.evidence = evidence.value();
    auto decision = reader.identity<PromotionDecisionIdTag>();
    if (!decision) {
        return decision.status();
    }
    value.decision = decision.value();
    auto outcome = reader.u8();
    if (!outcome) {
        return outcome.status();
    }
    if (outcome.value() != 0 && !is_valid_promotion_outcome(outcome.value())) {
        return Status(ErrorCode::InvalidEnum, "encoded history outcome is not a known outcome");
    }
    value.outcome = static_cast<PromotionOutcome>(outcome.value());
    auto from = read_optional_stage(reader);
    if (!from) {
        return from.status();
    }
    value.from = from.value();
    auto to = read_optional_stage(reader);
    if (!to) {
        return to.status();
    }
    value.to = to.value();
    auto authority = read_authority(reader);
    if (!authority) {
        return authority.status();
    }
    value.authority = authority.value();
    auto note = reader.text(kMaxTextLength);
    if (!note) {
        return note.status();
    }
    value.note = note.value();
    return value;
}

void write_veto(Writer& writer, const VetoState& value) {
    writer.boolean(value.security_veto);
    writer.text(value.security_reason, kMaxTextLength);
    writer.boolean(value.dependency_veto);
    writer.text(value.dependency_reason, kMaxTextLength);
}

Result<VetoState> read_veto(Reader& reader) {
    VetoState value;
    auto security = reader.boolean();
    if (!security) {
        return security.status();
    }
    value.security_veto = security.value();
    auto security_reason = reader.text(kMaxTextLength);
    if (!security_reason) {
        return security_reason.status();
    }
    value.security_reason = security_reason.value();
    auto dependency = reader.boolean();
    if (!dependency) {
        return dependency.status();
    }
    value.dependency_veto = dependency.value();
    auto dependency_reason = reader.text(kMaxTextLength);
    if (!dependency_reason) {
        return dependency_reason.status();
    }
    value.dependency_reason = dependency_reason.value();
    return value;
}

}  // namespace artifact_promotion::wire
