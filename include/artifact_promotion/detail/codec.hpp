// Artifact Promotion - canonical wire codecs for governed records.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_DETAIL_CODEC_HPP
#define ARTIFACT_PROMOTION_DETAIL_CODEC_HPP

#include "artifact_promotion/artifact.hpp"
#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/decision.hpp"
#include "artifact_promotion/detail/reader.hpp"
#include "artifact_promotion/detail/writer.hpp"
#include "artifact_promotion/evidence.hpp"
#include "artifact_promotion/policy.hpp"
#include "artifact_promotion/stage.hpp"
#include "artifact_promotion/store.hpp"

// Each codec writes exactly the fields that define the value and reads them
// back with every external length, count, enum, and identity validated. A
// decoded domain value is checked with its own validity predicate before it is
// accepted, so a syntactically well formed but semantically impossible record
// is rejected rather than trusted.
namespace artifact_promotion::wire {

// Enum helpers: an unknown on-disk or on-wire enum value is a hard failure.
[[nodiscard]] Result<Stage> read_stage(Reader& reader);
[[nodiscard]] Result<ArtifactKind> read_kind(Reader& reader);
[[nodiscard]] Result<EvidenceType> read_evidence_type(Reader& reader);
[[nodiscard]] Result<EvidenceResult> read_evidence_result(Reader& reader);
[[nodiscard]] Result<ProvenanceResolution> read_provenance_resolution(Reader& reader);
[[nodiscard]] Result<GateKind> read_gate_kind(Reader& reader);
[[nodiscard]] Result<OrderingRule> read_ordering_rule(Reader& reader);
[[nodiscard]] Result<HistoryEventKind> read_history_kind(Reader& reader);
[[nodiscard]] Result<PromotionOutcome> read_outcome(Reader& reader);
[[nodiscard]] Result<GateStatus> read_gate_status(Reader& reader);
[[nodiscard]] Result<ErrorCode> read_error_code(Reader& reader);

void write_producer(Writer& writer, const ProducerIncarnation& value);
[[nodiscard]] Result<ProducerIncarnation> read_producer(Reader& reader);

void write_provenance(Writer& writer, const ProvenanceRecord& value, std::size_t limit);
[[nodiscard]] Result<ProvenanceRecord> read_provenance(Reader& reader, std::size_t limit);

void write_compatibility(Writer& writer, const CompatibilityDescriptor& value);
[[nodiscard]] Result<CompatibilityDescriptor> read_compatibility(Reader& reader);

void write_lifecycle_graph(Writer& writer, const LifecycleGraph& value);
[[nodiscard]] Result<LifecycleGraph> read_lifecycle_graph(Reader& reader);

void write_policy(Writer& writer, const PromotionPolicy& value);
[[nodiscard]] Result<PromotionPolicy> read_policy(Reader& reader);

void write_artifact(Writer& writer, const ArtifactRecord& value);
[[nodiscard]] Result<ArtifactRecord> read_artifact(Reader& reader);

void write_evidence(Writer& writer, const EvidenceRecord& value);
[[nodiscard]] Result<EvidenceRecord> read_evidence(Reader& reader);

void write_plan(Writer& writer, const PromotionPlan& value);
[[nodiscard]] Result<PromotionPlan> read_plan(Reader& reader);

void write_decision(Writer& writer, const PromotionDecision& value);
[[nodiscard]] Result<PromotionDecision> read_decision(Reader& reader);

void write_promotion_record(Writer& writer, const PromotionRecord& value);
[[nodiscard]] Result<PromotionRecord> read_promotion_record(Reader& reader);

void write_idempotency(Writer& writer, const IdempotencyRecord& value);
[[nodiscard]] Result<IdempotencyRecord> read_idempotency(Reader& reader);

void write_history_event(Writer& writer, const HistoryEvent& value);
[[nodiscard]] Result<HistoryEvent> read_history_event(Reader& reader);

void write_veto(Writer& writer, const VetoState& value);
[[nodiscard]] Result<VetoState> read_veto(Reader& reader);

void write_authority(Writer& writer, const CoordinatorAuthority& value);
[[nodiscard]] Result<CoordinatorAuthority> read_authority(Reader& reader);

}  // namespace artifact_promotion::wire

#endif  // ARTIFACT_PROMOTION_DETAIL_CODEC_HPP
