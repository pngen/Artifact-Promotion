// Artifact Promotion - bounded framed binary protocol.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/protocol.hpp"

#include "artifact_promotion/detail/codec.hpp"
#include "artifact_promotion/detail/reader.hpp"
#include "artifact_promotion/detail/writer.hpp"

namespace artifact_promotion::protocol {
namespace {

using wire::Reader;
using wire::Writer;

constexpr std::size_t kMaxProvenanceList = 32;
constexpr std::size_t kMaxDependencyList = 32;
constexpr std::size_t kMaxHistoryRecords = 4096;
constexpr std::size_t kMaxText = kMaxTextLength;

}  // namespace

const char* to_string(MessageType type) noexcept {
    switch (type) {
        case MessageType::Invalid:
            return "INVALID";
        case MessageType::HelloRequest:
            return "HELLO_REQUEST";
        case MessageType::HelloResponse:
            return "HELLO_RESPONSE";
        case MessageType::RegisterArtifactRequest:
            return "REGISTER_ARTIFACT_REQUEST";
        case MessageType::RegisterArtifactResponse:
            return "REGISTER_ARTIFACT_RESPONSE";
        case MessageType::SubmitEvidenceRequest:
            return "SUBMIT_EVIDENCE_REQUEST";
        case MessageType::SubmitEvidenceResponse:
            return "SUBMIT_EVIDENCE_RESPONSE";
        case MessageType::PromotionRequest:
            return "PROMOTION_REQUEST";
        case MessageType::PromotionResponse:
            return "PROMOTION_RESPONSE";
        case MessageType::EvaluateRequest:
            return "EVALUATE_REQUEST";
        case MessageType::EvaluateResponse:
            return "EVALUATE_RESPONSE";
        case MessageType::ArtifactStateRequest:
            return "ARTIFACT_STATE_REQUEST";
        case MessageType::ArtifactStateResponse:
            return "ARTIFACT_STATE_RESPONSE";
        case MessageType::HistoryRequest:
            return "HISTORY_REQUEST";
        case MessageType::HistoryResponse:
            return "HISTORY_RESPONSE";
        case MessageType::QuarantineRequest:
            return "QUARANTINE_REQUEST";
        case MessageType::QuarantineResponse:
            return "QUARANTINE_RESPONSE";
        case MessageType::ReleaseQuarantineRequest:
            return "RELEASE_QUARANTINE_REQUEST";
        case MessageType::ReleaseQuarantineResponse:
            return "RELEASE_QUARANTINE_RESPONSE";
        case MessageType::RevokeRequest:
            return "REVOKE_REQUEST";
        case MessageType::RevokeResponse:
            return "REVOKE_RESPONSE";
        case MessageType::RevokeEvidenceRequest:
            return "REVOKE_EVIDENCE_REQUEST";
        case MessageType::RevokeEvidenceResponse:
            return "REVOKE_EVIDENCE_RESPONSE";
        case MessageType::SupersedeRequest:
            return "SUPERSEDE_REQUEST";
        case MessageType::SupersedeResponse:
            return "SUPERSEDE_RESPONSE";
        case MessageType::RetireRequest:
            return "RETIRE_REQUEST";
        case MessageType::RetireResponse:
            return "RETIRE_RESPONSE";
        case MessageType::SnapshotSaveRequest:
            return "SNAPSHOT_SAVE_REQUEST";
        case MessageType::SnapshotSaveResponse:
            return "SNAPSHOT_SAVE_RESPONSE";
        case MessageType::ExplainRequest:
            return "EXPLAIN_REQUEST";
        case MessageType::ExplainResponse:
            return "EXPLAIN_RESPONSE";
        case MessageType::Error:
            return "ERROR";
        case MessageType::Goodbye:
            return "GOODBYE";
    }
    return "INVALID";
}

bool is_valid_message_type(std::uint64_t raw) noexcept {
    switch (static_cast<MessageType>(raw)) {
        case MessageType::Invalid:
            return false;
        case MessageType::HelloRequest:
        case MessageType::HelloResponse:
        case MessageType::RegisterArtifactRequest:
        case MessageType::RegisterArtifactResponse:
        case MessageType::SubmitEvidenceRequest:
        case MessageType::SubmitEvidenceResponse:
        case MessageType::PromotionRequest:
        case MessageType::PromotionResponse:
        case MessageType::EvaluateRequest:
        case MessageType::EvaluateResponse:
        case MessageType::ArtifactStateRequest:
        case MessageType::ArtifactStateResponse:
        case MessageType::HistoryRequest:
        case MessageType::HistoryResponse:
        case MessageType::QuarantineRequest:
        case MessageType::QuarantineResponse:
        case MessageType::ReleaseQuarantineRequest:
        case MessageType::ReleaseQuarantineResponse:
        case MessageType::RevokeRequest:
        case MessageType::RevokeResponse:
        case MessageType::RevokeEvidenceRequest:
        case MessageType::RevokeEvidenceResponse:
        case MessageType::SupersedeRequest:
        case MessageType::SupersedeResponse:
        case MessageType::RetireRequest:
        case MessageType::RetireResponse:
        case MessageType::SnapshotSaveRequest:
        case MessageType::SnapshotSaveResponse:
        case MessageType::ExplainRequest:
        case MessageType::ExplainResponse:
        case MessageType::Error:
        case MessageType::Goodbye:
            return true;
    }
    return false;
}

bool is_request_type(MessageType type) noexcept {
    switch (type) {
        case MessageType::HelloRequest:
        case MessageType::RegisterArtifactRequest:
        case MessageType::SubmitEvidenceRequest:
        case MessageType::PromotionRequest:
        case MessageType::EvaluateRequest:
        case MessageType::ArtifactStateRequest:
        case MessageType::HistoryRequest:
        case MessageType::QuarantineRequest:
        case MessageType::ReleaseQuarantineRequest:
        case MessageType::RevokeRequest:
        case MessageType::RevokeEvidenceRequest:
        case MessageType::SupersedeRequest:
        case MessageType::RetireRequest:
        case MessageType::SnapshotSaveRequest:
        case MessageType::ExplainRequest:
            return true;
        default:
            return false;
    }
}

Result<ByteBuffer> encode_frame(const Frame& frame) {
    if (!is_valid_message_type(static_cast<std::uint64_t>(frame.type))) {
        return Status(ErrorCode::ProtocolMalformed, "frame carries an unknown message type");
    }
    // A flag bit this protocol does not define is refused on the way out as well
    // as on the way in. An encoder that silently emits bits the peer will reject
    // turns a local mistake into a remote one.
    if ((frame.flags & ~kFlagNonIdempotent) != 0) {
        return Status(ErrorCode::ProtocolMalformed, "frame carries unknown flag bits");
    }
    if (frame.payload.size() > kMaxFrameBytes) {
        return Status(ErrorCode::ProtocolOversized, "frame payload exceeds the configured bound");
    }
    if (frame.request.invalid() && frame.correlation.invalid()) {
        return Status(ErrorCode::ProtocolMalformed, "frame carries neither a request nor a correlation identity");
    }

    Writer writer(frame.payload.size() + kFrameHeaderSize + kFrameFooterSize);
    writer.u32(kFrameMagic);
    writer.u16(frame.version);
    writer.u16(static_cast<std::uint16_t>(frame.type));
    writer.u32(frame.flags);
    writer.u32(static_cast<std::uint32_t>(frame.payload.size()));
    writer.identity(frame.request);
    writer.identity(frame.correlation);
    writer.identity(frame.coordinator);
    writer.counter(frame.epoch);
    writer.identity(frame.worker);
    writer.identity(frame.boot);
    writer.raw(frame.payload.data(), frame.payload.size());
    if (writer.size() != kFrameHeaderSize + frame.payload.size()) {
        return Status(ErrorCode::InternalError, "frame header size does not match the declared layout");
    }
    const Digest footer = sha256(writer.buffer());
    writer.digest(footer);
    return std::move(writer).take();
}

Result<Frame> decode_frame(const ByteBuffer& bytes) {
    if (bytes.size() < kFrameHeaderSize + kFrameFooterSize) {
        return Status(ErrorCode::ProtocolTruncated, "frame is shorter than the minimum frame size");
    }
    Reader reader(bytes);
    auto magic = reader.u32();
    if (!magic) {
        return magic.status();
    }
    if (magic.value() != kFrameMagic) {
        return Status(ErrorCode::ProtocolMalformed, "frame does not begin with the expected magic");
    }
    Frame frame;
    auto version = reader.u16();
    if (!version) {
        return version.status();
    }
    if (version.value() != kProtocolVersion) {
        return Status(ErrorCode::ProtocolError,
                      "frame protocol version " + std::to_string(version.value()) + " is not supported");
    }
    frame.version = version.value();
    auto type = reader.u16();
    if (!type) {
        return type.status();
    }
    if (!is_valid_message_type(type.value())) {
        return Status(ErrorCode::ProtocolMalformed, "frame carries an unknown message type");
    }
    frame.type = static_cast<MessageType>(type.value());
    auto flags = reader.u32();
    if (!flags) {
        return flags.status();
    }
    if ((flags.value() & ~kFlagNonIdempotent) != 0) {
        return Status(ErrorCode::ProtocolMalformed, "frame carries unknown flag bits");
    }
    frame.flags = flags.value();
    auto length = reader.u32();
    if (!length) {
        return length.status();
    }
    if (length.value() > kMaxFrameBytes) {
        return Status(ErrorCode::ProtocolOversized, "declared frame payload exceeds the configured bound");
    }
    const std::size_t expected = kFrameHeaderSize + static_cast<std::size_t>(length.value()) + kFrameFooterSize;
    if (expected != bytes.size()) {
        return Status(ErrorCode::ProtocolMalformed,
                      "declared frame length does not match the received byte count");
    }

    auto request = reader.identity<PromotionRequestIdTag>();
    if (!request) {
        return request.status();
    }
    frame.request = request.value();
    auto correlation = reader.identity<PromotionRequestIdTag>();
    if (!correlation) {
        return correlation.status();
    }
    frame.correlation = correlation.value();
    if (frame.request.invalid() && frame.correlation.invalid()) {
        return Status(ErrorCode::ProtocolMalformed, "frame carries neither a request nor a correlation identity");
    }
    auto coordinator = reader.identity<CoordinatorIdTag>();
    if (!coordinator) {
        return coordinator.status();
    }
    frame.coordinator = coordinator.value();
    auto epoch = reader.counter<CoordinatorEpochTag>();
    if (!epoch) {
        return epoch.status();
    }
    frame.epoch = epoch.value();
    auto worker = reader.identity<WorkerIdTag>();
    if (!worker) {
        return worker.status();
    }
    frame.worker = worker.value();
    auto boot = reader.identity<WorkerBootIdTag>();
    if (!boot) {
        return boot.status();
    }
    frame.boot = boot.value();

    const Digest stored_footer = Digest::from_raw(bytes.data() + bytes.size() - kFrameFooterSize);
    const Digest computed_footer = sha256(bytes.data(), bytes.size() - kFrameFooterSize);
    if (!(stored_footer == computed_footer)) {
        return Status(ErrorCode::ProtocolMalformed, "frame footer digest does not match the frame content");
    }

    Status status = reader.raw(static_cast<std::size_t>(length.value()), frame.payload);
    if (status.failed()) {
        return status;
    }
    // The footer is part of the frame, so the reader is asked whether the header
    // and payload together are exactly the frame's content, not whether the
    // whole received buffer is exhausted. Requiring a fully consumed buffer here
    // would reject the frame this module itself just encoded.
    const std::size_t consumed = kFrameHeaderSize + static_cast<std::size_t>(length.value());
    if (consumed > bytes.size() || bytes.size() - consumed != kFrameFooterSize) {
        return Status(ErrorCode::ProtocolMalformed, "frame contains trailing bytes after its declared content");
    }
    return frame;
}

Status encode_hello(const HelloPayload& payload, ByteBuffer& out) {
    Writer writer(64);
    writer.u16(payload.protocol_version);
    writer.identity(payload.coordinator);
    writer.counter(payload.epoch);
    writer.u64(payload.max_frame_bytes);
    writer.u64(payload.pending_promotions);
    writer.digest(payload.policy_digest);
    writer.counter(payload.policy_generation);
    out = std::move(writer).take();
    return Status::success();
}

Result<HelloPayload> decode_hello(const ByteBuffer& in) {
    Reader reader(in);
    HelloPayload payload;
    auto version = reader.u16();
    if (!version) {
        return version.status();
    }
    payload.protocol_version = version.value();
    if (payload.protocol_version != kProtocolVersion) {
        return Status(ErrorCode::ProtocolError, "peer speaks an unsupported protocol version");
    }
    auto coordinator = reader.identity<CoordinatorIdTag>();
    if (!coordinator) {
        return coordinator.status();
    }
    payload.coordinator = coordinator.value();
    auto epoch = reader.counter<CoordinatorEpochTag>();
    if (!epoch) {
        return epoch.status();
    }
    payload.epoch = epoch.value();
    auto max_frame = reader.u64();
    if (!max_frame) {
        return max_frame.status();
    }
    payload.max_frame_bytes = max_frame.value();
    auto pending = reader.u64();
    if (!pending) {
        return pending.status();
    }
    payload.pending_promotions = pending.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    payload.policy_digest = digest.value();
    auto generation = reader.counter<PolicyGenerationTag>();
    if (!generation) {
        return generation.status();
    }
    payload.policy_generation = generation.value();
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return payload;
}

Status encode_register_artifact(const RegisterArtifactPayload& payload, ByteBuffer& out) {
    if (payload.name.size() > kMaxNameLength || !is_valid_name(payload.name)) {
        return Status(ErrorCode::InvalidName, "artifact name is empty, too long, or malformed");
    }
    Writer writer(128);
    writer.identity(payload.artifact);
    writer.u8(static_cast<std::uint8_t>(payload.kind));
    writer.digest(payload.digest);
    writer.u64(payload.size_bytes);
    writer.text(payload.name, kMaxNameLength);
    writer.list(payload.provenance.size(), [&](Writer& element, std::size_t index) {
        element.identity(payload.provenance[index]);
    });
    writer.list(payload.dependencies.size(), [&](Writer& element, std::size_t index) {
        element.text(payload.dependencies[index], kMaxNameLength);
    });
    out = std::move(writer).take();
    return Status::success();
}

Result<RegisterArtifactPayload> decode_register_artifact(const ByteBuffer& in) {
    Reader reader(in);
    RegisterArtifactPayload payload;
    auto artifact = reader.identity<ArtifactIdTag>();
    if (!artifact) {
        return artifact.status();
    }
    payload.artifact = artifact.value();
    auto kind = reader.u8();
    if (!kind) {
        return kind.status();
    }
    if (!is_valid_artifact_kind(kind.value())) {
        return Status(ErrorCode::InvalidEnum, "artifact registration carries an unknown artifact class");
    }
    payload.kind = static_cast<ArtifactKind>(kind.value());
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    payload.digest = digest.value();
    auto size = reader.u64();
    if (!size) {
        return size.status();
    }
    payload.size_bytes = size.value();
    auto name = reader.text(kMaxNameLength);
    if (!name) {
        return name.status();
    }
    payload.name = name.value();
    auto provenance_count = reader.count(kMaxProvenanceList);
    if (!provenance_count) {
        return provenance_count.status();
    }
    for (std::size_t i = 0; i < provenance_count.value(); ++i) {
        auto reference = reader.identity<ProvenanceRefTag>();
        if (!reference) {
            return reference.status();
        }
        payload.provenance.push_back(reference.value());
    }
    auto dependency_count = reader.count(kMaxDependencyList);
    if (!dependency_count) {
        return dependency_count.status();
    }
    for (std::size_t i = 0; i < dependency_count.value(); ++i) {
        auto dependency = reader.text(kMaxNameLength);
        if (!dependency) {
            return dependency.status();
        }
        payload.dependencies.push_back(dependency.value());
    }
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return payload;
}

Status encode_evidence_submission(const EvidencePayload& payload, ByteBuffer& out) {
    Writer writer(256);
    writer.u8(static_cast<std::uint8_t>(payload.type));
    writer.text(payload.custom_type, kMaxNameLength);
    writer.identity(payload.subject);
    writer.digest(payload.subject_digest);
    writer.identity(payload.subject_revision);
    writer.u8(static_cast<std::uint8_t>(payload.result));
    writer.u32(payload.confidence_milli);
    writer.text(payload.measurement, kMaxText);
    writer.text(payload.detail, kMaxText);
    writer.digest(payload.payload_digest);
    writer.identity(payload.provenance);
    writer.u64(payload.produced_unix_millis);
    writer.boolean(payload.has_validity_window);
    writer.u64(payload.valid_from_unix_millis);
    writer.u64(payload.valid_until_unix_millis);
    writer.text(payload.environment, kMaxText);
    out = std::move(writer).take();
    return Status::success();
}

Result<EvidencePayload> decode_evidence_submission(const ByteBuffer& in) {
    Reader reader(in);
    EvidencePayload payload;
    auto type = reader.u8();
    if (!type) {
        return type.status();
    }
    if (!is_valid_evidence_type(type.value())) {
        return Status(ErrorCode::InvalidEnum, "evidence submission carries an unknown evidence class");
    }
    payload.type = static_cast<EvidenceType>(type.value());
    auto custom = reader.text(kMaxNameLength);
    if (!custom) {
        return custom.status();
    }
    payload.custom_type = custom.value();
    auto subject = reader.identity<ArtifactIdTag>();
    if (!subject) {
        return subject.status();
    }
    payload.subject = subject.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    payload.subject_digest = digest.value();
    auto revision = reader.identity<ArtifactRevisionTag>();
    if (!revision) {
        return revision.status();
    }
    payload.subject_revision = revision.value();
    auto result = reader.u8();
    if (!result) {
        return result.status();
    }
    if (!is_valid_evidence_result(result.value())) {
        return Status(ErrorCode::InvalidEnum, "evidence submission carries an unknown result class");
    }
    payload.result = static_cast<EvidenceResult>(result.value());
    auto confidence = reader.u32();
    if (!confidence) {
        return confidence.status();
    }
    if (confidence.value() > 1000) {
        return Status(ErrorCode::InvalidArgument, "evidence confidence exceeds the documented range");
    }
    payload.confidence_milli = confidence.value();
    auto measurement = reader.text(kMaxText);
    if (!measurement) {
        return measurement.status();
    }
    payload.measurement = measurement.value();
    auto detail = reader.text(kMaxText);
    if (!detail) {
        return detail.status();
    }
    payload.detail = detail.value();
    auto payload_digest = reader.digest();
    if (!payload_digest) {
        return payload_digest.status();
    }
    payload.payload_digest = payload_digest.value();
    auto provenance = reader.identity<ProvenanceRefTag>();
    if (!provenance) {
        return provenance.status();
    }
    payload.provenance = provenance.value();
    auto produced = reader.u64();
    if (!produced) {
        return produced.status();
    }
    payload.produced_unix_millis = produced.value();
    auto has_window = reader.boolean();
    if (!has_window) {
        return has_window.status();
    }
    payload.has_validity_window = has_window.value();
    auto from_time = reader.u64();
    if (!from_time) {
        return from_time.status();
    }
    payload.valid_from_unix_millis = from_time.value();
    auto until_time = reader.u64();
    if (!until_time) {
        return until_time.status();
    }
    payload.valid_until_unix_millis = until_time.value();
    auto environment = reader.text(kMaxText);
    if (!environment) {
        return environment.status();
    }
    payload.environment = environment.value();
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return payload;
}

Status encode_evidence_record(const EvidenceRecord& payload, ByteBuffer& out) {
    Writer writer(256);
    wire::write_evidence(writer, payload);
    out = std::move(writer).take();
    return Status::success();
}

Result<EvidenceRecord> decode_evidence_record(const ByteBuffer& in) {
    Reader reader(in);
    auto record = wire::read_evidence(reader);
    if (!record) {
        return record.status();
    }
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return record.value();
}

Status encode_promotion_request(const PromotionPayload& payload, ByteBuffer& out) {
    Writer writer(96);
    writer.identity(payload.artifact);
    writer.identity(payload.revision);
    writer.digest(payload.digest);
    writer.u8(static_cast<std::uint8_t>(payload.requested_stage));
    writer.boolean(payload.commit_immediately);
    writer.digest(payload.plan_digest);
    out = std::move(writer).take();
    return Status::success();
}

Result<PromotionPayload> decode_promotion_request(const ByteBuffer& in) {
    Reader reader(in);
    PromotionPayload payload;
    auto artifact = reader.identity<ArtifactIdTag>();
    if (!artifact) {
        return artifact.status();
    }
    payload.artifact = artifact.value();
    auto revision = reader.identity<ArtifactRevisionTag>();
    if (!revision) {
        return revision.status();
    }
    payload.revision = revision.value();
    auto digest = reader.digest();
    if (!digest) {
        return digest.status();
    }
    payload.digest = digest.value();
    auto stage = reader.u8();
    if (!stage) {
        return stage.status();
    }
    // The empty stage is legitimate here. The same payload shape carries state,
    // history, and explain probes, for which no destination stage exists; only a
    // real promotion request must name one, and that is checked where the
    // request is interpreted rather than where it is parsed.
    if (stage.value() > kStageMax) {
        return Status(ErrorCode::InvalidStage, "promotion request carries an unknown lifecycle stage");
    }
    payload.requested_stage = static_cast<Stage>(stage.value());
    auto commit = reader.boolean();
    if (!commit) {
        return commit.status();
    }
    payload.commit_immediately = commit.value();
    auto plan_digest = reader.digest();
    if (!plan_digest) {
        return plan_digest.status();
    }
    payload.plan_digest = plan_digest.value();
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return payload;
}

Status encode_promotion_result(const PromotionResultPayload& payload, ByteBuffer& out) {
    Writer writer(512);
    writer.u8(static_cast<std::uint8_t>(payload.outcome));
    wire::write_decision(writer, payload.decision);
    writer.boolean(payload.has_plan);
    if (payload.has_plan) {
        wire::write_plan(writer, payload.plan);
    }
    writer.boolean(payload.has_record);
    if (payload.has_record) {
        wire::write_promotion_record(writer, payload.record);
    }
    out = std::move(writer).take();
    return Status::success();
}

Result<PromotionResultPayload> decode_promotion_result(const ByteBuffer& in) {
    Reader reader(in);
    PromotionResultPayload payload;
    auto outcome = reader.u8();
    if (!outcome) {
        return outcome.status();
    }
    if (!is_valid_promotion_outcome(outcome.value())) {
        return Status(ErrorCode::InvalidEnum, "promotion response carries an unknown outcome");
    }
    payload.outcome = static_cast<PromotionOutcome>(outcome.value());
    auto decision = wire::read_decision(reader);
    if (!decision) {
        return decision.status();
    }
    payload.decision = decision.value();
    auto has_plan = reader.boolean();
    if (!has_plan) {
        return has_plan.status();
    }
    payload.has_plan = has_plan.value();
    if (payload.has_plan) {
        auto plan = wire::read_plan(reader);
        if (!plan) {
            return plan.status();
        }
        payload.plan = plan.value();
    }
    auto has_record = reader.boolean();
    if (!has_record) {
        return has_record.status();
    }
    payload.has_record = has_record.value();
    if (payload.has_record) {
        auto record = wire::read_promotion_record(reader);
        if (!record) {
            return record.status();
        }
        payload.record = record.value();
    }
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return payload;
}

Status encode_artifact_state(const ArtifactStatePayload& payload, ByteBuffer& out) {
    Writer writer(512);
    writer.identity(payload.artifact);
    wire::write_artifact(writer, payload.record);
    writer.u32(payload.evidence_count);
    writer.u32(payload.promotion_record_count);
    writer.boolean(payload.has_active_reservation);
    out = std::move(writer).take();
    return Status::success();
}

Result<ArtifactStatePayload> decode_artifact_state(const ByteBuffer& in) {
    Reader reader(in);
    ArtifactStatePayload payload;
    auto artifact = reader.identity<ArtifactIdTag>();
    if (!artifact) {
        return artifact.status();
    }
    payload.artifact = artifact.value();
    auto record = wire::read_artifact(reader);
    if (!record) {
        return record.status();
    }
    payload.record = record.value();
    auto evidence_count = reader.u32();
    if (!evidence_count) {
        return evidence_count.status();
    }
    payload.evidence_count = evidence_count.value();
    auto record_count = reader.u32();
    if (!record_count) {
        return record_count.status();
    }
    payload.promotion_record_count = record_count.value();
    auto reservation = reader.boolean();
    if (!reservation) {
        return reservation.status();
    }
    payload.has_active_reservation = reservation.value();
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return payload;
}

Status encode_history(const HistoryPayload& payload, ByteBuffer& out) {
    if (payload.records.size() > kMaxHistoryRecords) {
        return Status(ErrorCode::PayloadTooLarge, "history response exceeds the configured record bound");
    }
    Writer writer(512);
    writer.identity(payload.artifact);
    writer.list(payload.records.size(), [&](Writer& element, std::size_t index) {
        wire::write_promotion_record(element, payload.records[index]);
    });
    out = std::move(writer).take();
    return Status::success();
}

Result<HistoryPayload> decode_history(const ByteBuffer& in) {
    Reader reader(in);
    HistoryPayload payload;
    auto artifact = reader.identity<ArtifactIdTag>();
    if (!artifact) {
        return artifact.status();
    }
    payload.artifact = artifact.value();
    auto count = reader.count(kMaxHistoryRecords);
    if (!count) {
        return count.status();
    }
    for (std::size_t i = 0; i < count.value(); ++i) {
        auto record = wire::read_promotion_record(reader);
        if (!record) {
            return record.status();
        }
        payload.records.push_back(std::move(record.value()));
    }
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return payload;
}

Status encode_trust(const TrustPayload& payload, ByteBuffer& out) {
    Writer writer(128);
    writer.identity(payload.artifact);
    writer.identity(payload.successor);
    writer.identity(payload.decision);
    writer.identity(payload.evidence);
    writer.text(payload.reason_class, kMaxNameLength);
    writer.text(payload.detail, kMaxText);
    out = std::move(writer).take();
    return Status::success();
}

Result<TrustPayload> decode_trust(const ByteBuffer& in) {
    Reader reader(in);
    TrustPayload payload;
    auto artifact = reader.identity<ArtifactIdTag>();
    if (!artifact) {
        return artifact.status();
    }
    payload.artifact = artifact.value();
    auto successor = reader.identity<ArtifactIdTag>();
    if (!successor) {
        return successor.status();
    }
    payload.successor = successor.value();
    auto decision = reader.identity<PromotionDecisionIdTag>();
    if (!decision) {
        return decision.status();
    }
    payload.decision = decision.value();
    auto evidence = reader.identity<EvidenceIdTag>();
    if (!evidence) {
        return evidence.status();
    }
    payload.evidence = evidence.value();
    auto reason = reader.text(kMaxNameLength);
    if (!reason) {
        return reason.status();
    }
    payload.reason_class = reason.value();
    auto detail = reader.text(kMaxText);
    if (!detail) {
        return detail.status();
    }
    payload.detail = detail.value();
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return payload;
}

Status encode_status(ErrorCode code, std::string_view message, ByteBuffer& out) {
    Writer writer(96);
    writer.u16(static_cast<std::uint16_t>(code));
    writer.text(message, kMaxText);
    out = std::move(writer).take();
    return Status::success();
}

Result<Reason> decode_status(const ByteBuffer& in) {
    Reader reader(in);
    auto code = reader.u16();
    if (!code) {
        return code.status();
    }
    if (code.value() > static_cast<std::uint16_t>(ErrorCode::InvariantViolation)) {
        return Status(ErrorCode::ProtocolMalformed, "error payload carries an unknown error code");
    }
    auto message = reader.text(kMaxText);
    if (!message) {
        return message.status();
    }
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return Reason(static_cast<ErrorCode>(code.value()), message.value());
}


Status encode_artifact_result(const ArtifactResultPayload& payload, ByteBuffer& out) {
    Writer writer(256);
    writer.u8(static_cast<std::uint8_t>(payload.outcome));
    writer.boolean(payload.has_artifact);
    if (payload.has_artifact) {
        wire::write_artifact(writer, payload.artifact);
    }
    writer.list(payload.reasons.size(), [&](Writer& element, std::size_t index) {
        const Reason& reason = payload.reasons[index];
        element.u16(static_cast<std::uint16_t>(reason.code));
        element.text(reason.text.view(), kMaxText);
        element.text(reason.subject, kMaxReferenceLength);
    });
    out = std::move(writer).take();
    return Status::success();
}

Result<ArtifactResultPayload> decode_artifact_result(const ByteBuffer& in) {
    Reader reader(in);
    ArtifactResultPayload payload;
    auto outcome = reader.u8();
    if (!outcome) {
        return outcome.status();
    }
    if (!is_valid_promotion_outcome(outcome.value())) {
        return Status(ErrorCode::InvalidEnum, "artifact result carries an unknown outcome");
    }
    payload.outcome = static_cast<PromotionOutcome>(outcome.value());
    auto has_artifact = reader.boolean();
    if (!has_artifact) {
        return has_artifact.status();
    }
    payload.has_artifact = has_artifact.value();
    if (payload.has_artifact) {
        auto record = wire::read_artifact(reader);
        if (!record) {
            return record.status();
        }
        payload.artifact = record.value();
    }
    auto reason_count = reader.count(32);
    if (!reason_count) {
        return reason_count.status();
    }
    for (std::size_t i = 0; i < reason_count.value(); ++i) {
        auto code = reader.u16();
        if (!code) {
            return code.status();
        }
        if (code.value() > static_cast<std::uint16_t>(ErrorCode::InvariantViolation)) {
            return Status(ErrorCode::ProtocolMalformed, "reason carries an unknown error code");
        }
        auto text = reader.text(kMaxText);
        if (!text) {
            return text.status();
        }
        auto subject = reader.text(kMaxReferenceLength);
        if (!subject) {
            return subject.status();
        }
        payload.reasons.emplace_back(static_cast<ErrorCode>(code.value()), text.value(), subject.value());
    }
    const Status status = reader.require_finished();
    if (status.failed()) {
        return status;
    }
    return payload;
}

}  // namespace artifact_promotion::protocol