// Artifact Promotion - bounded framed binary protocol.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_PROTOCOL_HPP
#define ARTIFACT_PROMOTION_PROTOCOL_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "artifact_promotion/artifact.hpp"
#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/decision.hpp"
#include "artifact_promotion/engine.hpp"
#include "artifact_promotion/error.hpp"
#include "artifact_promotion/evidence.hpp"
#include "artifact_promotion/identity.hpp"
#include "artifact_promotion/policy.hpp"
#include "artifact_promotion/sha256.hpp"

namespace artifact_promotion::protocol {

// ---------------------------------------------------------------------------
// Frame
//
//   magic            u32   'APFR'
//   version          u16
//   message type     u16
//   flags            u32
//   payload length   u32
//   request id       16 bytes
//   correlation id   16 bytes
//   coordinator id   16 bytes
//   coordinator epoch u64
//   worker id        16 bytes
//   worker boot id   16 bytes
//   payload          payload length bytes
//   digest           32 bytes  SHA-256 over every preceding frame byte
//
// The header is fixed size, so a reader always knows how much to demand next.
// The declared payload length is validated against the configured maximum
// before any buffer is allocated, and the footer digest is verified before a
// single field is interpreted.
// ---------------------------------------------------------------------------
inline constexpr std::uint32_t kFrameMagic = 0x41504652U;  // 'APFR'
inline constexpr std::uint16_t kProtocolVersion = 1;
inline constexpr std::size_t kFrameHeaderSize = 4 + 2 + 2 + 4 + 4 + 16 + 16 + 16 + 8 + 16 + 16;
inline constexpr std::size_t kFrameFooterSize = kSha256DigestSize;

enum class MessageType : std::uint16_t {
    Invalid = 0,

    HelloRequest = 1,
    HelloResponse = 2,

    RegisterArtifactRequest = 10,
    RegisterArtifactResponse = 11,

    SubmitEvidenceRequest = 20,
    SubmitEvidenceResponse = 21,

    PromotionRequest = 30,
    PromotionResponse = 31,

    EvaluateRequest = 32,
    EvaluateResponse = 33,

    ArtifactStateRequest = 40,
    ArtifactStateResponse = 41,

    HistoryRequest = 50,
    HistoryResponse = 51,

    QuarantineRequest = 60,
    QuarantineResponse = 61,

    ReleaseQuarantineRequest = 62,
    ReleaseQuarantineResponse = 63,

    RevokeRequest = 64,
    RevokeResponse = 65,

    RevokeEvidenceRequest = 66,
    RevokeEvidenceResponse = 67,

    SupersedeRequest = 68,
    SupersedeResponse = 69,

    RetireRequest = 70,
    RetireResponse = 71,

    SnapshotSaveRequest = 80,
    SnapshotSaveResponse = 81,

    ExplainRequest = 90,
    ExplainResponse = 91,

    Error = 100,
    Goodbye = 101,
};

[[nodiscard]] const char* to_string(MessageType type) noexcept;
[[nodiscard]] bool is_valid_message_type(std::uint64_t raw) noexcept;
[[nodiscard]] bool is_request_type(MessageType type) noexcept;

// Frame flags. A request flagged NonIdempotent is never retried automatically
// by a client, because its execution outcome may already be committed.
inline constexpr std::uint32_t kFlagNone = 0;
inline constexpr std::uint32_t kFlagNonIdempotent = 1U;

struct Frame {
    std::uint16_t version = kProtocolVersion;
    MessageType type = MessageType::Invalid;
    std::uint32_t flags = kFlagNone;
    PromotionRequestId request{};
    PromotionRequestId correlation{};
    CoordinatorId coordinator{};
    CoordinatorEpoch epoch{};
    WorkerId worker{};
    WorkerBootId boot{};
    ByteBuffer payload{};
};

// Encodes a frame with a freshly computed footer digest.
[[nodiscard]] Result<ByteBuffer> encode_frame(const Frame& frame);

// Decodes and fully validates a frame. Rejects an unknown message type, a
// payload that exceeds the bound, a digest mismatch, an unsupported version,
// and a frame whose declared length is not exactly the buffer length.
[[nodiscard]] Result<Frame> decode_frame(const ByteBuffer& bytes);

// ---------------------------------------------------------------------------
// Payload codecs. Each returns a Status describing the first violation.
// ---------------------------------------------------------------------------
struct HelloPayload {
    std::uint16_t protocol_version = kProtocolVersion;
    CoordinatorId coordinator{};
    CoordinatorEpoch epoch{};
    std::uint64_t max_frame_bytes = kMaxFrameBytes;
    std::uint64_t pending_promotions = 0;
    Digest policy_digest{};
    PolicyGeneration policy_generation{};
};

[[nodiscard]] Status encode_hello(const HelloPayload& payload, ByteBuffer& out);
[[nodiscard]] Result<HelloPayload> decode_hello(const ByteBuffer& in);

struct RegisterArtifactPayload {
    ArtifactId artifact{};
    ArtifactKind kind = ArtifactKind::Invalid;
    Digest digest{};
    std::uint64_t size_bytes = 0;
    std::string name{};
    std::vector<ProvenanceRef> provenance{};
    std::vector<std::string> dependencies{};
};

[[nodiscard]] Status encode_register_artifact(const RegisterArtifactPayload& payload, ByteBuffer& out);
[[nodiscard]] Result<RegisterArtifactPayload> decode_register_artifact(const ByteBuffer& in);

// Generic result of a mutation that yields an artifact record.
struct ArtifactResultPayload {
    PromotionOutcome outcome = PromotionOutcome::Invalid;
    ArtifactRecord artifact{};
    bool has_artifact = false;
    std::vector<Reason> reasons{};
};

[[nodiscard]] Status encode_artifact_result(const ArtifactResultPayload& payload, ByteBuffer& out);
[[nodiscard]] Result<ArtifactResultPayload> decode_artifact_result(const ByteBuffer& in);

struct EvidencePayload {
    EvidenceId evidence{};
    EvidenceType type = EvidenceType::Invalid;
    std::uint64_t produced_unix_millis = 0;
    std::string custom_type{};
    ArtifactId subject{};
    Digest subject_digest{};
    ArtifactRevision subject_revision{};
    EvidenceResult result = EvidenceResult::Unknown;
    std::uint32_t confidence_milli = 0;
    std::string measurement{};
    std::string detail{};
    Digest payload_digest{};
    ProvenanceRef provenance{};
    bool has_validity_window = false;
    std::uint64_t valid_from_unix_millis = 0;
    std::uint64_t valid_until_unix_millis = 0;
    std::string environment{};
};

[[nodiscard]] Status encode_evidence_submission(const EvidencePayload& payload, ByteBuffer& out);
[[nodiscard]] Result<EvidencePayload> decode_evidence_submission(const ByteBuffer& in);
[[nodiscard]] Status encode_evidence_record(const EvidenceRecord& payload, ByteBuffer& out);
[[nodiscard]] Result<EvidenceRecord> decode_evidence_record(const ByteBuffer& in);

struct PromotionPayload {
    ArtifactId artifact{};
    ArtifactRevision revision{};
    Digest digest{};
    Stage requested_stage = Stage::Invalid;
    bool commit_immediately = false;
    Digest plan_digest{};
};

[[nodiscard]] Status encode_promotion_request(const PromotionPayload& payload, ByteBuffer& out);
[[nodiscard]] Result<PromotionPayload> decode_promotion_request(const ByteBuffer& in);

// A promotion response carries the decision, the plan when one was issued, and
// the committed record when the transition committed.
struct PromotionResultPayload {
    PromotionOutcome outcome = PromotionOutcome::Invalid;
    PromotionDecision decision{};
    PromotionPlan plan{};
    bool has_plan = false;
    PromotionRecord record{};
    bool has_record = false;
};

[[nodiscard]] Status encode_promotion_result(const PromotionResultPayload& payload, ByteBuffer& out);
[[nodiscard]] Result<PromotionResultPayload> decode_promotion_result(const ByteBuffer& in);

struct ArtifactStatePayload {
    ArtifactId artifact{};
    ArtifactRecord record{};
    std::uint32_t evidence_count = 0;
    std::uint32_t promotion_record_count = 0;
    bool has_active_reservation = false;
};

[[nodiscard]] Status encode_artifact_state(const ArtifactStatePayload& payload, ByteBuffer& out);
[[nodiscard]] Result<ArtifactStatePayload> decode_artifact_state(const ByteBuffer& in);

struct HistoryPayload {
    ArtifactId artifact{};
    std::vector<PromotionRecord> records{};
};

[[nodiscard]] Status encode_history(const HistoryPayload& payload, ByteBuffer& out);
[[nodiscard]] Result<HistoryPayload> decode_history(const ByteBuffer& in);

struct TrustPayload {
    ArtifactId artifact{};
    ArtifactId successor{};
    PromotionDecisionId decision{};
    EvidenceId evidence{};
    std::string reason_class{};
    std::string detail{};
};

[[nodiscard]] Status encode_trust(const TrustPayload& payload, ByteBuffer& out);
[[nodiscard]] Result<TrustPayload> decode_trust(const ByteBuffer& in);

// A generic status response carrying only a typed failure.
[[nodiscard]] Status encode_status(ErrorCode code, std::string_view message, ByteBuffer& out);
[[nodiscard]] Result<Reason> decode_status(const ByteBuffer& in);

}  // namespace artifact_promotion::protocol

#endif  // ARTIFACT_PROMOTION_PROTOCOL_HPP
