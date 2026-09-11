// Artifact Promotion - evidence producing worker over framed TCP.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/worker_client.hpp"

#include <chrono>
#include <thread>
#include <utility>

namespace artifact_promotion {
namespace {

[[nodiscard]] std::uint64_t entropy() noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto thread_hash = std::hash<std::thread::id>{}(std::this_thread::get_id());
    std::uint64_t mixed = static_cast<std::uint64_t>(now) ^ static_cast<std::uint64_t>(thread_hash);
    mixed ^= 0x9E3779B97F4A7C15ULL;
    mixed ^= mixed >> 30;
    mixed *= 0xBF58476D1CE4E5B9ULL;
    mixed ^= mixed >> 27;
    mixed *= 0x94D049BB133111EBULL;
    mixed ^= mixed >> 31;
    return mixed == 0 ? 1 : mixed;
}

}  // namespace

WorkerClient::WorkerClient(Options options)
    : options_(std::move(options)),
      worker_(options_.worker.valid() ? options_.worker
                                      : WorkerId::from_parts(entropy(), entropy())),
      request_generator_(entropy()),
      attempt_generator_(entropy()) {
    // A fresh boot identity is generated for every client instance, so a
    // restarted worker never resumes its predecessor's incarnation.
    boot_ = WorkerBootId::from_parts(entropy(), entropy());
}

WorkerClient::~WorkerClient() { disconnect(); }

void WorkerClient::disconnect() {
    if (!connected_) {
        return;
    }
    protocol::Frame goodbye;
    goodbye.type = protocol::MessageType::Goodbye;
    goodbye.request = request_generator_.next();
    goodbye.coordinator = coordinator_;
    goodbye.epoch = epoch_;
    goodbye.worker = worker_;
    goodbye.boot = boot_;
    auto encoded = protocol::encode_frame(goodbye);
    if (encoded) {
        (void)socket_.send_all(encoded.value());
    }
    socket_.close();
    connected_ = false;
}

Status WorkerClient::connect() {
    const Status init = net::initialize_networking();
    if (init.failed()) {
        return init;
    }
    if (connected_) {
        return Status::success();
    }
    auto socket = net::connect_loopback(options_.port, options_.connect_attempts, options_.connect_delay_millis);
    if (!socket) {
        return detached_status(socket.status());
    }
    socket_ = std::move(socket.value());
    (void)socket_.set_nodelay(true);
    connected_ = true;
    const Status handshake_status = handshake();
    if (handshake_status.failed()) {
        socket_.close();
        connected_ = false;
        return handshake_status;
    }
    return Status::success();
}

Status WorkerClient::handshake() {
    if (!connected_) {
        return Status(ErrorCode::ConnectionClosed, "the worker is not connected to a coordinator");
    }
    protocol::Frame request;
    request.type = protocol::MessageType::HelloRequest;
    request.request = request_generator_.next();
    request.worker = worker_;
    request.boot = boot_;
    // The handshake deliberately carries no coordinator identity or epoch: it
    // is the exchange through which the client learns the current ones.
    protocol::Frame response;
    const Status exchanged = exchange(request, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::HelloResponse) {
        return Status(ErrorCode::ProtocolError, "the coordinator did not answer the handshake with a hello response");
    }
    auto payload = protocol::decode_hello(response.payload);
    if (!payload) {
        return detached_status(payload.status());
    }
    coordinator_ = payload.value().coordinator;
    epoch_ = payload.value().epoch;
    return Status::success();
}

Status WorkerClient::exchange(const protocol::Frame& request, protocol::Frame& response) {
    auto encoded = protocol::encode_frame(request);
    if (!encoded) {
        return detached_status(encoded.status());
    }
    Status status = socket_.send_all(encoded.value());
    if (status.failed()) {
        connected_ = false;
        return status;
    }
    ++frames_sent_;

    ByteBuffer header(protocol::kFrameHeaderSize);
    status = socket_.receive_exactly(header.data(), header.size());
    if (status.failed()) {
        connected_ = false;
        return status;
    }
    const std::uint32_t declared = load_u32(header.data() + 12);
    if (declared > kMaxFrameBytes) {
        return Status(ErrorCode::ProtocolOversized, "the coordinator declared an oversized response frame");
    }
    ByteBuffer full(protocol::kFrameHeaderSize + declared + protocol::kFrameFooterSize);
    for (std::size_t i = 0; i < header.size(); ++i) {
        full[i] = header[i];
    }
    status = socket_.receive_exactly(full.data() + header.size(), full.size() - header.size());
    if (status.failed()) {
        connected_ = false;
        return status;
    }
    auto decoded = protocol::decode_frame(full);
    if (!decoded) {
        return detached_status(decoded.status());
    }
    response = std::move(decoded.value());
    if (response.correlation != request.request) {
        return Status(ErrorCode::ProtocolError, "the response does not correlate with the request");
    }
    if (response.type == protocol::MessageType::Error) {
        auto reason = protocol::decode_status(response.payload);
        if (!reason) {
            return detached_status(reason.status());
        }
        return Status(reason.value().code, reason.value().text.view(), reason.value().subject);
    }
    // Adopt any newer authority the coordinator reports, so a worker that
    // survives a coordinator restart is never left using a stale epoch.
    if (response.coordinator.valid() && response.coordinator != coordinator_) {
        coordinator_ = response.coordinator;
    }
    if (response.epoch.valid() && (response.epoch > epoch_ || response.epoch != epoch_)) {
        epoch_ = response.epoch;
    }
    return Status::success();
}

PromotionRequestId WorkerClient::next_request_id() { return request_generator_.next(); }

PromotionAttemptId WorkerClient::next_attempt_id() { return attempt_generator_.next(); }

Result<ArtifactRecord> WorkerClient::register_artifact(const ArtifactRegistration& registration) {
    const Status validation = registration.validate();
    if (validation.failed()) {
        return validation;
    }
    protocol::RegisterArtifactPayload payload;
    payload.artifact = registration.id;
    payload.kind = registration.kind;
    payload.digest = registration.digest;
    payload.size_bytes = registration.size_bytes;
    payload.name = registration.name;
    for (const ProvenanceRecord& record : registration.provenance) {
        payload.provenance.push_back(record.reference);
    }
    payload.dependencies = registration.dependencies;

    protocol::Frame request;
    request.type = protocol::MessageType::RegisterArtifactRequest;
    request.request = request_generator_.next();
    request.coordinator = coordinator_;
    request.epoch = epoch_;
    request.worker = worker_;
    request.boot = boot_;
    const Status encoded = protocol::encode_register_artifact(payload, request.payload);
    if (encoded.failed()) {
        return encoded;
    }

    protocol::Frame response;
    const Status exchanged = exchange(request, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::RegisterArtifactResponse) {
        return Status(ErrorCode::ProtocolError, "unexpected response type for an artifact registration");
    }
    auto result = protocol::decode_artifact_result(response.payload);
    if (!result) {
        return detached_status(result.status());
    }
    if (!result.value().has_artifact) {
        return Status(ErrorCode::ArtifactNotFound, "the coordinator did not return an artifact record");
    }
    return result.value().artifact;
}

Result<EvidenceRecord> WorkerClient::submit_evidence(const EvidenceSubmission& submission) {
    const Status validation = submission.validate();
    if (validation.failed()) {
        return validation;
    }
    protocol::EvidencePayload payload;
    payload.type = submission.type;
    payload.custom_type = submission.custom_type;
    payload.subject = submission.subject;
    payload.subject_digest = submission.subject_digest;
    payload.subject_revision = submission.subject_revision;
    payload.result = submission.result;
    payload.confidence_milli = submission.confidence_milli;
    payload.measurement = submission.measurement;
    payload.detail = submission.detail;
    payload.payload_digest = submission.payload_digest;
    payload.provenance = submission.provenance;
    payload.produced_unix_millis = submission.produced_unix_millis;
    payload.has_validity_window = submission.has_validity_window;
    payload.valid_from_unix_millis = submission.valid_from_unix_millis;
    payload.valid_until_unix_millis = submission.valid_until_unix_millis;
    payload.environment = submission.environment;

    protocol::Frame request;
    request.type = protocol::MessageType::SubmitEvidenceRequest;
    request.request = request_generator_.next();
    request.coordinator = coordinator_;
    request.epoch = epoch_;
    request.worker = worker_;
    request.boot = boot_;
    const Status encoded = protocol::encode_evidence_submission(payload, request.payload);
    if (encoded.failed()) {
        return encoded;
    }

    protocol::Frame response;
    const Status exchanged = exchange(request, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::SubmitEvidenceResponse) {
        return Status(ErrorCode::ProtocolError, "unexpected response type for an evidence submission");
    }
    return protocol::decode_evidence_record(response.payload);
}

namespace {

protocol::PromotionPayload make_promotion_payload(const PromotionRequest& request) {
    protocol::PromotionPayload payload;
    payload.artifact = request.artifact;
    payload.revision = request.expected_revision;
    payload.digest = request.expected_digest;
    payload.requested_stage = request.requested_stage;
    return payload;
}

}  // namespace

Result<PromotionEngine::EvaluationResult> WorkerClient::evaluate(const PromotionRequest& request) {
    protocol::Frame frame;
    frame.type = protocol::MessageType::EvaluateRequest;
    frame.request = request.request.valid() ? request.request : request_generator_.next();
    frame.coordinator = coordinator_;
    frame.epoch = epoch_;
    frame.worker = worker_;
    frame.boot = boot_;
    frame.flags = protocol::kFlagNone;
    const Status encoded = protocol::encode_promotion_request(make_promotion_payload(request), frame.payload);
    if (encoded.failed()) {
        return encoded;
    }
    protocol::Frame response;
    const Status exchanged = exchange(frame, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::EvaluateResponse) {
        return Status(ErrorCode::ProtocolError, "unexpected response type for an evaluation");
    }
    auto result = protocol::decode_promotion_result(response.payload);
    if (!result) {
        return detached_status(result.status());
    }
    PromotionEngine::EvaluationResult evaluation;
    evaluation.decision = result.value().decision;
    evaluation.plan = result.value().plan;
    evaluation.has_plan = result.value().has_plan;
    return evaluation;
}

Result<PromotionEngine::CommitResult> WorkerClient::promote(const PromotionRequest& request) {
    protocol::Frame frame;
    frame.type = protocol::MessageType::PromotionRequest;
    frame.request = request.request.valid() ? request.request : request_generator_.next();
    frame.coordinator = coordinator_;
    frame.epoch = epoch_;
    frame.worker = worker_;
    frame.boot = boot_;
    // A promotion mutates lifecycle state and is therefore marked as a request
    // whose execution outcome may already be committed: the client never
    // retries it blindly.
    frame.flags = protocol::kFlagNonIdempotent;
    const Status encoded = protocol::encode_promotion_request(make_promotion_payload(request), frame.payload);
    if (encoded.failed()) {
        return encoded;
    }
    protocol::Frame response;
    const Status exchanged = exchange(frame, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::PromotionResponse) {
        return Status(ErrorCode::ProtocolError, "unexpected response type for a promotion");
    }
    auto result = protocol::decode_promotion_result(response.payload);
    if (!result) {
        return detached_status(result.status());
    }
    PromotionEngine::CommitResult committed;
    committed.outcome = result.value().outcome;
    committed.decision = result.value().decision;
    committed.record = result.value().record;
    committed.has_record = result.value().has_record;
    return committed;
}

Result<protocol::ArtifactStatePayload> WorkerClient::artifact_state(ArtifactId artifact) {
    PromotionRequest probe;
    probe.artifact = artifact;
    protocol::Frame frame;
    frame.type = protocol::MessageType::ArtifactStateRequest;
    frame.request = request_generator_.next();
    frame.coordinator = coordinator_;
    frame.epoch = epoch_;
    frame.worker = worker_;
    frame.boot = boot_;
    const Status encoded = protocol::encode_promotion_request(make_promotion_payload(probe), frame.payload);
    if (encoded.failed()) {
        return encoded;
    }
    protocol::Frame response;
    const Status exchanged = exchange(frame, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::ArtifactStateResponse) {
        return Status(ErrorCode::ProtocolError, "unexpected response type for an artifact state query");
    }
    return protocol::decode_artifact_state(response.payload);
}

Result<std::vector<PromotionRecord>> WorkerClient::history(ArtifactId artifact) {
    PromotionRequest probe;
    probe.artifact = artifact;
    protocol::Frame frame;
    frame.type = protocol::MessageType::HistoryRequest;
    frame.request = request_generator_.next();
    frame.coordinator = coordinator_;
    frame.epoch = epoch_;
    frame.worker = worker_;
    frame.boot = boot_;
    const Status encoded = protocol::encode_promotion_request(make_promotion_payload(probe), frame.payload);
    if (encoded.failed()) {
        return encoded;
    }
    protocol::Frame response;
    const Status exchanged = exchange(frame, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::HistoryResponse) {
        return Status(ErrorCode::ProtocolError, "unexpected response type for a history query");
    }
    auto payload = protocol::decode_history(response.payload);
    if (!payload) {
        return detached_status(payload.status());
    }
    return payload.value().records;
}

Result<PromotionEngine::TrustMutation> WorkerClient::quarantine(ArtifactId artifact, std::string reason_class,
                                                               std::string detail) {
    protocol::TrustPayload payload;
    payload.artifact = artifact;
    payload.reason_class = std::move(reason_class);
    payload.detail = std::move(detail);
    protocol::Frame frame;
    frame.type = protocol::MessageType::QuarantineRequest;
    frame.request = request_generator_.next();
    frame.coordinator = coordinator_;
    frame.epoch = epoch_;
    frame.worker = worker_;
    frame.boot = boot_;
    frame.flags = protocol::kFlagNonIdempotent;
    const Status encoded = protocol::encode_trust(payload, frame.payload);
    if (encoded.failed()) {
        return encoded;
    }
    protocol::Frame response;
    const Status exchanged = exchange(frame, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::QuarantineResponse) {
        return Status(ErrorCode::ProtocolError, "unexpected response type for a quarantine request");
    }
    auto result = protocol::decode_artifact_result(response.payload);
    if (!result) {
        return detached_status(result.status());
    }
    PromotionEngine::TrustMutation mutation;
    mutation.outcome = result.value().outcome;
    mutation.artifact = result.value().artifact;
    mutation.reasons = result.value().reasons;
    return mutation;
}

Result<PromotionEngine::TrustMutation> WorkerClient::revoke(ArtifactId artifact, std::string reason_class,
                                                            std::string detail) {
    protocol::TrustPayload payload;
    payload.artifact = artifact;
    payload.reason_class = std::move(reason_class);
    payload.detail = std::move(detail);
    protocol::Frame frame;
    frame.type = protocol::MessageType::RevokeRequest;
    frame.request = request_generator_.next();
    frame.coordinator = coordinator_;
    frame.epoch = epoch_;
    frame.worker = worker_;
    frame.boot = boot_;
    frame.flags = protocol::kFlagNonIdempotent;
    const Status encoded = protocol::encode_trust(payload, frame.payload);
    if (encoded.failed()) {
        return encoded;
    }
    protocol::Frame response;
    const Status exchanged = exchange(frame, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::RevokeResponse) {
        return Status(ErrorCode::ProtocolError, "unexpected response type for a revocation");
    }
    auto result = protocol::decode_artifact_result(response.payload);
    if (!result) {
        return detached_status(result.status());
    }
    PromotionEngine::TrustMutation mutation;
    mutation.outcome = result.value().outcome;
    mutation.artifact = result.value().artifact;
    mutation.reasons = result.value().reasons;
    return mutation;
}

Result<PromotionDecision> WorkerClient::explain(ArtifactId artifact, Stage destination) {
    PromotionRequest probe;
    probe.artifact = artifact;
    probe.requested_stage = destination;
    protocol::Frame frame;
    frame.type = protocol::MessageType::ExplainRequest;
    frame.request = request_generator_.next();
    frame.coordinator = coordinator_;
    frame.epoch = epoch_;
    frame.worker = worker_;
    frame.boot = boot_;
    const Status encoded = protocol::encode_promotion_request(make_promotion_payload(probe), frame.payload);
    if (encoded.failed()) {
        return encoded;
    }
    protocol::Frame response;
    const Status exchanged = exchange(frame, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::ExplainResponse) {
        return Status(ErrorCode::ProtocolError, "unexpected response type for an explanation");
    }
    auto result = protocol::decode_promotion_result(response.payload);
    if (!result) {
        return detached_status(result.status());
    }
    return result.value().decision;
}

Status WorkerClient::request_snapshot_save() {
    protocol::Frame frame;
    frame.type = protocol::MessageType::SnapshotSaveRequest;
    frame.request = request_generator_.next();
    frame.coordinator = coordinator_;
    frame.epoch = epoch_;
    frame.worker = worker_;
    frame.boot = boot_;
    protocol::Frame response;
    const Status exchanged = exchange(frame, response);
    if (exchanged.failed()) {
        return exchanged;
    }
    if (response.type != protocol::MessageType::SnapshotSaveResponse) {
        return Status(ErrorCode::ProtocolError, "unexpected response type for a snapshot save request");
    }
    return Status::success();
}

}  // namespace artifact_promotion
