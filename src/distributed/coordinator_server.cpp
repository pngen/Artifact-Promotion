// Artifact Promotion - authoritative coordinator over framed TCP.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/coordinator_server.hpp"

#include <set>
#include <utility>

#include "artifact_promotion/io.hpp"

namespace artifact_promotion {
namespace {

void fill_response_header(const protocol::Frame& request, protocol::Frame& response,
                          const CoordinatorAuthority& authority) {
    response.correlation = request.request;
    response.coordinator = authority.coordinator;
    response.epoch = authority.epoch;
    response.worker = request.worker;
    response.boot = request.boot;
}

Status error_response(const protocol::Frame& request, protocol::Frame& response, const CoordinatorAuthority& authority,
                      ErrorCode code, std::string_view message) {
    fill_response_header(request, response, authority);
    response.type = protocol::MessageType::Error;
    return protocol::encode_status(code, message, response.payload);
}

}  // namespace

CoordinatorServer::CoordinatorServer(Options options) : options_(std::move(options)), engine_(options_.engine) {
    if (options_.state_path.empty()) {
        return;
    }
    // The listener is installed before start() so every committed mutation is
    // written before success is acknowledged to any client.
    engine_.set_change_listener([this] { (void)persist_now(); });
}

CoordinatorServer::~CoordinatorServer() { stop(); }

Status CoordinatorServer::persist_now() {
    if (options_.state_path.empty()) {
        return Status(ErrorCode::InvalidArgument, "no state path is configured for this coordinator");
    }
    std::lock_guard<std::mutex> lock(persist_mutex_);
    const CoordinatorState snapshot = engine_.snapshot();
    return StatePersistence::save(options_.state_path, snapshot);
}

Status CoordinatorServer::start() {
    if (running_.load()) {
        return Status(ErrorCode::Conflict, "the coordinator is already running");
    }
    const Status init = net::initialize_networking();
    if (init.failed()) {
        return init;
    }

    if (!options_.state_path.empty() && file_exists(options_.state_path)) {
        auto loaded = StatePersistence::load(options_.state_path);
        if (!loaded) {
            // A state file that cannot be validated is rejected outright. The
            // coordinator never silently restarts from an empty state.
            return detached_status(loaded.status());
        }
        CoordinatorState state = loaded.value();
        // The restarted coordinator is a new incarnation: it advances its epoch
        // so that every plan issued by the previous process is fenced.
        state.epoch = state.epoch.next();
        const Status installed = engine_.install_state(state);
        if (installed.failed()) {
            return installed;
        }
        // Reservations held by the previous process are released
        // conservatively; nothing is promoted by recovery.
        engine_.recover_in_flight();
    }

    Status status = listener_.bind_loopback(options_.port);
    if (status.failed()) {
        return status;
    }
    status = listener_.listen(options_.backlog);
    if (status.failed()) {
        return status;
    }

    running_.store(true);
    stopping_.store(false);
    accept_thread_ = std::thread([this] { accept_loop(); });
    return Status::success();
}

void CoordinatorServer::stop() {
    if (!running_.load()) {
        return;
    }
    stopping_.store(true);
    engine_.close_admission();
    // Unblock accept() by connecting once to our own listener.
    if (listener_.valid()) {
        (void)net::connect_loopback(listener_.bound_port(), 1, 0);
    }
    listener_.shutdown();
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (std::thread& thread : connection_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        connection_threads_.clear();
    }
    listener_.close();
    running_.store(false);
    if (!options_.state_path.empty()) {
        // Only state that actually crossed a durable boundary is written.
        (void)persist_now();
    }
}

void CoordinatorServer::accept_loop() {
    while (!stopping_.load()) {
        auto accepted = listener_.accept_one();
        if (!accepted) {
            if (stopping_.load()) {
                break;
            }
            continue;
        }
        net::Socket socket = std::move(accepted.value());
        if (stopping_.load()) {
            socket.close();
            break;
        }
        active_connections_.fetch_add(1);
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connection_threads_.emplace_back([this, connection = std::move(socket)]() mutable {
            serve_connection(std::move(connection));
        });
    }
}

Status CoordinatorServer::register_worker_boot(WorkerId worker, WorkerBootId boot) {
    if (worker.invalid() || boot.invalid()) {
        return Status(ErrorCode::InvalidIdentity, "worker identity and boot identity must both be present");
    }
    std::lock_guard<std::mutex> lock(workers_mutex_);
    const auto existing = worker_boots_.find(worker);
    if (existing != worker_boots_.end()) {
        if (boot == existing->second) {
            return Status::success();
        }
        // Boot identities are allocated by a monotonic generator, so an older
        // boot identity names a stale incarnation. It is fenced here and can
        // never regain authority by reconnecting.
        if (boot < existing->second) {
            return Status(ErrorCode::StaleWorkerBoot,
                          "this worker boot identity is older than the incarnation already registered");
        }
    }
    worker_boots_[worker] = boot;
    return Status::success();
}

void CoordinatorServer::serve_connection(net::Socket socket) {
    (void)socket.set_nodelay(true);
    (void)socket.set_receive_timeout_millis(options_.connection_receive_timeout_millis);

    // Per-connection duplicate suppression. Promotion is idempotent by request
    // identity, and a repeated frame is additionally rejected before it reaches
    // the engine, so a replayed frame can never be read as new work.
    std::set<PromotionRequestId> seen_requests;
    bool handshake_completed = false;

    while (!stopping_.load()) {
        ByteBuffer header(protocol::kFrameHeaderSize);
        Status status = socket.receive_exactly(header.data(), header.size());
        if (status.failed()) {
            break;
        }
        // The declared payload length lives at a fixed header offset, so it is
        // read from the bounded prefix before the remainder is requested.
        const std::uint32_t declared = load_u32(header.data() + 12);
        if (declared > kMaxFrameBytes) {
            protocol_rejections_.fetch_add(1);
            break;
        }
        ByteBuffer full(protocol::kFrameHeaderSize + declared + protocol::kFrameFooterSize);
        for (std::size_t i = 0; i < header.size(); ++i) {
            full[i] = header[i];
        }
        status = socket.receive_exactly(full.data() + header.size(), full.size() - header.size());
        if (status.failed()) {
            protocol_rejections_.fetch_add(1);
            break;
        }

        auto decoded = protocol::decode_frame(full);
        if (!decoded) {
            protocol_rejections_.fetch_add(1);
            const CoordinatorAuthority authority = engine_.authority();
            protocol::Frame response;
            protocol::Frame placeholder;
            placeholder.request = PromotionRequestId::from_parts(1, 1);
            (void)error_response(placeholder, response, authority, decoded.status().code(),
                                 decoded.status().message().view());
            response.correlation = decoded.status().code() == ErrorCode::Ok ? PromotionRequestId{} : placeholder.request;
            auto encoded = protocol::encode_frame(response);
            if (encoded) {
                (void)socket.send_all(encoded.value());
            }
            break;
        }

        const protocol::Frame request = std::move(decoded.value());
        if (request.type == protocol::MessageType::Goodbye) {
            break;
        }

        protocol::Frame response;
        if (!seen_requests.insert(request.request).second) {
            duplicate_request_rejections_.fetch_add(1);
            const CoordinatorAuthority authority = engine_.authority();
            (void)error_response(request, response, authority, ErrorCode::DuplicateRequest,
                                 "this request identity was already received on this connection");
        } else if (!handshake_completed && request.type != protocol::MessageType::HelloRequest) {
            // No request is served before the coordinator has accepted a boot
            // identity for this connection.
            const CoordinatorAuthority authority = engine_.authority();
            (void)error_response(request, response, authority, ErrorCode::StaleWorkerBoot,
                                 "no handshake has been completed on this connection");
        } else {
            const Status handled = handle_frame(request, response);
            if (handled.failed()) {
                const CoordinatorAuthority authority = engine_.authority();
                (void)error_response(request, response, authority, handled.code(), handled.message().view());
            }
            const CoordinatorAuthority authority = engine_.authority();
            response.correlation = request.request;
            response.coordinator = authority.coordinator;
            response.epoch = authority.epoch;
            response.worker = request.worker;
            response.boot = request.boot;
            if (request.type == protocol::MessageType::HelloRequest &&
                response.type == protocol::MessageType::HelloResponse) {
                handshake_completed = true;
            }
        }

        auto encoded = protocol::encode_frame(response);
        if (!encoded) {
            break;
        }
        status = socket.send_all(encoded.value());
        if (status.failed()) {
            break;
        }
    }

    socket.close();
    active_connections_.fetch_sub(1);
}

Status CoordinatorServer::handle_frame(const protocol::Frame& request, protocol::Frame& response) {
    const CoordinatorAuthority authority = engine_.authority();
    response.type = protocol::MessageType::Invalid;
    response.request = request.request;

    const auto require_current_authority = [&]() -> Status {
        if (!engine_.admission_open()) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is shutting down");
        }
        if (request.coordinator != authority.coordinator || request.epoch != authority.epoch) {
            stale_authority_rejections_.fetch_add(1);
            return Status(ErrorCode::StaleCoordinatorEpoch,
                          "request carries a stale coordinator identity or epoch");
        }
        return Status::success();
    };

    switch (request.type) {
        case protocol::MessageType::HelloRequest: {
            // The handshake is deliberately accepted under any epoch: its whole
            // purpose is to let a restarted worker learn the current authority.
            const Status boot = register_worker_boot(request.worker, request.boot);
            if (boot.failed()) {
                stale_authority_rejections_.fetch_add(1);
                return boot;
            }
            const CoordinatorState snapshot = engine_.snapshot();
            protocol::HelloPayload payload;
            payload.protocol_version = protocol::kProtocolVersion;
            payload.coordinator = authority.coordinator;
            payload.epoch = authority.epoch;
            payload.max_frame_bytes = static_cast<std::uint64_t>(kMaxFrameBytes);
            payload.pending_promotions = snapshot.pending_size();
            payload.policy_generation = snapshot.active_policy_generation;
            payload.policy_digest = snapshot.active_policy_digest;
            response.type = protocol::MessageType::HelloResponse;
            return protocol::encode_hello(payload, response.payload);
        }
        case protocol::MessageType::RegisterArtifactRequest: {
            Status authority_status = require_current_authority();
            if (authority_status.failed()) {
                return authority_status;
            }
            auto payload = protocol::decode_register_artifact(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            ArtifactRegistration registration;
            registration.id = payload.value().artifact;
            registration.kind = payload.value().kind;
            registration.digest = payload.value().digest;
            registration.size_bytes = payload.value().size_bytes;
            registration.name = payload.value().name;
            registration.producer.worker = request.worker;
            registration.producer.boot = request.boot;
            for (const ProvenanceRef reference : payload.value().provenance) {
                ProvenanceRecord record;
                record.reference = reference;
                record.source = "research-ledger";
                record.subject = "ledger:" + reference.to_string();
                record.resolution = ProvenanceResolution::Resolved;
                registration.provenance.push_back(std::move(record));
            }
            registration.dependencies = payload.value().dependencies;

            auto registered = engine_.register_artifact(registration);
            if (!registered) {
                return detached_status(registered.status());
            }
            protocol::ArtifactResultPayload result;
            result.outcome = PromotionOutcome::PromotionCommitted;
            result.artifact = registered.value();
            result.has_artifact = true;
            response.type = protocol::MessageType::RegisterArtifactResponse;
            return protocol::encode_artifact_result(result, response.payload);
        }
        case protocol::MessageType::SubmitEvidenceRequest: {
            Status authority_status = require_current_authority();
            if (authority_status.failed()) {
                return authority_status;
            }
            auto payload = protocol::decode_evidence_submission(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            EvidenceSubmission submission;
            submission.subject = payload.value().subject;
            submission.subject_digest = payload.value().subject_digest;
            submission.subject_revision = payload.value().subject_revision;
            submission.type = payload.value().type;
            submission.custom_type = payload.value().custom_type;
            submission.producer.worker = request.worker;
            submission.producer.boot = request.boot;
            submission.result = payload.value().result;
            submission.confidence_milli = payload.value().confidence_milli;
            submission.measurement = payload.value().measurement;
            submission.detail = payload.value().detail;
            submission.payload_digest = payload.value().payload_digest;
            submission.provenance = payload.value().provenance;
            submission.produced_unix_millis = payload.value().produced_unix_millis;
            submission.has_validity_window = payload.value().has_validity_window;
            submission.valid_from_unix_millis = payload.value().valid_from_unix_millis;
            submission.valid_until_unix_millis = payload.value().valid_until_unix_millis;
            submission.environment = payload.value().environment;

            auto stored = engine_.submit_evidence(submission);
            if (!stored) {
                return detached_status(stored.status());
            }
            response.type = protocol::MessageType::SubmitEvidenceResponse;
            return protocol::encode_evidence_record(stored.value(), response.payload);
        }
        case protocol::MessageType::PromotionRequest:
        case protocol::MessageType::EvaluateRequest: {
            Status authority_status = require_current_authority();
            if (authority_status.failed()) {
                return authority_status;
            }
            auto payload = protocol::decode_promotion_request(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            // A promotion or evaluation must name a destination stage. The
            // payload shape is shared with the read-only probes, which carry no
            // stage, so the requirement is enforced here rather than at parse
            // time.
            if (!is_valid_stage_value(static_cast<std::uint8_t>(payload.value().requested_stage))) {
                return Status(ErrorCode::InvalidStage, "promotion request names no destination stage",
                              request.request.to_string());
            }
            PromotionRequest promotion;
            promotion.artifact = payload.value().artifact;
            promotion.expected_revision = payload.value().revision;
            promotion.expected_digest = payload.value().digest;
            promotion.requested_stage = payload.value().requested_stage;
            promotion.request = request.request;
            promotion.attempt = PromotionAttemptId::from_parts(request.request.high(), request.request.low());
            promotion.authority = authority;
            promotion.requester.worker = request.worker;
            promotion.requester.boot = request.boot;

            protocol::PromotionResultPayload result;
            if (request.type == protocol::MessageType::EvaluateRequest) {
                auto evaluated = engine_.evaluate(promotion);
                if (!evaluated) {
                    return detached_status(evaluated.status());
                }
                result.outcome = evaluated.value().decision.outcome;
                result.decision = evaluated.value().decision;
                result.has_plan = evaluated.value().has_plan;
                result.plan = evaluated.value().plan;
                response.type = protocol::MessageType::EvaluateResponse;
            } else {
                auto committed = engine_.promote(promotion);
                if (!committed) {
                    return detached_status(committed.status());
                }
                result.outcome = committed.value().outcome;
                result.decision = committed.value().decision;
                result.has_record = committed.value().has_record;
                result.record = committed.value().record;
                if (result.decision.plan.valid()) {
                    auto stored_plan = engine_.inspect_plan(result.decision.plan);
                    if (stored_plan.has_value()) {
                        result.plan = stored_plan.value();
                        result.has_plan = true;
                    }
                }
                response.type = protocol::MessageType::PromotionResponse;
            }
            return protocol::encode_promotion_result(result, response.payload);
        }
        case protocol::MessageType::ArtifactStateRequest: {
            auto payload = protocol::decode_promotion_request(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            auto view = engine_.inspect_artifact(payload.value().artifact);
            if (!view.has_value()) {
                return Status(ErrorCode::ArtifactNotFound, "artifact identity is not registered");
            }
            protocol::ArtifactStatePayload state;
            state.artifact = payload.value().artifact;
            state.record = view.value().artifact;
            state.evidence_count = static_cast<std::uint32_t>(view.value().evidence_count);
            state.promotion_record_count = static_cast<std::uint32_t>(view.value().promotion_record_count);
            state.has_active_reservation = view.value().has_active_reservation;
            response.type = protocol::MessageType::ArtifactStateResponse;
            return protocol::encode_artifact_state(state, response.payload);
        }
        case protocol::MessageType::HistoryRequest: {
            auto payload = protocol::decode_promotion_request(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            protocol::HistoryPayload history;
            history.artifact = payload.value().artifact;
            history.records = engine_.promotion_history(payload.value().artifact);
            response.type = protocol::MessageType::HistoryResponse;
            return protocol::encode_history(history, response.payload);
        }
        case protocol::MessageType::ExplainRequest: {
            auto payload = protocol::decode_promotion_request(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            auto decision = engine_.explain(payload.value().artifact, payload.value().requested_stage);
            if (!decision.has_value()) {
                return Status(ErrorCode::ArtifactNotFound, "artifact identity is not registered");
            }
            protocol::PromotionResultPayload result;
            result.outcome = decision.value().outcome;
            result.decision = decision.value();
            response.type = protocol::MessageType::ExplainResponse;
            return protocol::encode_promotion_result(result, response.payload);
        }
        case protocol::MessageType::QuarantineRequest: {
            Status authority_status = require_current_authority();
            if (authority_status.failed()) {
                return authority_status;
            }
            auto payload = protocol::decode_trust(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            auto outcome = engine_.quarantine(payload.value().artifact, payload.value().reason_class,
                                              payload.value().detail, authority);
            if (!outcome) {
                return detached_status(outcome.status());
            }
            protocol::ArtifactResultPayload result;
            result.outcome = outcome.value().outcome;
            result.artifact = outcome.value().artifact;
            result.has_artifact = outcome.value().artifact.id.valid();
            result.reasons = outcome.value().reasons;
            response.type = protocol::MessageType::QuarantineResponse;
            return protocol::encode_artifact_result(result, response.payload);
        }
        case protocol::MessageType::ReleaseQuarantineRequest: {
            Status authority_status = require_current_authority();
            if (authority_status.failed()) {
                return authority_status;
            }
            auto payload = protocol::decode_trust(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            auto outcome = engine_.release_quarantine(payload.value().artifact, authority);
            if (!outcome) {
                return detached_status(outcome.status());
            }
            protocol::ArtifactResultPayload result;
            result.outcome = outcome.value().outcome;
            result.artifact = outcome.value().artifact;
            result.has_artifact = outcome.value().artifact.id.valid();
            result.reasons = outcome.value().reasons;
            response.type = protocol::MessageType::ReleaseQuarantineResponse;
            return protocol::encode_artifact_result(result, response.payload);
        }
        case protocol::MessageType::RevokeRequest: {
            Status authority_status = require_current_authority();
            if (authority_status.failed()) {
                return authority_status;
            }
            auto payload = protocol::decode_trust(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            auto outcome = engine_.revoke(payload.value().artifact, payload.value().decision,
                                          payload.value().reason_class, payload.value().detail, authority);
            if (!outcome) {
                return detached_status(outcome.status());
            }
            protocol::ArtifactResultPayload result;
            result.outcome = outcome.value().outcome;
            result.artifact = outcome.value().artifact;
            result.has_artifact = outcome.value().artifact.id.valid();
            result.reasons = outcome.value().reasons;
            response.type = protocol::MessageType::RevokeResponse;
            return protocol::encode_artifact_result(result, response.payload);
        }
        case protocol::MessageType::RevokeEvidenceRequest: {
            Status authority_status = require_current_authority();
            if (authority_status.failed()) {
                return authority_status;
            }
            auto payload = protocol::decode_trust(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            auto outcome = engine_.revoke_evidence(payload.value().evidence, payload.value().detail, authority);
            if (!outcome) {
                return detached_status(outcome.status());
            }
            protocol::ArtifactResultPayload result;
            result.outcome = outcome.value().outcome;
            result.reasons = outcome.value().reasons;
            response.type = protocol::MessageType::RevokeEvidenceResponse;
            return protocol::encode_artifact_result(result, response.payload);
        }
        case protocol::MessageType::SupersedeRequest: {
            Status authority_status = require_current_authority();
            if (authority_status.failed()) {
                return authority_status;
            }
            auto payload = protocol::decode_trust(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            auto outcome = engine_.supersede(payload.value().artifact, payload.value().successor,
                                             payload.value().detail, authority);
            if (!outcome) {
                return detached_status(outcome.status());
            }
            protocol::ArtifactResultPayload result;
            result.outcome = outcome.value().outcome;
            result.artifact = outcome.value().artifact;
            result.has_artifact = outcome.value().artifact.id.valid();
            result.reasons = outcome.value().reasons;
            response.type = protocol::MessageType::SupersedeResponse;
            return protocol::encode_artifact_result(result, response.payload);
        }
        case protocol::MessageType::RetireRequest: {
            Status authority_status = require_current_authority();
            if (authority_status.failed()) {
                return authority_status;
            }
            auto payload = protocol::decode_trust(request.payload);
            if (!payload) {
                return detached_status(payload.status());
            }
            auto outcome = engine_.retire(payload.value().artifact, authority);
            if (!outcome) {
                return detached_status(outcome.status());
            }
            protocol::ArtifactResultPayload result;
            result.outcome = outcome.value().outcome;
            result.artifact = outcome.value().artifact;
            result.has_artifact = outcome.value().artifact.id.valid();
            result.reasons = outcome.value().reasons;
            response.type = protocol::MessageType::RetireResponse;
            return protocol::encode_artifact_result(result, response.payload);
        }
        case protocol::MessageType::SnapshotSaveRequest: {
            const Status saved = persist_now();
            if (saved.failed()) {
                return saved;
            }
            protocol::ArtifactResultPayload result;
            result.outcome = PromotionOutcome::PromotionCommitted;
            response.type = protocol::MessageType::SnapshotSaveResponse;
            return protocol::encode_artifact_result(result, response.payload);
        }
        case protocol::MessageType::Invalid:
        case protocol::MessageType::HelloResponse:
        case protocol::MessageType::RegisterArtifactResponse:
        case protocol::MessageType::SubmitEvidenceResponse:
        case protocol::MessageType::PromotionResponse:
        case protocol::MessageType::EvaluateResponse:
        case protocol::MessageType::ArtifactStateResponse:
        case protocol::MessageType::HistoryResponse:
        case protocol::MessageType::QuarantineResponse:
        case protocol::MessageType::ReleaseQuarantineResponse:
        case protocol::MessageType::RevokeResponse:
        case protocol::MessageType::RevokeEvidenceResponse:
        case protocol::MessageType::SupersedeResponse:
        case protocol::MessageType::RetireResponse:
        case protocol::MessageType::SnapshotSaveResponse:
        case protocol::MessageType::ExplainResponse:
        case protocol::MessageType::Error:
        case protocol::MessageType::Goodbye:
            return Status(ErrorCode::ProtocolMalformed, "a response message type was received as a request");
    }
    return Status(ErrorCode::ProtocolMalformed, "unhandled message type");
}

}  // namespace artifact_promotion
