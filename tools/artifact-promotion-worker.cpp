// Artifact Promotion - evidence producing worker process.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// A process bound evidence producer. It generates a fresh boot identity on
// every run, so a killed and restarted worker is a new incarnation whose
// predecessor's evidence cannot become current again.
//
//   artifact-promotion-worker --port N --artifact HEX32 --name NAME --kind KIND
//                             [--digest HEX64] [--evidence TYPE=RESULT ...]
//                             [--environment TEXT] [--request-promotion STAGE]
//                             [--inspect] [--history] [--explain STAGE]
//                             [--quarantine REASON] [--revoke REASON]
//                             [--submit-only] [--expect-outcome NAME] [--expect-stage NAME]
//
// Exit codes: 0 the expectation held, 1 the expectation was violated,
// 2 a usage or transport error, 3 the coordinator rejected the request.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "artifact_promotion/io.hpp"
#include "artifact_promotion/worker_client.hpp"

namespace {

using namespace artifact_promotion;

struct Options {
    std::uint16_t port = 0;
    std::string artifact{};
    Digest digest{};
    bool has_digest = false;
    std::string name{};
    std::string kind{"EXECUTABLE"};
    std::vector<std::string> evidence{};
    std::string environment{};
    std::string request_promotion{};
    bool inspect = false;
    bool history = false;
    std::string explain{};
    std::string quarantine_reason{};
    std::string revoke_reason{};
    bool submit_only = false;
    std::string expect_outcome{};
    std::string expect_stage{};
    std::string expect_reason{};
    std::uint64_t produced_offset_millis = 0;
    std::string state_dump{};
};

void print_usage() {
    std::printf(
        "usage: artifact-promotion-worker --port N --artifact HEX32 [options]\n"
        "\n"
        "  --port N                 coordinator loopback port (required)\n"
        "  --artifact HEX32         artifact identity (32 lower-case hex characters)\n"
        "  --digest HEX64           explicit artifact content digest\n"
        "  --name NAME              artifact name; defaults to the identity\n"
        "  --kind KIND              artifact class; default EXECUTABLE\n"
        "  --evidence TYPE=RESULT   submit one evidence record; repeatable\n"
        "  --environment TEXT       environment binding for typed evidence\n"
        "  --produced-offset-ms N   age the submitted evidence by N milliseconds\n"
        "  --request-promotion STG  request a governed promotion to STAGE\n"
        "  --inspect                print current artifact state\n"
        "  --history                print the promotion history\n"
        "  --explain STAGE          print the decision for a transition without mutating state\n"
        "  --quarantine REASON      quarantine the artifact\n"
        "  --revoke REASON          revoke the artifact's promotion authority\n"
        "  --submit-only            register and submit evidence, then stop\n"
        "  --expect-outcome NAME    fail unless the observed outcome matches\n"
        "  --expect-stage NAME      fail unless the resulting stage matches\n"
        "  --expect-reason CODE     fail unless the first typed reason code matches\n"
        "  --state-dump FILE        ask the coordinator to persist and record the path\n");
}

[[nodiscard]] bool parse_options(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        const auto next = [&](std::string& target) -> bool {
            if (i + 1 >= argc) {
                return false;
            }
            target = argv[++i];
            return true;
        };
        if (argument == "--help" || argument == "-h") {
            print_usage();
            std::exit(0);
        }
        if (argument == "--inspect") {
            options.inspect = true;
            continue;
        }
        if (argument == "--history") {
            options.history = true;
            continue;
        }
        if (argument == "--submit-only") {
            options.submit_only = true;
            continue;
        }
        std::string value;
        if (argument == "--port") {
            if (!next(value)) {
                return false;
            }
            options.port = static_cast<std::uint16_t>(std::strtoul(value.c_str(), nullptr, 10));
            continue;
        }
        if (argument == "--artifact") {
            if (!next(value)) {
                return false;
            }
            options.artifact = value;
            continue;
        }
        if (argument == "--digest") {
            if (!next(value)) {
                return false;
            }
            auto parsed = Digest::parse(value);
            if (!parsed.has_value()) {
                std::printf("--digest must be 64 lower-case hex characters\n");
                return false;
            }
            options.digest = parsed.value();
            options.has_digest = true;
            continue;
        }
        if (argument == "--name") {
            if (!next(value)) {
                return false;
            }
            options.name = value;
            continue;
        }
        if (argument == "--kind") {
            if (!next(value)) {
                return false;
            }
            options.kind = value;
            continue;
        }
        if (argument == "--evidence") {
            if (!next(value)) {
                return false;
            }
            options.evidence.push_back(value);
            continue;
        }
        if (argument == "--environment") {
            if (!next(value)) {
                return false;
            }
            options.environment = value;
            continue;
        }
        if (argument == "--produced-offset-ms") {
            if (!next(value)) {
                return false;
            }
            options.produced_offset_millis = static_cast<std::uint64_t>(std::strtoull(value.c_str(), nullptr, 10));
            continue;
        }
        if (argument == "--request-promotion") {
            if (!next(value)) {
                return false;
            }
            options.request_promotion = value;
            continue;
        }
        if (argument == "--explain") {
            if (!next(value)) {
                return false;
            }
            options.explain = value;
            continue;
        }
        if (argument == "--quarantine") {
            if (!next(value)) {
                return false;
            }
            options.quarantine_reason = value;
            continue;
        }
        if (argument == "--revoke") {
            if (!next(value)) {
                return false;
            }
            options.revoke_reason = value;
            continue;
        }
        if (argument == "--expect-outcome") {
            if (!next(value)) {
                return false;
            }
            options.expect_outcome = value;
            continue;
        }
        if (argument == "--expect-stage") {
            if (!next(value)) {
                return false;
            }
            options.expect_stage = value;
            continue;
        }
        if (argument == "--expect-reason") {
            if (!next(value)) {
                return false;
            }
            options.expect_reason = value;
            continue;
        }
        if (argument == "--state-dump") {
            if (!next(value)) {
                return false;
            }
            options.state_dump = value;
            continue;
        }
        std::printf("unknown argument: %s\n", argument.c_str());
        return false;
    }
    if (options.port == 0 || options.artifact.empty()) {
        return false;
    }
    return true;
}

[[nodiscard]] std::optional<EvidenceResult> parse_result(const std::string& text) {
    if (text == "PASS") {
        return EvidenceResult::Pass;
    }
    if (text == "FAIL") {
        return EvidenceResult::Fail;
    }
    if (text == "INCONCLUSIVE") {
        return EvidenceResult::Inconclusive;
    }
    if (text == "UNKNOWN") {
        return EvidenceResult::Unknown;
    }
    if (text == "NOT_APPLICABLE") {
        return EvidenceResult::NotApplicable;
    }
    return std::nullopt;
}

int g_exit_code = 0;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::printf("EXPECTATION FAILED %s\n", message.c_str());
        g_exit_code = 1;
    } else {
        std::printf("EXPECTATION HELD %s\n", message.c_str());
    }
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!parse_options(argc, argv, options)) {
        print_usage();
        return 2;
    }

    auto artifact_id = ArtifactId::parse(options.artifact);
    if (!artifact_id.has_value()) {
        std::printf("--artifact must be 32 lower-case hex characters and non-zero\n");
        return 2;
    }
    auto kind = artifact_kind_from_string(options.kind);
    if (!kind.has_value()) {
        std::printf("unknown artifact kind: %s\n", options.kind.c_str());
        return 2;
    }

    WorkerClient::Options client_options;
    client_options.port = options.port;
    WorkerClient client(client_options);
    const Status connected = client.connect();
    if (connected.failed()) {
        std::printf("worker cannot reach the coordinator: %s\n", connected.render().c_str());
        return 2;
    }
    std::printf("HANDSHAKE worker=%s boot=%s coordinator=%s epoch=%s\n", client.worker_id().to_string().c_str(),
                client.boot_id().to_string().c_str(), client.coordinator_id().to_string().c_str(),
                client.epoch().to_string().c_str());

    ArtifactRegistration registration;
    registration.id = artifact_id.value();
    registration.kind = kind.value();
    registration.digest = options.has_digest ? options.digest : Digest::from_string(options.artifact);
    registration.size_bytes = 1024;
    registration.name = options.name.empty() ? options.artifact : options.name;

    // The worker declares provenance as a resolved reference from an adjacent
    // ledger-style source. Artifact Promotion stores the reference; it never
    // becomes the ledger.
    ProvenanceRecord provenance;
    provenance.reference = ProvenanceRef::from_parts(0xA11CE00000000000ULL, 0x0000000000000001ULL);
    provenance.source = "research-ledger";
    provenance.subject = "ledger:worker-declared";
    provenance.resolution = ProvenanceResolution::Resolved;
    registration.provenance.push_back(provenance);

    auto registered = client.register_artifact(registration);
    ArtifactRecord record;
    if (!registered) {
        // Registering the revision this identity already carries is the
        // documented rejection: the content is known. A process that restarts,
        // or that repeats a step whose acknowledgement it never saw, therefore
        // treats that answer as "already registered" and reads the current
        // state, instead of failing a step that has in fact already happened.
        if (registered.status().code() != ErrorCode::AlreadyExists) {
            std::printf("artifact registration rejected: %s\n", registered.status().render().c_str());
            return 3;
        }
        const auto current = client.artifact_state(artifact_id.value());
        if (!current) {
            std::printf("cannot read artifact state after re-registration: %s\n",
                        current.status().render().c_str());
            return 2;
        }
        record = current.value().record;
        std::printf("ALREADY_REGISTERED revision=%s digest=%s stage=%s\n", record.revision.to_string().c_str(),
                    record.digest.to_string().c_str(), to_string(record.stage));
    } else {
        record = registered.value();
    }
    std::printf("REGISTERED revision=%s digest=%s stage=%s\n", record.revision.to_string().c_str(),
                record.digest.to_string().c_str(), to_string(record.stage));

    const std::uint64_t now = PromotionEngine::now_millis();
    const std::uint64_t produced =
        options.produced_offset_millis >= now ? 1 : now - options.produced_offset_millis;

    for (const std::string& specification : options.evidence) {
        const std::size_t separator = specification.find('=');
        if (separator == std::string::npos) {
            std::printf("--evidence expects TYPE=RESULT, got %s\n", specification.c_str());
            return 2;
        }
        const std::string type_text = specification.substr(0, separator);
        const std::string result_text = specification.substr(separator + 1);
        auto type = evidence_type_from_string(type_text);
        auto result = parse_result(result_text);
        if (!type.has_value() || !result.has_value()) {
            std::printf("unknown evidence class or result: %s\n", specification.c_str());
            return 2;
        }
        EvidenceSubmission submission;
        submission.subject = artifact_id.value();
        submission.subject_revision = record.revision;
        submission.subject_digest = record.digest;
        submission.type = type.value();
        submission.result = result.value();
        submission.confidence_milli = 900;
        submission.measurement = "worker-cli";
        submission.detail = "submitted by artifact-promotion-worker";
        submission.payload_digest = Digest::from_string("payload:" + record.digest.to_string());
        submission.produced_unix_millis = produced;
        submission.environment = options.environment;

        auto stored = client.submit_evidence(submission);
        if (!stored) {
            std::printf("evidence rejected class=%s code=%s message=%s\n", type_text.c_str(),
                        to_string(stored.status().code()), stored.status().message().c_str());
            return 3;
        }
        std::printf("EVIDENCE id=%s class=%s result=%s generation=%s\n", stored.value().id.to_string().c_str(),
                    type_text.c_str(), result_text.c_str(), stored.value().generation.to_string().c_str());
    }

    if (!options.state_dump.empty()) {
        const Status saved = client.request_snapshot_save();
        if (saved.failed()) {
            std::printf("snapshot save failed: %s\n", saved.render().c_str());
            return 2;
        }
        std::printf("SNAPSHOT saved\n");
    }

    // --submit-only with no --evidence is the "register, then stop" form used to
    // establish an artifact and then let a later process act on it. It submits
    // nothing by design, so it is a success, not a missing-argument error.
    if (options.submit_only && options.evidence.empty()) {
        std::printf("REGISTERED_ONLY revision=%s digest=%s\n", record.revision.to_string().c_str(),
                    record.digest.to_string().c_str());
    }

    if (options.submit_only) {
        client.disconnect();
        return g_exit_code;
    }

    if (!options.quarantine_reason.empty()) {
        auto outcome = client.quarantine(artifact_id.value(), "operator_action", options.quarantine_reason);
        if (!outcome) {
            std::printf("quarantine rejected: %s\n", outcome.status().render().c_str());
            return 3;
        }
        std::printf("QUARANTINE outcome=%s stage=%s\n", to_string(outcome.value().outcome),
                    to_string(outcome.value().artifact.stage));
    }

    if (!options.revoke_reason.empty()) {
        auto outcome = client.revoke(artifact_id.value(), "security_finding", options.revoke_reason);
        if (!outcome) {
            std::printf("revocation rejected: %s\n", outcome.status().render().c_str());
            return 3;
        }
        std::printf("REVOKE outcome=%s stage=%s\n", to_string(outcome.value().outcome),
                    to_string(outcome.value().artifact.stage));
    }

    PromotionOutcome observed_outcome = PromotionOutcome::Invalid;
    if (!options.request_promotion.empty()) {
        auto destination = stage_from_string(options.request_promotion);
        if (!destination.has_value()) {
            std::printf("unknown stage: %s\n", options.request_promotion.c_str());
            return 2;
        }
        const auto state = client.artifact_state(artifact_id.value());
        if (!state) {
            std::printf("cannot read artifact state: %s\n", state.status().render().c_str());
            return 2;
        }

        // A governed promotion advances one lifecycle edge at a time. Asking for
        // a distant stage therefore walks the chain: each intermediate
        // transition is requested and committed on its own evidence, exactly as
        // an operator working the lifecycle by hand would. The reported outcome
        // is the outcome of the last step actually attempted, so a chain that
        // stalls records where it stalled instead of claiming the destination.
        const std::uint8_t from_value = static_cast<std::uint8_t>(state.value().record.stage);
        const std::uint8_t to_value = static_cast<std::uint8_t>(destination.value());
        std::vector<Stage> chain;
        if (to_value > from_value) {
            for (std::uint8_t raw = static_cast<std::uint8_t>(from_value + 1); raw <= to_value; ++raw) {
                chain.push_back(static_cast<Stage>(raw));
            }
        } else {
            chain.push_back(destination.value());
        }

        for (std::size_t index = 0; index < chain.size(); ++index) {
            const bool is_final = index + 1 == chain.size();
            PromotionRequest request;
            request.artifact = artifact_id.value();
            request.expected_revision = state.value().record.revision;
            request.expected_digest = state.value().record.digest;
            request.requested_stage = chain[index];
            request.request = client.next_request_id();
            request.attempt = client.next_attempt_id();
            request.authority = CoordinatorAuthority{client.coordinator_id(), client.epoch()};

            auto committed = client.promote(request);
            if (!committed) {
                std::printf("promotion rejected at the transport or authority layer: %s\n",
                            committed.status().render().c_str());
                return 3;
            }
            observed_outcome = committed.value().outcome;
            std::printf("PROMOTION %s->%s outcome=%s decision=%s gates=%zu failed_gates=%zu\n",
                        to_string(state.value().record.stage), to_string(chain[index]),
                        to_string(committed.value().outcome), committed.value().decision.id.to_string().c_str(),
                        committed.value().decision.gates.size(), committed.value().decision.failed_gate_count());
            if (is_final || committed.value().outcome != PromotionOutcome::PromotionCommitted) {
                for (const GateExplanation& gate : committed.value().decision.gates) {
                    std::printf("  GATE %s\n", gate.render().c_str());
                }
                for (const Reason& reason : committed.value().decision.reasons) {
                    std::printf("  REASON %s\n", reason.render().c_str());
                }
            }
            if (committed.value().has_record) {
                std::printf("COMMITTED transition=%s sequence=%s\n",
                            committed.value().record.transition.to_string().c_str(),
                            committed.value().record.sequence.to_string().c_str());
            }
            if (!is_final) {
                continue;
            }
            if (!options.expect_outcome.empty()) {
                require(to_string(observed_outcome) == options.expect_outcome,
                        "outcome " + std::string(to_string(observed_outcome)) + " == " + options.expect_outcome);
            }
            if (!options.expect_reason.empty() && !committed.value().decision.reasons.empty()) {
                require(to_string(committed.value().decision.reasons.front().code) == options.expect_reason,
                        "reason " + std::string(to_string(committed.value().decision.reasons.front().code)) +
                            " == " + options.expect_reason);
            }
        }
    }

    if (!options.explain.empty()) {
        auto destination = stage_from_string(options.explain);
        if (!destination.has_value()) {
            std::printf("unknown stage: %s\n", options.explain.c_str());
            return 2;
        }
        auto decision = client.explain(artifact_id.value(), destination.value());
        if (!decision) {
            std::printf("explanation unavailable: %s\n", decision.status().render().c_str());
            return 2;
        }
        std::printf("EXPLAIN %s\n", decision.value().render().c_str());
    }

    if (options.expect_stage.empty() || options.inspect || options.history) {
        const auto state = client.artifact_state(artifact_id.value());
        if (!state) {
            std::printf("cannot read artifact state: %s\n", state.status().render().c_str());
            return 2;
        }
        std::printf("STATE stage=%s promoted=%s quarantined=%s revoked=%s superseded=%s evidence=%u records=%u\n",
                    to_string(state.value().record.stage), state.value().record.promoted ? "true" : "false",
                    state.value().record.quarantine.active ? "true" : "false",
                    state.value().record.revocation.active ? "true" : "false",
                    state.value().record.supersession.active ? "true" : "false", state.value().evidence_count,
                    state.value().promotion_record_count);
        if (!options.expect_stage.empty()) {
            require(to_string(state.value().record.stage) == options.expect_stage,
                    "stage " + std::string(to_string(state.value().record.stage)) + " == " + options.expect_stage);
        }
    }

    if (options.history) {
        auto history = client.history(artifact_id.value());
        if (!history) {
            std::printf("cannot read history: %s\n", history.status().render().c_str());
            return 2;
        }
        std::printf("HISTORY records=%zu\n", history.value().size());
        for (const PromotionRecord& item : history.value()) {
            std::printf("  RECORD sequence=%s %s->%s note=%s\n", item.sequence.to_string().c_str(),
                        to_string(item.from), to_string(item.to), item.note.c_str());
        }
    }

    client.disconnect();
    if (observed_outcome != PromotionOutcome::Invalid) {
        std::printf("DONE outcome=%s frames=%llu\n", to_string(observed_outcome),
                    static_cast<unsigned long long>(client.frames_sent()));
    } else {
        std::printf("DONE frames=%llu\n", static_cast<unsigned long long>(client.frames_sent()));
    }
    return g_exit_code;
}
