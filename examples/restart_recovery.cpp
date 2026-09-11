// Artifact Promotion example: recovery from a durable snapshot.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// A coordinator commits a promotion and leaves one transition in flight. Its
// state is snapshotted, the engine is destroyed, a new engine installs that
// state under an advanced epoch, and the outcome is checked: the committed
// promotion survives, and the in-flight transition is not promoted because a
// reservation held by a process that no longer exists is not authority.
//
// The durable file form and the installability of a revocation-bearing state
// are exercised and printed as observed results rather than assumed, because
// they decide what a recovery procedure can rely on.
//
// Exit codes: 0 expectations observed, 1 expectation violated, 2 usage error.

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "artifact_promotion/engine.hpp"
#include "artifact_promotion/io.hpp"
#include "artifact_promotion/persistence.hpp"

namespace {

using namespace artifact_promotion;

const char* yes_no(bool value) noexcept { return value ? "true" : "false"; }

PromotionRequest make_request(const ArtifactRecord& artifact, const CoordinatorAuthority& authority,
                              Stage destination, PromotionRequestId request, PromotionAttemptId attempt) {
    PromotionRequest promotion;
    promotion.artifact = artifact.id;
    promotion.expected_revision = artifact.revision;
    promotion.expected_digest = artifact.digest;
    promotion.requested_stage = destination;
    promotion.request = request;
    promotion.attempt = attempt;
    promotion.authority = authority;
    return promotion;
}

Status submit_evidence_set(PromotionEngine& engine, const ArtifactRecord& artifact) {
    EvidenceSubmission base;
    base.subject = artifact.id;
    base.subject_revision = artifact.revision;
    base.subject_digest = artifact.digest;
    base.result = EvidenceResult::Pass;
    base.confidence_milli = 1000;
    base.measurement = "example-harness";
    base.produced_unix_millis = PromotionEngine::now_millis();

    const EvidenceType required[] = {EvidenceType::ProvenanceComplete, EvidenceType::BuildPass,
                                     EvidenceType::UnitTestPass,       EvidenceType::IntegrationTestPass,
                                     EvidenceType::ReproducibilityPass, EvidenceType::MachineCriticApproval,
                                     EvidenceType::SignatureValid};
    for (EvidenceType type : required) {
        EvidenceSubmission submission = base;
        submission.type = type;
        submission.detail = std::string("pass evidence for ") + to_string(type);
        submission.payload_digest =
            Digest::from_string(std::string("payload:") + to_string(type) + artifact.digest.to_string());
        submission.environment = type == EvidenceType::UnitTestPass ? "windows-x64-msvc" : "";
        const Result<EvidenceRecord> stored = engine.submit_evidence(submission);
        if (!stored) {
            return detached_status(stored.status());
        }
    }
    return Status::success();
}

Status drive_to_promoted(PromotionEngine& engine, const ArtifactRecord& artifact,
                         const CoordinatorAuthority& authority,
                         IdentityGenerator<PromotionRequestIdTag>& request_ids,
                         IdentityGenerator<PromotionAttemptIdTag>& attempt_ids) {
    const Status evidence = submit_evidence_set(engine, artifact);
    if (evidence.failed()) {
        return evidence;
    }
    const Stage pipeline[] = {Stage::Verified, Stage::Qualified, Stage::Staged, Stage::Approved, Stage::Promoted};
    for (Stage destination : pipeline) {
        const Result<PromotionEngine::CommitResult> committed =
            engine.promote(make_request(artifact, authority, destination, request_ids.next(), attempt_ids.next()));
        if (!committed) {
            return detached_status(committed.status());
        }
        if (committed.value().outcome != PromotionOutcome::PromotionCommitted) {
            return Status(ErrorCode::PolicyViolation,
                          std::string("transition to ") + to_string(destination) + " did not commit");
        }
    }
    return Status::success();
}

Result<ArtifactRecord> register_artifact(PromotionEngine& engine, ArtifactId id, std::string name,
                                         std::string_view digest_seed, ProvenanceRef reference) {
    ProvenanceRecord provenance;
    provenance.reference = reference;
    provenance.source = "research-ledger";
    provenance.subject = "ledger:" + name;
    provenance.resolution = ProvenanceResolution::Resolved;

    ArtifactRegistration registration;
    registration.id = id;
    registration.kind = ArtifactKind::Executable;
    registration.digest = Digest::from_string(digest_seed);
    registration.size_bytes = 4U * 1024U * 1024U;
    registration.name = std::move(name);
    registration.provenance.push_back(provenance);
    return engine.register_artifact(registration);
}

// The engine's built-in reference lifecycle graph contains CANDIDATE <->
// QUARANTINED, which LifecycleGraph::validate rejects as a cycle. Because
// install_state() re-validates the active policy, a recovered state is only
// installable once an acyclic revision has been published. The transition rules
// are unchanged; only the graph and the generation are.
PromotionPolicy make_installable_generation(const PromotionPolicy& active, PolicyGeneration generation) {
    PromotionPolicy next = active;
    LifecycleGraph graph;
    for (const LifecycleGraph::Edge& edge : next.graph.edges()) {
        if (edge.from == Stage::Quarantined && edge.to == Stage::Candidate) {
            continue;
        }
        (void)graph.add_edge(edge.from, edge.to);
    }
    bool quarantined_present = false;
    for (const LifecycleGraph::Edge& edge : graph.edges()) {
        if (edge.from == Stage::Quarantined || edge.to == Stage::Quarantined) {
            quarantined_present = true;
        }
    }
    if (quarantined_present && !graph.has_edge(Stage::Quarantined, Stage::Revoked) &&
        !graph.has_edge(Stage::Quarantined, Stage::Retired) &&
        !graph.has_edge(Stage::Quarantined, Stage::Superseded)) {
        (void)graph.add_edge(Stage::Quarantined, Stage::Revoked);
    }
    graph.canonicalize();
    next.graph = graph;

    std::vector<PolicyRule> retained;
    for (const PolicyRule& rule : next.rules) {
        if (graph.has_edge(rule.from, rule.to)) {
            retained.push_back(rule);
        }
    }
    next.rules = retained;
    next.generation = generation;
    return next;
}

std::size_t promoted_record_count(const std::vector<PromotionRecord>& records) {
    std::size_t count = 0;
    for (const PromotionRecord& record : records) {
        if (record.to == Stage::Promoted) {
            ++count;
        }
    }
    return count;
}

std::size_t record_count_for(const CoordinatorState& state, ArtifactId id, Stage destination) {
    std::size_t count = 0;
    for (const auto& [transition, record] : state.records) {
        (void)transition;
        if (record.artifact == id && record.to == destination) {
            ++count;
        }
    }
    return count;
}

}  // namespace

int main(int argc, char*[]) {
    if (argc != 1) {
        std::cout << "USAGE restart_recovery takes no arguments\n";
        return 2;
    }

    // The plan time-to-live is widened so the in-flight plan is fenced by the
    // epoch and the lost reservation, not by a clock.
    EngineConfig config = EngineConfig::defaults();
    config.plan_ttl_millis = 3600000ULL;

    const std::string state_path = "artifact_promotion_restart_recovery.apstate";

    IdentityGenerator<ArtifactIdTag> artifact_ids(0x9E81U);
    IdentityGenerator<PromotionRequestIdTag> request_ids(0x9E82U);
    IdentityGenerator<PromotionAttemptIdTag> attempt_ids(0x9E83U);
    IdentityGenerator<ProvenanceRefTag> provenance_refs(0x9E84U);

    PromotionPlan in_flight_plan{};
    PromotionRequest in_flight_request{};
    bool have_in_flight_plan = false;

    std::unique_ptr<PromotionEngine> engine = std::make_unique<PromotionEngine>(config, CoordinatorEpoch(1));
    const CoordinatorAuthority authority = engine->authority();

    const PromotionPolicy built_in = engine->snapshot().policy();
    const Status built_in_graph_status = built_in.graph.validate(built_in.entry_stage);
    if (built_in_graph_status.failed()) {
        const PromotionPolicy repaired = make_installable_generation(built_in, built_in.generation.next());
        const Result<PolicyGeneration> policy_published = engine->publish_policy(repaired);
        if (!policy_published) {
            std::cout << "POLICY published=false status=" << policy_published.status().render() << '\n';
            return 1;
        }
    }
    const CoordinatorState prepared = engine->snapshot();
    std::cout << "POLICY built_in_graph_valid=" << yes_no(built_in_graph_status.ok())
              << " built_in_generation=" << built_in.generation.to_string()
              << " active_generation=" << prepared.active_policy_generation.to_string()
              << " graph_edges=" << std::to_string(prepared.policy().graph.edge_count())
              << " rules=" << std::to_string(prepared.policy().rules.size()) << '\n';

    const Result<ArtifactRecord> alpha_registration =
        register_artifact(*engine, artifact_ids.next(), "alpha", "artifact:alpha:1.0.0", provenance_refs.next());
    const Result<ArtifactRecord> beta_registration =
        register_artifact(*engine, artifact_ids.next(), "beta", "artifact:beta:1.0.0", provenance_refs.next());
    const Result<ArtifactRecord> gamma_registration =
        register_artifact(*engine, artifact_ids.next(), "gamma", "artifact:gamma:1.0.0", provenance_refs.next());
    if (!alpha_registration || !beta_registration || !gamma_registration) {
        std::cout << "ARTIFACT registration_failed=true\n";
        return 1;
    }
    const ArtifactRecord alpha = alpha_registration.value();
    const ArtifactRecord beta = beta_registration.value();
    const ArtifactRecord gamma = gamma_registration.value();
    std::cout << "ARTIFACT count=" << std::to_string(engine->count_artifacts()) << " names=alpha,beta,gamma\n";

    const Status alpha_status = drive_to_promoted(*engine, alpha, authority, request_ids, attempt_ids);
    if (alpha_status.failed()) {
        std::cout << "STAGE drive_failed=true status=" << alpha_status.render() << '\n';
        return 1;
    }

    // gamma has one transition in flight: a plan was issued and a reservation is
    // held, but nothing was committed.
    const Status gamma_evidence = submit_evidence_set(*engine, gamma);
    if (gamma_evidence.failed()) {
        std::cout << "EVIDENCE submit_failed=true status=" << gamma_evidence.render() << '\n';
        return 1;
    }
    in_flight_request = make_request(gamma, authority, Stage::Verified, request_ids.next(), attempt_ids.next());
    const Result<PromotionEngine::EvaluationResult> gamma_evaluated = engine->evaluate(in_flight_request);
    if (!gamma_evaluated) {
        std::cout << "PLAN issued=false status=" << gamma_evaluated.status().render() << '\n';
        return 1;
    }
    in_flight_plan = gamma_evaluated.value().plan;
    have_in_flight_plan = gamma_evaluated.value().has_plan;
    std::cout << "PLAN artifact=gamma issued=" << yes_no(have_in_flight_plan)
              << " from=" << to_string(in_flight_plan.from) << " to=" << to_string(in_flight_plan.to)
              << " committed=false"
              << " reservation=" << yes_no(engine->pending_transition(gamma.id).has_value()) << '\n';
    if (!have_in_flight_plan) {
        std::cout << "PLAN unavailable=true\n";
        return 1;
    }

    const CoordinatorState durable = engine->snapshot();
    const std::size_t live_pending = engine->count_pending_transitions();
    const Result<ByteBuffer> encoded = StatePersistence::encode(durable);
    if (!encoded) {
        std::cout << "SNAPSHOT encoded=false status=" << encoded.status().render() << '\n';
        return 1;
    }
    std::cout << "SNAPSHOT bytes=" << std::to_string(encoded.value().size())
              << " artifacts=" << std::to_string(durable.artifacts.size())
              << " records=" << std::to_string(durable.records.size())
              << " live_reservations=" << std::to_string(live_pending)
              << " snapshot_reservations=" << std::to_string(durable.pending_size())
              << " epoch=" << durable.epoch.to_string() << '\n';

    // Durable file form, reported as observed. Recovery below uses the in-memory
    // snapshot/install_state path.
    const Status saved = StatePersistence::save(state_path, durable);
    const Result<CoordinatorState> reloaded = StatePersistence::load(state_path);
    std::cout << "PERSISTENCE saved=" << yes_no(saved.ok()) << " reloaded=" << yes_no(reloaded.has_value())
              << " status=" << (reloaded ? std::string("OK") : reloaded.status().render()) << '\n';
    const Status removed = remove_file(state_path);
    std::cout << "CLEANUP state_file_removed=" << yes_no(removed.ok()) << " path=" << state_path << '\n';

    // A revocation is committed after the clean snapshot so that the durable
    // form of a revoked artifact can be examined as well.
    const Status beta_status = drive_to_promoted(*engine, beta, authority, request_ids, attempt_ids);
    if (beta_status.failed()) {
        std::cout << "STAGE drive_failed=true status=" << beta_status.render() << '\n';
        return 1;
    }
    const std::optional<PromotionEngine::ArtifactView> beta_view = engine->inspect_artifact(beta.id);
    const PromotionDecisionId beta_decision =
        beta_view.has_value() ? beta_view->artifact.promotion_decision : PromotionDecisionId{};
    const Result<PromotionEngine::TrustMutation> beta_revoked =
        engine->revoke(beta.id, beta_decision, "integrity_mismatch", "revoked before the snapshot was taken",
                       authority);
    if (!beta_revoked) {
        std::cout << "REVOKE applied=false status=" << beta_revoked.status().render() << '\n';
        return 1;
    }
    const CoordinatorState with_revocation = engine->snapshot();
    std::cout << "SNAPSHOT revocation_present="
              << yes_no(record_count_for(with_revocation, beta.id, Stage::Revoked) == 1U)
              << " records=" << std::to_string(with_revocation.records.size()) << '\n';

    engine.reset();
    std::cout << "ENGINE destroyed=true\n";

    std::unique_ptr<PromotionEngine> restored = std::make_unique<PromotionEngine>(config, CoordinatorEpoch(1));
    const Status installed = restored->install_state(durable);
    const Result<CoordinatorEpoch> advanced = restored->restart(CoordinatorEpoch(2));
    if (installed.failed() || !advanced) {
        std::cout << "RECOVERY installed=false status="
                  << (installed.failed() ? installed.render() : advanced.status().render()) << '\n';
        return 1;
    }
    std::cout << "RECOVERY installed=true epoch=" << advanced.value().to_string()
              << " reservations=" << std::to_string(restored->count_pending_transitions()) << '\n';

    // A separate engine installs the revocation-bearing state: observed, not
    // assumed. The revocation is in the snapshot data but the record fails the
    // consistency check that install_state performs.
    {
        PromotionEngine probe(config, CoordinatorEpoch(1));
        const Status probe_installed = probe.install_state(with_revocation);
        std::cout << "RECOVERY case=with_revocation installed=" << yes_no(probe_installed.ok())
                  << " status="
                  << (probe_installed.ok() ? std::string("OK") : probe_installed.render()) << '\n';
    }

    const std::optional<PromotionEngine::ArtifactView> alpha_after = restored->inspect_artifact(alpha.id);
    const std::optional<PromotionEngine::ArtifactView> gamma_after = restored->inspect_artifact(gamma.id);
    const std::vector<PromotionRecord> alpha_records = restored->promotion_history(alpha.id);
    const std::vector<PromotionRecord> gamma_records = restored->promotion_history(gamma.id);

    std::cout << "STATE alpha stage="
              << (alpha_after.has_value() ? to_string(alpha_after->artifact.stage) : std::string("(missing)"))
              << " authoritative="
              << yes_no(alpha_after.has_value() && alpha_after->artifact.currently_authoritative())
              << " promotion_records=" << std::to_string(promoted_record_count(alpha_records)) << '\n';
    std::cout << "STATE gamma stage="
              << (gamma_after.has_value() ? to_string(gamma_after->artifact.stage) : std::string("(missing)"))
              << " promoted=" << yes_no(gamma_after.has_value() && gamma_after->artifact.promoted)
              << " promotion_records=" << std::to_string(gamma_records.size())
              << " reservation=" << yes_no(restored->pending_transition(gamma.id).has_value()) << '\n';

    // Replaying the in-flight request returns the decision that was recorded
    // before the restart: an eligibility answer, not a promotion. Nothing is
    // committed and gamma stays where it was.
    const Result<PromotionEngine::CommitResult> replay = restored->promote(in_flight_request);
    const std::optional<PromotionEngine::ArtifactView> gamma_final = restored->inspect_artifact(gamma.id);
    std::cout << "REPLAY in_flight_request outcome="
              << (replay ? to_string(replay.value().outcome) : replay.status().render())
              << " committed=" << yes_no(replay && replay.value().has_record)
              << " stage_after="
              << (gamma_final.has_value() ? to_string(gamma_final->artifact.stage) : std::string("(missing)"))
              << " promotion_records=" << std::to_string(restored->promotion_history(gamma.id).size()) << '\n';

    const Status invariants = restored->check_invariants();
    std::cout << "INVARIANTS ok=" << yes_no(invariants.ok())
              << " state_file_present=" << yes_no(file_exists(state_path)) << '\n';

    const bool expected =
        !alpha_status.failed() && !beta_status.failed() && beta_revoked.value().artifact.revocation.active &&
        have_in_flight_plan && live_pending == 1U && durable.pending_size() == 0U && saved.ok() &&
        removed.ok() && !file_exists(state_path) && record_count_for(with_revocation, beta.id, Stage::Revoked) == 1U &&
        alpha_after.has_value() && alpha_after->artifact.stage == Stage::Promoted &&
        alpha_after->artifact.currently_authoritative() && promoted_record_count(alpha_records) == 1U &&
        gamma_after.has_value() && gamma_after->artifact.stage == Stage::Candidate &&
        !gamma_after->artifact.promoted && gamma_records.empty() &&
        !restored->pending_transition(gamma.id).has_value() && restored->count_pending_transitions() == 0U &&
        replay.has_value() && !replay.value().has_record && gamma_final.has_value() &&
        gamma_final->artifact.stage == Stage::Candidate && restored->promotion_history(gamma.id).empty() &&
        invariants.ok();
    std::cout << "EXPECTATION " << (expected ? "satisfied" : "violated") << '\n';
    return expected ? 0 : 1;
}
