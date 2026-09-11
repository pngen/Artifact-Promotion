// Artifact Promotion example: a plan does not outlive the policy generation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// An artifact is driven to APPROVED and a promotion plan is issued under policy
// generation N. An incompatible revision is then published as generation N+1,
// and the plan that was issued under N stops being authority: its generation and
// policy digest no longer name the active policy, it still holds the only
// reservation, and the intent has to be re-derived under the generation that is
// actually active before the artifact can advance.
//
// Exit codes: 0 expectations observed, 1 expectation violated, 2 usage error.

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "artifact_promotion/engine.hpp"

namespace {

using namespace artifact_promotion;

const char* yes_no(bool value) noexcept { return value ? "true" : "false"; }

Result<EvidenceRecord> submit_pass(PromotionEngine& engine, const ArtifactRecord& artifact, EvidenceType type,
                                   std::string_view environment) {
    EvidenceSubmission submission;
    submission.subject = artifact.id;
    submission.subject_revision = artifact.revision;
    submission.subject_digest = artifact.digest;
    submission.type = type;
    submission.result = EvidenceResult::Pass;
    submission.confidence_milli = 1000;
    submission.measurement = "example-harness";
    submission.detail = std::string("pass evidence for ") + to_string(type);
    submission.payload_digest =
        Digest::from_string(std::string("payload:") + to_string(type) + artifact.digest.to_string());
    submission.produced_unix_millis = PromotionEngine::now_millis();
    submission.environment = std::string(environment);
    return engine.submit_evidence(submission);
}

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

// Builds an incompatible policy revision from the active policy body: the
// quarantine release path is removed and APPROVED -> PROMOTED gains a new hard
// evidence requirement. The lifecycle graph has to be rebuilt because the
// active revision's graph is not publishable (CANDIDATE <-> QUARANTINED is a
// cycle, which LifecycleGraph::validate rejects).
PromotionPolicy make_incompatible_generation(const PromotionPolicy& active, PolicyGeneration generation,
                                             std::size_t& gates_before, std::size_t& gates_after) {
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

    gates_before = 0;
    gates_after = 0;
    for (PolicyRule& rule : next.rules) {
        if (rule.from != Stage::Approved || rule.to != Stage::Promoted) {
            continue;
        }
        gates_before = rule.requirements.size();
        Gate abi;
        abi.kind = GateKind::EvidenceRequired;
        abi.evidence_type = EvidenceType::AbiCompatibilityPass;
        abi.label = "ABI compatibility evidence required by the new generation";
        rule.requirements.push_back(abi);
        gates_after = rule.requirements.size();
    }
    next.generation = generation;
    return next;
}

PromotionOutcome report(const char* label, const Result<PromotionEngine::CommitResult>& result) {
    if (!result) {
        std::cout << label << " outcome=TRANSPORT_FAILURE status=" << result.status().render() << '\n';
        return PromotionOutcome::Invalid;
    }
    const PromotionEngine::CommitResult& commit = result.value();
    std::cout << label << " outcome=" << to_string(commit.outcome)
              << " committed=" << yes_no(commit.has_record)
              << " failed_gates=" << std::to_string(commit.decision.failed_gate_count()) << '\n';
    for (const GateExplanation& gate : commit.decision.gates) {
        if (gate.status == GateStatus::Failed || gate.status == GateStatus::Unknown) {
            std::cout << "GATE " << to_string(gate.kind) << " status=" << to_string(gate.status)
                      << " code=" << to_string(gate.code) << " label=" << gate.label << '\n';
        }
    }
    return commit.outcome;
}

}  // namespace

int main(int argc, char*[]) {
    if (argc != 1) {
        std::cout << "USAGE policy_generation_invalidation takes no arguments\n";
        return 2;
    }

    // The plan time-to-live is widened so this example isolates authority: the
    // plan is still inside its validity window at every step below.
    EngineConfig config = EngineConfig::defaults();
    config.plan_ttl_millis = 3600000ULL;

    PromotionEngine engine(config, CoordinatorEpoch(1));
    const CoordinatorAuthority authority = engine.authority();

    IdentityGenerator<ArtifactIdTag> artifact_ids(0x9E31U);
    IdentityGenerator<PromotionRequestIdTag> request_ids(0x9E32U);
    IdentityGenerator<PromotionAttemptIdTag> attempt_ids(0x9E33U);
    IdentityGenerator<ProvenanceRefTag> provenance_refs(0x9E34U);

    ProvenanceRecord provenance;
    provenance.reference = provenance_refs.next();
    provenance.source = "research-ledger";
    provenance.subject = "ledger:summon-cli:3.0.0";
    provenance.resolution = ProvenanceResolution::Resolved;

    ArtifactRegistration registration;
    registration.id = artifact_ids.next();
    registration.kind = ArtifactKind::Executable;
    registration.digest = Digest::from_string("artifact:summon-cli:3.0.0");
    registration.size_bytes = 8U * 1024U * 1024U;
    registration.name = "summon-cli";
    registration.provenance.push_back(provenance);

    const Result<ArtifactRecord> registered = engine.register_artifact(registration);
    if (!registered) {
        std::cout << "ARTIFACT registered=false status=" << registered.status().render() << '\n';
        return 1;
    }
    const ArtifactRecord artifact = registered.value();
    std::cout << "ARTIFACT name=" << artifact.name << " kind=" << to_string(artifact.kind)
              << " stage=" << to_string(artifact.stage) << '\n';

    const EvidenceType required[] = {EvidenceType::ProvenanceComplete, EvidenceType::BuildPass,
                                     EvidenceType::UnitTestPass,       EvidenceType::IntegrationTestPass,
                                     EvidenceType::ReproducibilityPass, EvidenceType::MachineCriticApproval,
                                     EvidenceType::SignatureValid};
    for (EvidenceType type : required) {
        const std::string_view environment = type == EvidenceType::UnitTestPass ? "windows-x64-msvc" : "";
        const Result<EvidenceRecord> stored = submit_pass(engine, artifact, type, environment);
        if (!stored) {
            std::cout << "EVIDENCE type=" << to_string(type)
                      << " stored=false status=" << stored.status().render() << '\n';
            return 1;
        }
    }
    std::cout << "EVIDENCE submitted=" << std::to_string(sizeof(required) / sizeof(required[0])) << '\n';

    const Stage prelude[] = {Stage::Verified, Stage::Qualified, Stage::Staged, Stage::Approved};
    for (Stage destination : prelude) {
        const Result<PromotionEngine::CommitResult> committed =
            engine.promote(make_request(artifact, authority, destination, request_ids.next(), attempt_ids.next()));
        if (!committed || committed.value().outcome != PromotionOutcome::PromotionCommitted) {
            std::cout << "STAGE -> " << to_string(destination) << " outcome="
                      << (committed ? to_string(committed.value().outcome) : committed.status().render())
                      << " expected=PROMOTION_COMMITTED\n";
            return 1;
        }
        std::cout << "STAGE " << to_string(committed.value().record.from) << " -> "
                  << to_string(committed.value().record.to)
                  << " outcome=" << to_string(committed.value().outcome) << '\n';
    }

    // A plan is issued under the generation that is active now.
    const Result<PromotionEngine::EvaluationResult> evaluated = engine.evaluate(
        make_request(artifact, authority, Stage::Promoted, request_ids.next(), attempt_ids.next()));
    if (!evaluated) {
        std::cout << "PLAN issued=false status=" << evaluated.status().render() << '\n';
        return 1;
    }
    const PromotionPlan plan = evaluated.value().plan;
    const Digest plan_policy_digest = plan.policy_digest;
    const CoordinatorState before_publish = engine.snapshot();
    std::cout << "PLAN issued=" << yes_no(evaluated.value().has_plan)
              << " from=" << to_string(plan.from) << " to=" << to_string(plan.to)
              << " policy_generation=" << plan.policy_generation.to_string()
              << " active_policy_generation=" << before_publish.active_policy_generation.to_string()
              << " reservation=" << yes_no(engine.pending_transition(artifact.id).has_value()) << '\n';

    std::size_t gates_before = 0;
    std::size_t gates_after = 0;
    const PromotionPolicy next_generation = make_incompatible_generation(
        before_publish.policy(), before_publish.active_policy_generation.next(), gates_before, gates_after);
    const Result<PolicyGeneration> published = engine.publish_policy(next_generation);
    if (!published) {
        std::cout << "POLICY published=false status=" << published.status().render() << '\n';
        return 1;
    }
    const CoordinatorState after_publish = engine.snapshot();
    std::cout << "POLICY published generation=" << published.value().to_string()
              << " digest_changed=" << yes_no(after_publish.active_policy_digest != before_publish.active_policy_digest)
              << " promoted_rule_gates=" << std::to_string(gates_before) << "->" << std::to_string(gates_after)
              << '\n';

    // The plan still names the generation and the digest it was computed from.
    const bool generation_stale = plan.policy_generation != after_publish.active_policy_generation;
    const bool digest_stale = plan.policy_digest != after_publish.active_policy_digest;
    std::cout << "BINDING plan_policy_generation=" << plan.policy_generation.to_string()
              << " active_policy_generation=" << after_publish.active_policy_generation.to_string()
              << " generation_stale=" << yes_no(generation_stale) << " digest_stale=" << yes_no(digest_stale)
              << " plan_digest_matches_previous=" << yes_no(plan_policy_digest == before_publish.active_policy_digest)
              << '\n';

    // The fenced plan still holds the artifact's only reservation, so the
    // engine refuses to evaluate a second attempt against it.
    const Result<PromotionEngine::CommitResult> blocked = engine.promote(
        make_request(artifact, authority, Stage::Promoted, request_ids.next(), attempt_ids.next()));
    const PromotionOutcome blocked_outcome = report("REVALIDATION new_attempt", blocked);

    // Releasing in-flight work is the coordinator's conservative recovery: the
    // reservation is dropped and nothing is promoted.
    const std::size_t released = engine.recover_in_flight();
    std::cout << "RECOVERY released_reservations=" << std::to_string(released)
              << " reservations=" << std::to_string(engine.count_pending_transitions()) << '\n';

    // Re-derived under the active generation, the same intent no longer
    // qualifies: the new generation added a requirement that is not satisfied.
    const Result<PromotionEngine::CommitResult> stale_intent = engine.promote(
        make_request(artifact, authority, Stage::Promoted, request_ids.next(), attempt_ids.next()));
    const PromotionOutcome stale_intent_outcome = report("REVALIDATION under_active_generation", stale_intent);
    const std::optional<PromotionEngine::ArtifactView> after_rejection = engine.inspect_artifact(artifact.id);
    std::cout << "STATE stage="
              << (after_rejection.has_value() ? to_string(after_rejection->artifact.stage)
                                              : std::string("(missing)"))
              << " reservation=" << yes_no(engine.pending_transition(artifact.id).has_value()) << '\n';

    // Satisfying the new requirement lets the re-derived plan commit under the
    // generation that is actually active.
    const Result<EvidenceRecord> abi_evidence =
        submit_pass(engine, artifact, EvidenceType::AbiCompatibilityPass, "");
    if (!abi_evidence) {
        std::cout << "EVIDENCE type=ABI_COMPATIBILITY_PASS stored=false status="
                  << abi_evidence.status().render() << '\n';
        return 1;
    }
    std::cout << "EVIDENCE type=" << to_string(abi_evidence.value().type) << " stored=true\n";

    const Result<PromotionEngine::CommitResult> committed = engine.promote(
        make_request(artifact, authority, Stage::Promoted, request_ids.next(), attempt_ids.next()));
    if (!committed) {
        std::cout << "COMMIT transport_status=" << committed.status().render() << '\n';
        return 1;
    }
    std::cout << "COMMIT policy_generation=" << committed.value().decision.policy_generation.to_string()
              << " outcome=" << to_string(committed.value().outcome)
              << " committed=" << yes_no(committed.value().has_record) << '\n';

    const std::optional<PromotionEngine::ArtifactView> view = engine.inspect_artifact(artifact.id);
    const bool promoted = view.has_value() && view->artifact.stage == Stage::Promoted &&
                          view->artifact.currently_authoritative();
    std::cout << "STATE stage=" << (view.has_value() ? to_string(view->artifact.stage) : std::string("(missing)"))
              << " authoritative=" << yes_no(view.has_value() && view->artifact.currently_authoritative())
              << '\n';

    const bool expected = evaluated.value().has_plan && generation_stale && digest_stale &&
                          published.value() == PolicyGeneration(2) && gates_after == gates_before + 1U &&
                          blocked_outcome == PromotionOutcome::Conflict && released == 1U &&
                          stale_intent_outcome == PromotionOutcome::EvidenceMissing &&
                          after_rejection.has_value() && after_rejection->artifact.stage == Stage::Approved &&
                          committed.value().outcome == PromotionOutcome::PromotionCommitted &&
                          committed.value().decision.policy_generation == PolicyGeneration(2) && promoted;
    std::cout << "EXPECTATION " << (expected ? "satisfied" : "violated") << '\n';
    return expected ? 0 : 1;
}
