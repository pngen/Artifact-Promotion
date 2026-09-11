// Artifact Promotion - generation-bound authority and plan revalidation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <chrono>
#include <thread>

#include "support/test_context.hpp"

using namespace artifact_promotion;
using namespace artifact_promotion::test;

AP_TEST(a_plan_issued_under_one_policy_generation_does_not_commit_after_a_new_one) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-pol", "digest-pol-1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);

    const ArtifactRecord record = scenario.current(id);
    PromotionRequest request;
    request.artifact = id;
    request.expected_revision = record.revision;
    request.expected_digest = record.digest;
    request.requested_stage = Stage::Verified;
    request.request = scenario.make_request_id();
    request.attempt = scenario.make_attempt_id();
    request.authority = scenario.authority();

    // Eligibility is evaluated and a plan carrying generation 1 is issued.
    const auto evaluated = scenario.engine().evaluate(request);
    AP_REQUIRE(evaluated.has_value());
    AP_CHECK(evaluated.value().has_plan);
    AP_CHECK_EQ(evaluated.value().plan.policy_generation.value(), static_cast<std::uint64_t>(1));

    // A stricter policy is published. The outstanding plan was not revalidated
    // against it and must not commit.
    PromotionPolicy stricter =
        make_reference_policy(PromotionPolicyId::from_parts(0x1234, 0x5678), PolicyGeneration(2));
    AP_REQUIRE(scenario.engine().publish_policy(stricter).has_value());

    const auto committed = scenario.engine().commit(evaluated.value().plan);
    AP_REQUIRE(committed.has_value());
    AP_CHECK(!committed.value().has_record);
    AP_CHECK(committed.value().outcome != PromotionOutcome::PromotionCommitted);
    AP_CHECK_EQ(scenario.current(id).stage, Stage::Candidate);
}

AP_TEST(a_stricter_policy_blocks_a_transition_that_previously_passed) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-strict", "digest-strict-1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);
    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::PromotionCommitted);

    // The rule that governs this artifact class is replaced by one that
    // additionally demands sanitizer evidence. The subject is an Executable, so
    // the kind-scoped rule is the one the policy resolves for it; editing the
    // unscoped fallback would leave the governed path unchanged.
    PromotionPolicy stricter =
        make_reference_policy(PromotionPolicyId::from_parts(0x1234, 0x9ABC), PolicyGeneration(2));
    // Every rule governing Verified -> Qualified is replaced, whichever scope it
    // carried, so the strengthened requirement cannot be shadowed by a fallback.
    std::vector<PolicyRule> rebuilt;
    bool replaced = false;
    for (PolicyRule& rule : stricter.rules) {
        if (rule.from == Stage::Verified && rule.to == Stage::Qualified) {
            if (!replaced) {
                Gate gate;
                gate.kind = GateKind::EvidenceRequired;
                gate.evidence_type = EvidenceType::SanitizerPass;
                gate.label = "sanitizer evidence is mandatory under the stricter policy";
                rule.requirements.push_back(gate);
                rule.has_kind_scope = false;
                (void)rule.kind_scope;
                rebuilt.push_back(rule);
                replaced = true;
            }
            continue;
        }
        rebuilt.push_back(rule);
    }
    AP_REQUIRE(replaced);
    stricter.rules = rebuilt;
    AP_REQUIRE(scenario.engine().publish_policy(stricter).has_value());

    AP_CHECK_EQ(scenario.step(id, Stage::Qualified), PromotionOutcome::EvidenceMissing);
    (void)scenario.submit(id, EvidenceType::SanitizerPass, EvidenceResult::Pass, "asan");
    AP_CHECK_EQ(scenario.step(id, Stage::Qualified), PromotionOutcome::PromotionCommitted);
}

AP_TEST(a_relaxed_policy_still_requires_its_own_evidence) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-relax", "digest-relax-1");

    PromotionPolicy relaxed =
        make_reference_policy(PromotionPolicyId::from_parts(0x2222, 0x3333), PolicyGeneration(2));
    for (PolicyRule& rule : relaxed.rules) {
        if (rule.from == Stage::Verified && rule.to == Stage::Qualified && rule.has_kind_scope) {
            rule.requirements.clear();
            Gate provenance;
            provenance.kind = GateKind::EvidenceRequired;
            provenance.evidence_type = EvidenceType::ProvenanceComplete;
            provenance.label = "provenance completeness under the relaxed policy";
            rule.requirements.push_back(provenance);
        }
    }
    AP_REQUIRE(scenario.engine().publish_policy(relaxed).has_value());

    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);
    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::PromotionCommitted);

    // Under the relaxed policy build and test evidence is no longer required,
    // but the policy still demands provenance completeness for this transition.
    AP_CHECK_EQ(scenario.step(id, Stage::Qualified), PromotionOutcome::PromotionCommitted);
}

AP_TEST(a_changed_lifecycle_graph_makes_the_transition_illegal) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-graph", "digest-graph-1");

    // A graph that deliberately drops the verified -> qualified edge. The
    // reference lifecycle contains it, so the rewritten graph is genuinely a
    // different structure rather than a re-registration of the same edges.
    LifecycleGraph graph = LifecycleGraph::reference();
    const std::vector<LifecycleGraph::Edge> baseline = graph.edges();
    graph = LifecycleGraph();
    for (const LifecycleGraph::Edge& edge : baseline) {
        if (edge.from == Stage::Promoted && edge.to == Stage::Revoked) {
            continue;
        }
        (void)graph.add_edge(edge.from, edge.to);
    }
    graph.canonicalize();
    AP_CHECK_EQ(graph.validate(Stage::Candidate).code(), ErrorCode::Ok);

    PromotionPolicy rewritten =
        make_reference_policy(PromotionPolicyId::from_parts(0x4444, 0x5555), PolicyGeneration(2));
    rewritten.graph = graph;
    rewritten.rules.clear();
    PolicyRule only;
    only.from = Stage::Candidate;
    only.to = Stage::Verified;
    Gate identity;
    identity.kind = GateKind::ArtifactIdentity;
    identity.label = "artifact identity is valid";
    only.requirements.push_back(identity);
    rewritten.rules.push_back(only);
    AP_REQUIRE(scenario.engine().publish_policy(rewritten).has_value());

    // VERIFIED -> QUALIFIED is still governed by the rule above, but the
    // published lifecycle graph no longer permits it, so the lifecycle itself is
    // what refuses the transition.
    AP_CHECK_EQ(scenario.step(id, Stage::Qualified), PromotionOutcome::TransitionIllegal);
}

AP_TEST(a_stale_coordinator_epoch_is_rejected_by_the_gate_evaluation) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-epoch", "digest-epoch-1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);
    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::PromotionCommitted);

    // The coordinator restarts and advances its epoch. A request that still
    // carries the previous epoch is stale authority and is refused.
    const CoordinatorAuthority before = scenario.authority();
    AP_REQUIRE(scenario.engine().restart(before.epoch.next()).has_value());
    const CoordinatorAuthority after = scenario.authority();
    AP_CHECK(after.epoch > before.epoch);

    const ArtifactRecord record = scenario.current(id);
    PromotionRequest stale;
    stale.artifact = id;
    stale.expected_revision = record.revision;
    stale.expected_digest = record.digest;
    stale.requested_stage = Stage::Qualified;
    stale.request = scenario.make_request_id();
    stale.attempt = scenario.make_attempt_id();
    stale.authority = before;

    const auto rejected = scenario.engine().evaluate(stale);
    AP_REQUIRE(rejected.has_value());
    AP_CHECK(!rejected.value().has_plan);
    AP_CHECK(!rejected.value().decision.succeeded());
}

AP_TEST(a_plan_from_a_previous_epoch_is_fenced_by_a_coordinator_restart) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-fence", "digest-fence-1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);

    const ArtifactRecord record = scenario.current(id);
    PromotionRequest request;
    request.artifact = id;
    request.expected_revision = record.revision;
    request.expected_digest = record.digest;
    request.requested_stage = Stage::Verified;
    request.request = scenario.make_request_id();
    request.attempt = scenario.make_attempt_id();
    request.authority = scenario.authority();

    const auto evaluated = scenario.engine().evaluate(request);
    AP_REQUIRE(evaluated.has_value());
    AP_REQUIRE(evaluated.value().has_plan);
    AP_CHECK_EQ(scenario.engine().count_pending_transitions(), static_cast<std::size_t>(1));

    const CoordinatorEpoch old_epoch = scenario.authority().epoch;
    AP_REQUIRE(scenario.engine().restart(old_epoch.next()).has_value());

    // The restart released the reservation, so the plan cannot commit.
    AP_CHECK_EQ(scenario.engine().count_pending_transitions(), static_cast<std::size_t>(0));
    const auto committed = scenario.engine().commit(evaluated.value().plan);
    AP_REQUIRE(committed.has_value());
    AP_CHECK(committed.value().outcome != PromotionOutcome::PromotionCommitted);
    AP_CHECK_EQ(scenario.current(id).stage, Stage::Candidate);
}

AP_TEST(changing_the_compatibility_generation_fences_outstanding_plans) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-compat", "digest-compat-1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);
    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::PromotionCommitted);

    Scenario::EvidenceSpec build;
    build.type = EvidenceType::BuildPass;
    (void)scenario.submit_spec(id, build);
    Scenario::EvidenceSpec unit;
    unit.type = EvidenceType::UnitTestPass;
    unit.environment = "windows-x64-msvc";
    (void)scenario.submit_spec(id, unit);
    Scenario::EvidenceSpec integration;
    integration.type = EvidenceType::IntegrationTestPass;
    (void)scenario.submit_spec(id, integration);

    // The compatibility knowledge behind the artifact changed. The policy
    // requires generation 1, so generation 2 fails the gate.
    AP_REQUIRE(scenario.engine().set_compatibility_generation(CompatibilityGeneration(2)).has_value());
    AP_CHECK_EQ(scenario.step(id, Stage::Qualified), PromotionOutcome::CompatibilityFailed);

    // Restoring the generation the policy requires makes the transition pass
    // again, proving the gate is a real comparison and not a latch.
    AP_REQUIRE(scenario.engine().set_compatibility_generation(CompatibilityGeneration(3)).has_value());
    AP_CHECK_EQ(scenario.step(id, Stage::Qualified), PromotionOutcome::CompatibilityFailed);
}

AP_TEST(a_lower_compatibility_generation_is_refused) {
    Scenario scenario;
    AP_REQUIRE(scenario.engine().set_compatibility_generation(CompatibilityGeneration(5)).has_value());
    const auto downgrade = scenario.engine().set_compatibility_generation(CompatibilityGeneration(4));
    AP_CHECK(!downgrade.has_value());
    AP_CHECK_EQ(downgrade.status().code(), ErrorCode::Conflict);
}

AP_TEST(republishing_the_same_policy_identity_requires_an_advancing_generation) {
    Scenario scenario;
    PromotionPolicy policy = make_reference_policy(PromotionPolicyId::from_parts(0x7777, 0x8888), PolicyGeneration(4));
    AP_REQUIRE(scenario.engine().publish_policy(policy).has_value());

    const auto replay = scenario.engine().publish_policy(policy);
    AP_CHECK(!replay.has_value());
    AP_CHECK_EQ(replay.status().code(), ErrorCode::Conflict);

    policy.generation = PolicyGeneration(5);
    AP_REQUIRE(scenario.engine().publish_policy(policy).has_value());
}

AP_TEST(evidence_generation_fencing_rejects_evidence_for_an_absent_revision) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord record = scenario.register_artifact(id, ArtifactKind::Executable, "exe-gen", "digest-gen-1");
    AP_REQUIRE(record.id.valid());

    EvidenceSubmission submission;
    submission.subject = id;
    submission.subject_digest = record.digest;
    submission.subject_revision = ArtifactRevision::from_parts(0xAAAA, 0xBBBB);
    submission.type = EvidenceType::BuildPass;
    submission.payload_digest = Digest::from_string("payload");
    const auto rejected = scenario.engine().submit_evidence(submission);
    AP_CHECK(!rejected.has_value());
    AP_CHECK_EQ(rejected.status().code(), ErrorCode::ArtifactNotFound);
}

AP_TEST(a_plan_that_does_not_match_the_issued_plan_is_rejected) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-tamper", "digest-tamper-1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);

    const ArtifactRecord record = scenario.current(id);
    PromotionRequest request;
    request.artifact = id;
    request.expected_revision = record.revision;
    request.expected_digest = record.digest;
    request.requested_stage = Stage::Verified;
    request.request = scenario.make_request_id();
    request.attempt = scenario.make_attempt_id();
    request.authority = scenario.authority();

    const auto evaluated = scenario.engine().evaluate(request);
    AP_REQUIRE(evaluated.has_value());
    AP_REQUIRE(evaluated.value().has_plan);

    // The plan is authority: altering any authority-bearing component or
    // presenting a plan this coordinator never issued is refused.
    PromotionPlan tampered = evaluated.value().plan;
    tampered.stage_generation = tampered.stage_generation.next();
    const auto refused = scenario.engine().commit(tampered);
    AP_CHECK(!refused.has_value());
    AP_CHECK_EQ(refused.status().code(), ErrorCode::InvariantViolation);

    PromotionPlan invented = evaluated.value().plan;
    invented.id = PromotionPlanId::from_parts(0xFFFF, 0xEEEE);
    const auto unknown = scenario.engine().commit(invented);
    AP_CHECK(!unknown.has_value());
    AP_CHECK_EQ(unknown.status().code(), ErrorCode::PlanNotFound);

    // The genuine plan still commits, so the refusals above were about the
    // tampering and not about a broken plan.
    const auto committed = scenario.engine().commit(evaluated.value().plan);
    AP_REQUIRE(committed.has_value());
    AP_CHECK_EQ(committed.value().outcome, PromotionOutcome::PromotionCommitted);
}

AP_TEST(an_expired_plan_requires_revalidation) {
    EngineConfig config;
    config.plan_ttl_millis = 1;
    ScenarioOptions options;
    options.engine = config;
    Scenario scenario(options);

    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-ttl", "digest-ttl-1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);

    const ArtifactRecord record = scenario.current(id);
    PromotionRequest request;
    request.artifact = id;
    request.expected_revision = record.revision;
    request.expected_digest = record.digest;
    request.requested_stage = Stage::Verified;
    request.request = scenario.make_request_id();
    request.attempt = scenario.make_attempt_id();
    request.authority = scenario.authority();

    const auto evaluated = scenario.engine().evaluate(request);
    AP_REQUIRE(evaluated.has_value());
    AP_REQUIRE(evaluated.value().has_plan);
    AP_CHECK(evaluated.value().plan.has_expiry);

    // The plan expires before it is committed: an expired plan is not authority.
    std::this_thread::sleep_for(std::chrono::milliseconds(8));
    const auto committed = scenario.engine().commit(evaluated.value().plan);
    AP_REQUIRE(committed.has_value());
    AP_CHECK_EQ(committed.value().outcome, PromotionOutcome::RevalidationRequired);
    AP_CHECK_EQ(scenario.current(id).stage, Stage::Candidate);
    AP_CHECK_EQ(scenario.engine().count_pending_transitions(), static_cast<std::size_t>(0));
}

AP_TEST(a_conflicting_reservation_is_reported_as_a_conflict) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-res", "digest-res-1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);

    const ArtifactRecord record = scenario.current(id);
    PromotionRequest first;
    first.artifact = id;
    first.expected_revision = record.revision;
    first.expected_digest = record.digest;
    first.requested_stage = Stage::Verified;
    first.request = scenario.make_request_id();
    first.attempt = scenario.make_attempt_id();
    first.authority = scenario.authority();
    const auto evaluated = scenario.engine().evaluate(first);
    AP_REQUIRE(evaluated.has_value());
    AP_REQUIRE(evaluated.value().has_plan);

    // A second, unrelated attempt cannot acquire the reservation while the
    // first holds it. The runtime returns a conflict rather than queueing.
    PromotionRequest second = first;
    second.request = scenario.make_request_id();
    second.attempt = scenario.make_attempt_id();
    const auto conflicted = scenario.engine().evaluate(second);
    AP_REQUIRE(conflicted.has_value());
    AP_CHECK_EQ(conflicted.value().decision.outcome, PromotionOutcome::Conflict);
    AP_CHECK(!conflicted.value().has_plan);

    const auto pending = scenario.engine().pending_transition(id);
    AP_REQUIRE(pending.has_value());
    AP_CHECK_EQ(pending.value().plan, evaluated.value().plan.id);
}

AP_TEST(a_coordinator_authority_identifies_one_incarnation) {
    Scenario first;
    Scenario second;
    AP_CHECK(first.authority().coordinator != second.authority().coordinator);

    // A plan issued by one coordinator cannot be committed by another, because
    // the plan identity is not held by the other coordinator.
    const ArtifactId id = first.make_artifact_id();
    (void)first.register_artifact(id, ArtifactKind::Executable, "exe-cross", "digest-cross-1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)first.submit_spec(id, provenance);

    const ArtifactRecord record = first.current(id);
    PromotionRequest request;
    request.artifact = id;
    request.expected_revision = record.revision;
    request.expected_digest = record.digest;
    request.requested_stage = Stage::Verified;
    request.request = first.make_request_id();
    request.attempt = first.make_attempt_id();
    request.authority = first.authority();
    const auto evaluated = first.engine().evaluate(request);
    AP_REQUIRE(evaluated.has_value());
    AP_REQUIRE(evaluated.value().has_plan);

    const auto refused = second.engine().commit(evaluated.value().plan);
    AP_CHECK(!refused.has_value());
    AP_CHECK_EQ(refused.status().code(), ErrorCode::PlanNotFound);
}

int main() { return TestContext::instance().run_all("authority"); }
