// Artifact Promotion - lifecycle, quarantine, revocation, supersession, rollback.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "support/test_context.hpp"

using namespace artifact_promotion;
using namespace artifact_promotion::test;

AP_TEST(the_reference_lifecycle_is_valid_and_acyclic) {
    const LifecycleGraph graph = LifecycleGraph::reference();
    const Status valid = graph.validate(Stage::Candidate);
    if (valid.failed()) {
        context.fail(std::string("reference lifecycle rejected: ") + valid.render(), __FILE__, __LINE__);
    }
    AP_CHECK_EQ(valid.code(), ErrorCode::Ok);
    AP_CHECK_EQ(graph.edge_count(), static_cast<std::size_t>(21));
    AP_CHECK(graph.has_edge(Stage::Candidate, Stage::Verified));
    AP_CHECK(!graph.has_edge(Stage::Candidate, Stage::Promoted));
    AP_CHECK(!graph.has_edge(Stage::Candidate, Stage::Candidate));

    // Canonicalization is idempotent: the same transitions always produce the
    // same digest.
    LifecycleGraph copy = graph;
    copy.canonicalize();
    AP_CHECK(copy == graph);
    AP_CHECK_EQ(copy.graph_digest().to_string(), graph.graph_digest().to_string());
}

AP_TEST(a_cyclic_lifecycle_graph_is_rejected) {
    LifecycleGraph graph;
    (void)graph.add_edge(Stage::Candidate, Stage::Verified);
    (void)graph.add_edge(Stage::Verified, Stage::Candidate);
    (void)graph.add_edge(Stage::Candidate, Stage::Revoked);
    graph.canonicalize();
    AP_CHECK_EQ(graph.validate(Stage::Candidate).code(), ErrorCode::InvalidTransition);
}

AP_TEST(a_graph_without_an_exit_edge_is_rejected) {
    LifecycleGraph graph;
    (void)graph.add_edge(Stage::Candidate, Stage::Verified);
    (void)graph.add_edge(Stage::Verified, Stage::Qualified);
    graph.canonicalize();
    AP_CHECK_EQ(graph.validate(Stage::Candidate).code(), ErrorCode::InvalidTransition);
}

AP_TEST(an_empty_graph_is_rejected) {
    const LifecycleGraph graph;
    AP_CHECK_EQ(graph.validate(Stage::Candidate).code(), ErrorCode::InvalidTransition);
    AP_CHECK_EQ(graph.validate(Stage::Invalid).code(), ErrorCode::InvalidStage);
}

AP_TEST(full_promotion_path_is_recorded_in_history) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-life", "digest-life-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const ArtifactRecord final_record = scenario.current(id);
    AP_CHECK_EQ(final_record.stage, Stage::Promoted);
    AP_CHECK(final_record.currently_authoritative());
    AP_CHECK(final_record.promoted);
    AP_CHECK(final_record.promotion_decision.valid());
    AP_CHECK(final_record.promotion_authority.valid());
    AP_CHECK_EQ(final_record.stage_generation.value(), static_cast<std::uint64_t>(6));

    const std::vector<PromotionRecord> history = scenario.engine().promotion_history(id);
    AP_CHECK_EQ(history.size(), static_cast<std::size_t>(5));
    AP_CHECK_EQ(history.front().from, Stage::Candidate);
    AP_CHECK_EQ(history.back().to, Stage::Promoted);
    for (std::size_t index = 1; index < history.size(); ++index) {
        AP_CHECK(history[index - 1].sequence < history[index].sequence);
    }
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
}

AP_TEST(repeating_a_promotion_of_the_same_revision_is_idempotent) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-idem", "digest-idem-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const std::size_t records_before = scenario.engine().promotion_history(id).size();

    // A fresh request identity for an already promoted revision returns
    // ALREADY_PROMOTED and does not create a second transition.
    const PromotionOutcome outcome = scenario.step(id, Stage::Promoted);
    AP_CHECK_EQ(outcome, PromotionOutcome::AlreadyPromoted);
    AP_CHECK_EQ(scenario.engine().promotion_history(id).size(), records_before);
}

AP_TEST(a_duplicate_request_identity_returns_the_original_decision) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-dup", "digest-dup-1");
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

    const auto first = scenario.engine().promote(request);
    AP_REQUIRE(first.has_value());
    AP_CHECK_EQ(first.value().outcome, PromotionOutcome::PromotionCommitted);
    const PromotionDecisionId first_decision = first.value().decision.id;
    const std::size_t records_after_first = scenario.engine().promotion_history(id).size();

    // The same request identity, same content: the committed decision is
    // returned and nothing new is committed.
    const auto second = scenario.engine().promote(request);
    AP_REQUIRE(second.has_value());
    AP_CHECK_EQ(second.value().decision.id, first_decision);
    AP_CHECK_EQ(second.value().outcome, PromotionOutcome::PromotionCommitted);
    AP_CHECK_EQ(scenario.engine().promotion_history(id).size(), records_after_first);

    // The same request identity carrying different content is a conflict, never
    // a silent second transition.
    PromotionRequest altered = request;
    altered.requested_stage = Stage::Qualified;
    const auto conflicting = scenario.engine().promote(altered);
    AP_CHECK(!conflicting.has_value());
    AP_CHECK_EQ(conflicting.status().code(), ErrorCode::Conflict);
}

AP_TEST(quarantine_prevents_promotion_and_release_requires_authorized_evidence) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-quar", "digest-quar-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const auto quarantined = scenario.engine().quarantine(id, "security_finding", "advisory-2026-001",
                                                          scenario.authority());
    AP_REQUIRE(quarantined.has_value());
    AP_CHECK_EQ(quarantined.value().outcome, PromotionOutcome::Quarantined);
    AP_CHECK_EQ(quarantined.value().artifact.stage, Stage::Quarantined);
    AP_CHECK(quarantined.value().artifact.quarantine.active);
    AP_CHECK(!quarantined.value().artifact.currently_authoritative());
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);

    // A quarantined artifact cannot be promoted, and a plain release attempt is
    // refused until the policy's release evidence exists.
    AP_CHECK_EQ(scenario.step(id, Stage::Promoted), PromotionOutcome::TransitionIllegal);
    const auto refused = scenario.engine().release_quarantine(id, scenario.authority());
    AP_REQUIRE(refused.has_value());
    AP_CHECK_EQ(refused.value().outcome, PromotionOutcome::EvidenceMissing);
    AP_CHECK_EQ(scenario.current(id).stage, Stage::Quarantined);

    Scenario::EvidenceSpec scan;
    scan.type = EvidenceType::SecurityScanPass;
    (void)scenario.submit_spec(id, scan);
    Scenario::EvidenceSpec approval;
    approval.type = EvidenceType::HumanApproval;
    (void)scenario.submit_spec(id, approval);

    const auto released = scenario.engine().release_quarantine(id, scenario.authority());
    AP_REQUIRE(released.has_value());
    AP_CHECK_EQ(released.value().outcome, PromotionOutcome::PromotionCommitted);
    // Release returns the artifact to CANDIDATE for a full re-evaluation; it
    // does not restore the stage the artifact held before quarantine.
    AP_CHECK_EQ(released.value().artifact.stage, Stage::Candidate);
    AP_CHECK(!released.value().artifact.quarantine.active);
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
}

AP_TEST(revocation_invalidates_current_authority_but_preserves_history) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-rev", "digest-rev-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());
    const ArtifactRecord promoted = scenario.current(id);
    AP_CHECK(promoted.currently_authoritative());

    const auto revoked = scenario.engine().revoke(id, promoted.promotion_decision, "security_finding",
                                                  "critical advisory", scenario.authority());
    AP_REQUIRE(revoked.has_value());
    AP_CHECK_EQ(revoked.value().outcome, PromotionOutcome::Revoked);
    AP_CHECK_EQ(revoked.value().artifact.stage, Stage::Revoked);
    AP_CHECK(revoked.value().artifact.revocation.active);
    AP_CHECK(!revoked.value().artifact.currently_authoritative());
    AP_CHECK(!revoked.value().artifact.promoted);

    // History is not erased: the promotion record is still there.
    const std::vector<PromotionRecord> history = scenario.engine().promotion_history(id);
    bool saw_promotion = false;
    bool saw_revocation = false;
    for (const PromotionRecord& record : history) {
        if (record.to == Stage::Promoted) {
            saw_promotion = true;
        }
        if (record.to == Stage::Revoked) {
            saw_revocation = true;
        }
    }
    AP_CHECK(saw_promotion);
    AP_CHECK(saw_revocation);

    // A stale retry cannot resurrect the revoked authority.
    AP_CHECK_EQ(scenario.step(id, Stage::Promoted), PromotionOutcome::TransitionIllegal);
    AP_CHECK(!scenario.current(id).currently_authoritative());
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
}

AP_TEST(a_revocation_naming_an_unknown_decision_is_refused) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-rev2", "digest-rev-2");
    const auto outcome = scenario.engine().revoke(id, PromotionDecisionId::from_parts(0xDEAD, 0xBEEF), "reason",
                                                  "detail", scenario.authority());
    AP_CHECK(!outcome.has_value());
    AP_CHECK_EQ(outcome.status().code(), ErrorCode::DecisionNotFound);
}

AP_TEST(supersession_is_separate_from_revocation) {
    Scenario scenario;
    const ArtifactId older = scenario.make_artifact_id();
    const ArtifactId newer = scenario.make_artifact_id();
    (void)scenario.register_artifact(older, ArtifactKind::Executable, "exe-old", "digest-old-1");
    (void)scenario.register_artifact(newer, ArtifactKind::Executable, "exe-new", "digest-new-1");
    AP_REQUIRE(scenario.drive_to_promoted(older).ok());
    AP_REQUIRE(scenario.drive_to_promoted(newer).ok());

    const auto superseded = scenario.engine().supersede(older, newer, "newer revision released",
                                                        scenario.authority());
    AP_REQUIRE(superseded.has_value());
    AP_CHECK_EQ(superseded.value().outcome, PromotionOutcome::Superseded);
    AP_CHECK_EQ(superseded.value().artifact.stage, Stage::Superseded);
    AP_CHECK(superseded.value().artifact.supersession.active);
    AP_CHECK_EQ(superseded.value().artifact.supersession.successor, newer);
    // Supersession does not assert that the older artifact is invalid.
    AP_CHECK(!superseded.value().artifact.revocation.active);
    AP_CHECK(!superseded.value().artifact.currently_authoritative());
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
}

AP_TEST(supersession_requires_a_registered_successor_and_rejects_self_supersession) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-self", "digest-self-1");

    const auto self = scenario.engine().supersede(id, id, "nonsense", scenario.authority());
    AP_CHECK(!self.has_value());
    AP_CHECK_EQ(self.status().code(), ErrorCode::InvalidArgument);

    const auto missing = scenario.engine().supersede(id, scenario.make_artifact_id(), "nonsense",
                                                     scenario.authority());
    AP_CHECK(!missing.has_value());
    AP_CHECK_EQ(missing.status().code(), ErrorCode::ArtifactNotFound);
}

AP_TEST(rollback_eligibility_requires_policy_permission_and_current_gates) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-roll", "digest-roll-1");

    // An artifact that was never promoted is not a rollback target even though
    // the policy permits rollback for its class.
    const auto before = scenario.engine().evaluate_rollback_eligibility(id);
    AP_CHECK(!before.eligible);
    AP_CHECK(!before.blocking_gates.empty());

    AP_REQUIRE(scenario.drive_to_promoted(id).ok());
    const auto after = scenario.engine().evaluate_rollback_eligibility(id);
    AP_CHECK(after.eligible);
    AP_CHECK_EQ(after.outcome, PromotionOutcome::PromotionEligible);

    // Revocation removes rollback eligibility, because "previously promoted"
    // does not mean "safe to restore now".
    (void)scenario.engine().revoke(id, PromotionDecisionId{}, "integrity_failure", "digest no longer matches",
                                   scenario.authority());
    const auto revoked = scenario.engine().evaluate_rollback_eligibility(id);
    AP_CHECK(!revoked.eligible);
}

AP_TEST(rollback_eligibility_is_denied_when_policy_does_not_allow_it) {
    PromotionPolicy policy = make_reference_policy(PromotionPolicyId::from_parts(0xE, 0xF), PolicyGeneration(1));
    for (PolicyRule& rule : policy.rules) {
        if (rule.from == Stage::Approved && rule.to == Stage::Promoted) {
            rule.allow_rollback_eligibility = false;
        }
    }
    AP_CHECK_EQ(policy.validate().code(), ErrorCode::Ok);

    ScenarioOptions options;
    Scenario scenario(options);
    AP_REQUIRE(scenario.engine().publish_policy(policy).has_value());

    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-roll2", "digest-roll-2");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const auto eligibility = scenario.engine().evaluate_rollback_eligibility(id);
    AP_CHECK(!eligibility.eligible);
    AP_CHECK(std::string(eligibility.render()).find("policy") != std::string::npos);
}

AP_TEST(evidence_revocation_is_separate_from_artifact_revocation) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-ev", "digest-ev-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const std::vector<EvidenceRecord> evidence = scenario.engine().evidence_for(id, scenario.current(id).revision);
    AP_REQUIRE(!evidence.empty());
    const auto withdrawn = scenario.engine().revoke_evidence(evidence.front().id, "producer withdrew the result",
                                                            scenario.authority());
    AP_REQUIRE(withdrawn.has_value());
    AP_CHECK_EQ(withdrawn.value().outcome, PromotionOutcome::EvidenceRevoked);

    // The artifact stays promoted: revoking one evidence record is not the same
    // as revoking the artifact's authority, which is an explicit operation.
    AP_CHECK(scenario.current(id).currently_authoritative());
    AP_CHECK(!scenario.current(id).revocation.active);
}

AP_TEST(retirement_ends_the_lifecycle_without_asserting_invalidity) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-ret", "digest-ret-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const auto retired = scenario.engine().retire(id, scenario.authority());
    AP_REQUIRE(retired.has_value());
    AP_CHECK_EQ(retired.value().outcome, PromotionOutcome::PromotionCommitted);
    AP_CHECK_EQ(retired.value().artifact.stage, Stage::Retired);
    AP_CHECK(!retired.value().artifact.currently_authoritative());
    AP_CHECK(!retired.value().artifact.revocation.active);
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
}

AP_TEST(history_is_append_only_across_a_quarantine_release_cycle) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-hist", "digest-hist-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());
    const std::size_t promoted_records = scenario.engine().promotion_history(id).size();

    (void)scenario.engine().quarantine(id, "integrity_mismatch", "digest changed", scenario.authority());
    (void)scenario.submit(id, EvidenceType::SecurityScanPass, EvidenceResult::Pass, "scan");
    (void)scenario.submit(id, EvidenceType::HumanApproval, EvidenceResult::Pass, "approval");
    (void)scenario.engine().release_quarantine(id, scenario.authority());

    const std::vector<PromotionRecord> history = scenario.engine().promotion_history(id);
    AP_CHECK(history.size() > promoted_records);
    const std::vector<HistoryEvent> events = scenario.engine().artifact_history(id, 4096);
    AP_CHECK(!events.empty());
    for (const HistoryEvent& event : events) {
        if (event.kind == HistoryEventKind::Revoked || event.kind == HistoryEventKind::Quarantined) {
            AP_CHECK(event.sequence.valid());
        }
    }
}

int main() { return TestContext::instance().run_all("lifecycle"); }
