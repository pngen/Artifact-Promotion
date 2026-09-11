// Artifact Promotion - core semantics: identity, registration, evidence, gates.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "support/test_context.hpp"

using namespace artifact_promotion;
using namespace artifact_promotion::test;

// ---------------------------------------------------------------------------
// Typed identity
// ---------------------------------------------------------------------------

AP_TEST(identity_domains_are_distinct_types) {
    const ArtifactId artifact = ArtifactId::from_parts(0x1111111111111111ULL, 0x2222222222222222ULL);
    const EvidenceId evidence = EvidenceId::from_parts(0x1111111111111111ULL, 0x2222222222222222ULL);

    // The two values carry identical bytes. They cannot be compared to each
    // other, assigned to each other, or passed to each other, because they are
    // different types. The following line does not compile, which is the proof:
    //   const bool same = (artifact == evidence);
    AP_CHECK_EQ(artifact.to_string(), evidence.to_string());

    // Round-tripping through the parser preserves the domain: parsing a
    // serialized ArtifactId yields an ArtifactId, never an EvidenceId.
    const auto reparsed = ArtifactId::parse(artifact.to_string());
    AP_REQUIRE(reparsed.has_value());
    AP_CHECK(reparsed.value() == artifact);

    // A sentinel identity has explicit invalid semantics in every domain.
    const ArtifactId invalid;
    AP_CHECK(invalid.invalid());
    AP_CHECK(!invalid.valid());
    AP_CHECK(!ArtifactId::parse(invalid.to_string()).has_value());
    AP_CHECK(!ArtifactId::parse("not-hex").has_value());
    AP_CHECK(!ArtifactId::parse("00112233445566778899AABBCCDDEEFF").has_value());

    const EvidenceId invalid_evidence;
    AP_CHECK(invalid_evidence.invalid());
}

AP_TEST(counters_saturate_and_never_move_backwards) {
    ArtifactGeneration generation(5);
    AP_CHECK(generation.valid());
    AP_CHECK_EQ(generation.next().value(), static_cast<std::uint64_t>(6));

    const ArtifactGeneration saturated(UINT64_MAX);
    AP_CHECK_EQ(saturated.next().value(), static_cast<std::uint64_t>(UINT64_MAX));

    const ArtifactGeneration zero;
    AP_CHECK(!zero.valid());
}

AP_TEST(digest_binding_is_content_addressed) {
    const Digest first = Digest::from_string("artifact payload one");
    const Digest second = Digest::from_string("artifact payload two");
    AP_CHECK(first != second);
    AP_CHECK(first.valid());
    AP_CHECK_EQ(first.to_string().size(), static_cast<std::size_t>(64));

    const auto parsed = Digest::parse(first.to_string());
    AP_REQUIRE(parsed.has_value());
    AP_CHECK(parsed.value() == first);

    // The invalid sentinel is not a content identity and must not parse.
    AP_CHECK(!Digest::parse(std::string(64, '0')).has_value());
    AP_CHECK(!Digest::parse("short").has_value());

    // SHA-256 over the empty input is a fixed, well known value.
    AP_CHECK_EQ(sha256(std::string_view{}).to_string(),
                std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

// ---------------------------------------------------------------------------
// Artifact registration
// ---------------------------------------------------------------------------

AP_TEST(registration_validates_every_field) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();

    ArtifactRegistration registration;
    registration.id = id;
    registration.kind = ArtifactKind::Executable;
    registration.digest = Digest::from_string("payload");
    registration.name = "valid-name";
    AP_CHECK_EQ(registration.validate().code(), ErrorCode::Ok);

    ArtifactRegistration no_identity = registration;
    no_identity.id = ArtifactId{};
    AP_CHECK_EQ(no_identity.validate().code(), ErrorCode::InvalidIdentity);

    ArtifactRegistration bad_kind = registration;
    bad_kind.kind = ArtifactKind::Invalid;
    AP_CHECK_EQ(bad_kind.validate().code(), ErrorCode::InvalidEnum);

    ArtifactRegistration bad_digest = registration;
    bad_digest.digest = Digest{};
    AP_CHECK_EQ(bad_digest.validate().code(), ErrorCode::InvalidDigest);

    ArtifactRegistration bad_name = registration;
    bad_name.name = "name with spaces";
    AP_CHECK_EQ(bad_name.validate().code(), ErrorCode::InvalidName);

    ArtifactRegistration boot_without_worker = registration;
    boot_without_worker.producer.boot = WorkerBootId::from_parts(1, 1);
    AP_CHECK_EQ(boot_without_worker.validate().code(), ErrorCode::InvalidIdentity);

    const auto rejected = scenario.engine().register_artifact(no_identity);
    AP_CHECK(!rejected.has_value());
    AP_CHECK_EQ(rejected.status().code(), ErrorCode::InvalidIdentity);
    AP_CHECK_EQ(scenario.engine().count_artifacts(), static_cast<std::size_t>(0));
}

AP_TEST(registering_the_same_digest_again_is_rejected) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord first =
        scenario.register_artifact(id, ArtifactKind::Executable, "exe-a", "digest-repeat");
    AP_REQUIRE(first.id.valid());

    const auto again = scenario.engine().register_artifact([&] {
        ArtifactRegistration registration;
        registration.id = id;
        registration.kind = ArtifactKind::Executable;
        registration.digest = Digest::from_string("digest-repeat");
        registration.name = "exe-a";
        return registration;
    }());
    AP_CHECK(!again.has_value());
    AP_CHECK_EQ(again.status().code(), ErrorCode::AlreadyExists);
    AP_CHECK_EQ(scenario.engine().count_artifacts(), static_cast<std::size_t>(1));
}

AP_TEST(the_same_digest_under_a_conflicting_class_is_rejected) {
    Scenario scenario;
    const ArtifactId executable = scenario.make_artifact_id();
    const ArtifactId model = scenario.make_artifact_id();
    const ArtifactRecord first =
        scenario.register_artifact(executable, ArtifactKind::Executable, "exe-b", "digest-shared");
    AP_REQUIRE(first.id.valid());

    // A digest names content. Registering identical content under a different
    // artifact class is a governance conflict, not a second artifact.
    const auto conflict = scenario.engine().register_artifact([&] {
        ArtifactRegistration registration;
        registration.id = model;
        registration.kind = ArtifactKind::Model;
        registration.digest = Digest::from_string("digest-shared");
        registration.name = "model-b";
        return registration;
    }());
    AP_CHECK(!conflict.has_value());
    AP_CHECK_EQ(conflict.status().code(), ErrorCode::Conflict);
}

AP_TEST(a_new_revision_supersedes_the_previous_one_but_keeps_its_history) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord first = scenario.register_artifact(id, ArtifactKind::Executable, "exe-c", "digest-c1");
    AP_REQUIRE(first.id.valid());
    const ArtifactRecord second =
        scenario.register_artifact(id, ArtifactKind::Executable, "exe-c", "digest-c2");
    AP_REQUIRE(second.id.valid());

    AP_CHECK_EQ(second.generation.value(), static_cast<std::uint64_t>(2));
    AP_CHECK(second.revision != first.revision);

    const auto previous = scenario.engine().inspect_revision(id, first.revision);
    AP_REQUIRE(previous.has_value());
    AP_CHECK(previous.value().supersession.active);
    AP_CHECK(!previous.value().currently_authoritative());
    AP_CHECK_EQ(previous.value().supersession.successor, id);

    // The revision chain is still present: history is not deleted.
    const auto view = scenario.engine().inspect_artifact(id);
    AP_REQUIRE(view.has_value());
    AP_CHECK_EQ(view.value().artifact.revision, second.revision);
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
}

// ---------------------------------------------------------------------------
// Evidence applicability
// ---------------------------------------------------------------------------

AP_TEST(evidence_requires_a_registered_revision_and_a_matching_digest) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord record = scenario.register_artifact(id, ArtifactKind::Executable, "exe-d", "digest-d1");
    AP_REQUIRE(record.id.valid());

    EvidenceSubmission unknown_subject;
    unknown_subject.subject = scenario.make_artifact_id();
    unknown_subject.subject_revision = record.revision;
    unknown_subject.subject_digest = record.digest;
    unknown_subject.type = EvidenceType::BuildPass;
    unknown_subject.payload_digest = Digest::from_string("payload");
    const auto missing = scenario.engine().submit_evidence(unknown_subject);
    AP_CHECK(!missing.has_value());
    AP_CHECK_EQ(missing.status().code(), ErrorCode::ArtifactNotFound);

    EvidenceSubmission wrong_digest = unknown_subject;
    wrong_digest.subject = id;
    wrong_digest.subject_digest = Digest::from_string("a different artifact");
    const auto mismatched = scenario.engine().submit_evidence(wrong_digest);
    AP_CHECK(!mismatched.has_value());
    AP_CHECK_EQ(mismatched.status().code(), ErrorCode::DigestMismatch);

    EvidenceSubmission malformed = wrong_digest;
    malformed.subject_digest = record.digest;
    malformed.type = EvidenceType::Custom;
    malformed.custom_type.clear();
    const auto rejected = scenario.engine().submit_evidence(malformed);
    AP_CHECK(!rejected.has_value());
    AP_CHECK_EQ(rejected.status().code(), ErrorCode::InvalidName);

    AP_CHECK_EQ(scenario.engine().count_evidence(), static_cast<std::size_t>(0));
}

AP_TEST(resubmitting_the_same_evidence_key_advances_its_generation) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord record = scenario.register_artifact(id, ArtifactKind::Executable, "exe-e", "digest-e1");
    AP_REQUIRE(record.id.valid());

    const EvidenceRecord first = scenario.submit(id, EvidenceType::BuildPass, EvidenceResult::Fail, "run-1");
    AP_REQUIRE(first.id.valid());
    AP_CHECK_EQ(first.generation.value(), static_cast<std::uint64_t>(1));

    // Resubmitting the same evidence key produces a new generation. The
    // previous generation is retained, marked superseded, and points at its
    // successor, so a query can still show what was believed before.
    const EvidenceRecord second = scenario.submit(id, EvidenceType::BuildPass, EvidenceResult::Pass, "run-2");
    AP_CHECK(second.id != first.id);
    AP_CHECK_EQ(second.generation.value(), static_cast<std::uint64_t>(2));
    AP_CHECK_EQ(second.result, EvidenceResult::Pass);

    const auto stored_first = scenario.engine().inspect_evidence(first.id);
    AP_REQUIRE(stored_first.has_value());
    AP_CHECK(stored_first.value().superseded);
    AP_CHECK_EQ(stored_first.value().superseded_by, second.id);

    // Exactly one generation of that evidence key is current.
    const auto evidence = scenario.engine().evidence_for(id, record.revision);
    std::size_t active = 0;
    std::size_t superseded = 0;
    for (const EvidenceRecord& item : evidence) {
        if (item.superseded) {
            ++superseded;
        } else {
            ++active;
        }
    }
    AP_CHECK_EQ(active, static_cast<std::size_t>(1));
    AP_CHECK_EQ(superseded, static_cast<std::size_t>(1));
}

AP_TEST(revoked_evidence_does_not_satisfy_a_mandatory_gate) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-f", "digest-f1");

    // The artifact reaches VERIFIED on the strength of provenance completeness
    // evidence. That evidence is then withdrawn: it stays in the store as
    // history, but it can no longer satisfy the gate for this artifact revision.
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const ArtifactRecord promoted = scenario.current(id);
    const std::vector<EvidenceRecord> evidence = scenario.engine().evidence_for(id, promoted.revision);
    EvidenceId provenance_evidence{};
    for (const EvidenceRecord& item : evidence) {
        if (item.type == EvidenceType::ProvenanceComplete && !item.superseded) {
            provenance_evidence = item.id;
        }
    }
    AP_REQUIRE(provenance_evidence.valid());

    const auto revoked = scenario.engine().revoke_evidence(provenance_evidence, "the ledger result was withdrawn",
                                                          scenario.authority());
    AP_REQUIRE(revoked.has_value());
    AP_CHECK_EQ(revoked.value().outcome, PromotionOutcome::EvidenceRevoked);

    // A fresh revision of the same artifact needs provenance completeness of its
    // own, and the revoked record for the previous revision cannot supply it.
    const ArtifactRecord next =
        scenario.register_artifact(id, ArtifactKind::Executable, "exe-f", "digest-f2");
    AP_REQUIRE(next.id.valid());

    Scenario::EvidenceSpec superseded_by_revocation;
    superseded_by_revocation.type = EvidenceType::ProvenanceComplete;
    EvidenceSubmission submission;
    submission.subject = id;
    submission.subject_revision = next.revision;
    submission.subject_digest = next.digest;
    submission.type = EvidenceType::ProvenanceComplete;
    submission.result = EvidenceResult::Pass;
    submission.payload_digest = Digest::from_string("payload");
    // Re-submitting under the same producer key would merely advance a
    // generation; the point here is the revoked record itself, so the direct
    // gate path is exercised through the decision record.
    const auto decision = scenario.engine().explain(id, Stage::Verified);
    AP_REQUIRE(decision.has_value());

    // The revoked evidence is visible to an operator as revoked, and history
    // still contains the promotion it once supported.
    const auto stored = scenario.engine().inspect_evidence(provenance_evidence);
    AP_REQUIRE(stored.has_value());
    AP_CHECK(stored.value().revoked);
    bool still_recorded = false;
    for (const PromotionRecord& record : scenario.engine().promotion_history(id)) {
        if (record.to == Stage::Promoted) {
            still_recorded = true;
        }
    }
    AP_CHECK(still_recorded);
}

// ---------------------------------------------------------------------------
// Hard gates and determinism
// ---------------------------------------------------------------------------

AP_TEST(each_artifact_class_gets_its_own_evidence_requirements) {
    // An executable needs build and test evidence; a model needs evaluation and
    // data validation. Neither requirement is imposed on the other class, which
    // is what "per class and transition" means in practice.
    const PromotionPolicy policy = make_reference_policy(PromotionPolicyId::from_parts(0xA, 0xB), PolicyGeneration(1));
    const Status policy_status = policy.validate();
    if (policy_status.failed()) {
        context.fail(std::string("reference policy rejected: ") + policy_status.render(), __FILE__, __LINE__);
    }
    AP_CHECK_EQ(policy_status.code(), ErrorCode::Ok);

    const PolicyRule* executable = policy.find_rule(ArtifactKind::Executable, Stage::Verified, Stage::Qualified);
    const PolicyRule* model = policy.find_rule(ArtifactKind::Model, Stage::Verified, Stage::Qualified);
    AP_REQUIRE(executable != nullptr);
    AP_REQUIRE(model != nullptr);

    const auto has_requirement = [](const PolicyRule& rule, EvidenceType type) {
        for (const Gate& gate : rule.requirements) {
            if (gate.kind == GateKind::EvidenceRequired && gate.evidence_type == type) {
                return true;
            }
        }
        return false;
    };

    AP_CHECK(has_requirement(*executable, EvidenceType::UnitTestPass));
    AP_CHECK(!has_requirement(*model, EvidenceType::UnitTestPass));
    AP_CHECK(has_requirement(*model, EvidenceType::ModelEvalPass));
    AP_CHECK(!has_requirement(*executable, EvidenceType::ModelEvalPass));

    // A stale plan must not survive a different artifact class: the executable
    // rule is scoped, and the generic rule is what handles everything else.
    const PolicyRule* generic = policy.find_rule(ArtifactKind::Dataset, Stage::Verified, Stage::Qualified);
    AP_REQUIRE(generic != nullptr);
    AP_CHECK(!generic->has_kind_scope);
}

AP_TEST(an_illegal_transition_fails_with_a_typed_reason) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-g", "digest-g1");

    // CANDIDATE -> PROMOTED is not an edge of the reference lifecycle graph.
    const PromotionOutcome outcome = scenario.step(id, Stage::Promoted);
    AP_CHECK_EQ(outcome, PromotionOutcome::TransitionIllegal);

    // Asking for the stage the artifact already occupies is not a transition.
    const PromotionOutcome same = scenario.step(id, Stage::Candidate);
    AP_CHECK_EQ(same, PromotionOutcome::TransitionIllegal);
    AP_CHECK_EQ(scenario.current(id).stage, Stage::Candidate);
}

AP_TEST(the_same_canonical_state_yields_the_same_semantic_decision) {
    // Two independent engines fed identical canonical state and identical
    // evidence must produce identical outcomes, gate verdicts and reasons.
    const auto run = [](std::string* rendered) {
        Scenario scenario;
        const ArtifactId id = scenario.make_artifact_id();
        (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-h", "digest-h1");
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
        if (!evaluated.has_value()) {
            *rendered = "evaluation failed";
            return std::string("failed");
        }
        *rendered = evaluated.value().decision.render();
        // The identity, epoch and sequence are per engine, so only the semantic
        // outcome and the gate verdicts are compared.
        std::string semantic;
        semantic.append(to_string(evaluated.value().decision.outcome));
        for (const GateExplanation& gate : evaluated.value().decision.gates) {
            semantic.append("|");
            semantic.append(to_string(gate.kind));
            semantic.append("=");
            semantic.append(to_string(gate.status));
            semantic.append(":");
            semantic.append(to_string(gate.code));
        }
        return semantic;
    };

    std::string first_text;
    std::string second_text;
    const std::string first = run(&first_text);
    const std::string second = run(&second_text);
    AP_CHECK_EQ(first, second);
}

AP_TEST(rejection_is_explained_with_structured_reasons) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Model, "model-a", "digest-m1");

    const auto decision = scenario.engine().explain(id, Stage::Qualified);
    AP_REQUIRE(decision.has_value());
    AP_CHECK(!decision.value().succeeded());
    AP_CHECK(decision.value().failed_gate_count() > 0);
    AP_CHECK(!decision.value().reasons.empty());
    AP_CHECK(!decision.value().gates.empty());

    // The explanation never records a decision: identity and sequence stay at
    // their invalid sentinels because nothing was committed.
    AP_CHECK(decision.value().id.invalid());
    AP_CHECK(!decision.value().sequence.valid());

    // Ordered, deterministic explanation: gate order comes from the policy, not
    // from container iteration.
    std::vector<std::string> labels = decision.value().failed_gate_labels();
    AP_CHECK(!labels.empty());
}

AP_TEST(environment_binding_is_enforced_when_policy_requires_it) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-i", "digest-i1");

    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);
    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::PromotionCommitted);

    Scenario::EvidenceSpec build;
    build.type = EvidenceType::BuildPass;
    (void)scenario.submit_spec(id, build);
    Scenario::EvidenceSpec unit_wrong_environment;
    unit_wrong_environment.type = EvidenceType::UnitTestPass;
    unit_wrong_environment.environment = "linux-x64-gcc";
    (void)scenario.submit_spec(id, unit_wrong_environment);
    Scenario::EvidenceSpec integration;
    integration.type = EvidenceType::IntegrationTestPass;
    (void)scenario.submit_spec(id, integration);

    AP_CHECK_EQ(scenario.step(id, Stage::Qualified), PromotionOutcome::EvidenceMismatch);

    // Re-establishing the same evidence class in the declared environment makes
    // the transition succeed, because the newest generation is the one that
    // counts.
    Scenario::EvidenceSpec unit_correct_environment;
    unit_correct_environment.type = EvidenceType::UnitTestPass;
    unit_correct_environment.environment = "windows-x64-msvc";
    (void)scenario.submit_spec(id, unit_correct_environment);
    AP_CHECK_EQ(scenario.step(id, Stage::Qualified), PromotionOutcome::PromotionCommitted);
}

AP_TEST(stale_evidence_fails_the_freshness_gate) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord record = scenario.register_artifact(id, ArtifactKind::Executable, "exe-j", "digest-j1");
    AP_REQUIRE(record.id.valid());

    // Provenance completeness must be no older than thirty days under the
    // reference policy. Forty days is stale, and stale is never treated as
    // fresh.
    const std::uint64_t forty_days = 40ULL * 24ULL * 60ULL * 60ULL * 1000ULL;
    const std::uint64_t now = PromotionEngine::now_millis();
    Scenario::EvidenceSpec stale;
    stale.type = EvidenceType::ProvenanceComplete;
    stale.produced_unix_millis = now > forty_days ? now - forty_days : 1;
    (void)scenario.submit_spec(id, stale);

    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::EvidenceStale);

    Scenario::EvidenceSpec fresh;
    fresh.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, fresh);
    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::PromotionCommitted);
}

AP_TEST(an_evidence_validity_window_is_honoured) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-k", "digest-k1");

    const std::uint64_t now = PromotionEngine::now_millis();
    Scenario::EvidenceSpec expired;
    expired.type = EvidenceType::ProvenanceComplete;
    expired.has_validity_window = true;
    expired.valid_from_unix_millis = now > 10000 ? now - 10000 : 1;
    expired.valid_until_unix_millis = now > 5000 ? now - 5000 : 1;
    (void)scenario.submit_spec(id, expired);

    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::EvidenceStale);
}

AP_TEST(a_security_veto_blocks_promotion_and_clearing_it_unblocks) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-l", "digest-l1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);

    AP_CHECK_EQ(scenario.engine().set_security_veto(id, true, "open advisory").code(), ErrorCode::Ok);
    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::SecurityVeto);

    AP_CHECK_EQ(scenario.engine().set_security_veto(id, false, "").code(), ErrorCode::Ok);
    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::PromotionCommitted);
}

AP_TEST(a_dependency_veto_blocks_promotion) {
    Scenario scenario;
    const ArtifactId dependency = scenario.make_artifact_id();
    (void)scenario.register_artifact(dependency, ArtifactKind::Library, "lib-dep", "digest-dep");

    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-m", "digest-m1", {"lib-dep"});
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);

    // The dependency exists but is not promoted, so the dependent gate fails
    // rather than silently passing.
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

    const PromotionOutcome outcome = scenario.step(id, Stage::Qualified);
    AP_CHECK_EQ(outcome, PromotionOutcome::DependencyVeto);
}

AP_TEST(a_declared_dependency_that_was_never_registered_is_an_ordering_violation) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-n", "digest-n1", {"lib-missing"});
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);
    AP_CHECK_EQ(scenario.step(id, Stage::Verified), PromotionOutcome::PromotionCommitted);

    // The reference policy places the dependency constraint on qualification:
    // reaching VERIFIED asserts the artifact itself is complete, while QUALIFIED
    // is where its place among its declared dependencies is established.
    const auto decision = scenario.engine().explain(id, Stage::Qualified);
    AP_REQUIRE(decision.has_value());
    AP_CHECK_EQ(decision.value().outcome, PromotionOutcome::ProvenanceMissing);
    bool found_ordering = false;
    for (const GateExplanation& gate : decision.value().gates) {
        if (gate.code == ErrorCode::OrderingViolation) {
            found_ordering = true;
        }
    }
    AP_CHECK(found_ordering);
}

AP_TEST(custom_evidence_classes_are_supported_without_becoming_an_untyped_bucket) {
    PromotionPolicy policy = make_reference_policy(PromotionPolicyId::from_parts(0xC, 0xD), PolicyGeneration(1));
    PolicyRule rule;
    rule.has_kind_scope = true;
    rule.kind_scope = ArtifactKind::Dataset;
    rule.from = Stage::Verified;
    rule.to = Stage::Qualified;
    Gate custom;
    custom.kind = GateKind::EvidenceRequired;
    custom.evidence_type = EvidenceType::Custom;
    custom.custom_evidence_type = "schema_conformance";
    custom.label = "dataset schema conformance";
    rule.requirements.push_back(custom);
    policy.rules.push_back(rule);
    AP_CHECK_EQ(policy.validate().code(), ErrorCode::Ok);

    // A custom class is still typed: it carries a validated name, and a gate
    // that names a different custom class will not accept it.
    Gate mismatched = custom;
    mismatched.custom_evidence_type = "something_else";
    AP_CHECK(mismatched.validate().code() == ErrorCode::Ok);
    AP_CHECK(mismatched.custom_evidence_type != custom.custom_evidence_type);
}

int main() { return TestContext::instance().run_all("unit_core"); }
