// Artifact Promotion - genuine concurrency and authority race tests.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Every case in this file runs real operating-system threads that overlap in
// time. Nothing here is a sequential loop wearing a concurrency label, no case
// carries a lifetime limit, and every assertion is a consequence of a stated
// runtime invariant rather than of a lucky thread schedule: a check that only
// holds because one thread happened to run first does not belong in a test.
//
// Proof label: REAL threads in one process against one PromotionEngine.
//
// NOTE ON AP_REQUIRE: the macro expands to AP_CHECK(expression) followed by
// if (!(expression)) return, so its argument is evaluated TWICE. Every helper
// call with an effect is therefore evaluated once into a local and only the
// stored result is required; a second evaluation would silently end the test
// body with no failure recorded.

#include <array>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "support/test_context.hpp"

using namespace artifact_promotion;
using namespace artifact_promotion::test;

namespace {

// ---------------------------------------------------------------------------
// Thread-owned identity sources
//
// IdentityGenerator is a plain monotonic counter: it is deliberately not a
// shared object. Each worker owns its own generators with a distinct salt, so
// two threads minting identities concurrently can never collide, and no
// generator is ever touched by two threads.
// ---------------------------------------------------------------------------
struct ThreadIdentities {
    IdentityGenerator<PromotionRequestIdTag> requests;
    IdentityGenerator<PromotionAttemptIdTag> attempts;

    explicit ThreadIdentities(std::uint64_t salt) noexcept
        : requests(salt), attempts(salt ^ 0x9E3779B97F4A7C15ULL) {}
};

// The typed verdict of one governed call. A refused call (a Status) is kept
// distinct from a call that returned a decision, because "the coordinator said
// no" and "the coordinator answered ineligible" are different facts.
struct AttemptRecord {
    // InternalError is the "no call has reported yet" sentinel: a slot that is
    // never written is reported as a failure rather than as a quiet success.
    ErrorCode status = ErrorCode::InternalError;
    PromotionOutcome outcome = PromotionOutcome::Invalid;
    PromotionDecisionId decision{};
    bool has_record = false;
};

struct TrustAttempt {
    ErrorCode status = ErrorCode::InternalError;
    PromotionOutcome outcome = PromotionOutcome::Invalid;
};

// Runs one trust mutation and captures its typed verdict. The callable is
// evaluated on the calling thread.
template <typename Call>
TrustAttempt run_trust(Call&& call) {
    TrustAttempt attempt;
    auto mutation = call();
    if (!mutation.has_value()) {
        attempt.status = mutation.status().code();
        return attempt;
    }
    attempt.status = ErrorCode::Ok;
    attempt.outcome = mutation.value().outcome;
    return attempt;
}

// ---------------------------------------------------------------------------
// Shared driving helpers
// ---------------------------------------------------------------------------

// One PASS record per evidence class the reference policy can require, so that
// the work under test is the authority race rather than evidence collection.
// Submission is itself a governed mutation and happens before the racing
// threads start unless a test explicitly wants it concurrent.
constexpr std::array<EvidenceType, 9> kReferenceEvidencePlan = {
    EvidenceType::ProvenanceComplete,  EvidenceType::BuildPass,       EvidenceType::UnitTestPass,
    EvidenceType::IntegrationTestPass, EvidenceType::ModelEvalPass,   EvidenceType::DataValidationPass,
    EvidenceType::ReproducibilityPass, EvidenceType::MachineCriticApproval, EvidenceType::SignatureValid};

constexpr std::array<Stage, 5> kPromotionChain = {Stage::Verified, Stage::Qualified, Stage::Staged,
                                                 Stage::Approved, Stage::Promoted};

Status submit_reference_evidence(Scenario& scenario, ArtifactId id, bool include_signature = true) {
    for (const EvidenceType type : kReferenceEvidencePlan) {
        if (type == EvidenceType::SignatureValid && !include_signature) {
            continue;
        }
        Scenario::EvidenceSpec spec;
        spec.type = type;
        spec.result = EvidenceResult::Pass;
        if (type == EvidenceType::UnitTestPass) {
            spec.environment = "windows-x64-msvc";
        }
        const EvidenceRecord stored = scenario.submit_spec(id, spec);
        if (!stored.valid()) {
            return Status(ErrorCode::EvidenceMissing, "reference evidence submission was refused",
                          std::string(to_string(type)));
        }
    }
    return Status::success();
}

// One governed promotion attempt with caller-supplied identities, so the same
// code path can serve a main-thread drive and a racing worker.
AttemptRecord promote_with_identity(Scenario& scenario, ArtifactId id, Stage destination,
                                    PromotionRequestId request, PromotionAttemptId attempt) {
    AttemptRecord result;
    const ArtifactRecord artifact = scenario.current(id);
    PromotionRequest promotion;
    promotion.artifact = id;
    promotion.expected_revision = artifact.revision;
    promotion.expected_digest = artifact.digest;
    promotion.requested_stage = destination;
    promotion.request = request;
    promotion.attempt = attempt;
    promotion.authority = scenario.engine().authority();

    auto committed = scenario.engine().promote(promotion);
    if (!committed) {
        result.status = committed.status().code();
        return result;
    }
    result.status = ErrorCode::Ok;
    result.outcome = committed.value().outcome;
    result.decision = committed.value().decision.id;
    result.has_record = committed.value().has_record;
    return result;
}

AttemptRecord promote_once(Scenario& scenario, ArtifactId id, Stage destination, ThreadIdentities& identities) {
    return promote_with_identity(scenario, id, destination, identities.requests.next(), identities.attempts.next());
}

// Advances one artifact along the canonical chain, one governed transaction at
// a time, using identities owned by the calling thread.
Status advance_through(Scenario& scenario, ArtifactId id, Stage target, ThreadIdentities& identities) {
    for (const Stage stage : kPromotionChain) {
        const AttemptRecord attempt = promote_once(scenario, id, stage, identities);
        if (attempt.status != ErrorCode::Ok) {
            return Status(attempt.status, "the promotion call was refused by the coordinator",
                          std::string(to_string(stage)));
        }
        if (attempt.outcome != PromotionOutcome::PromotionCommitted) {
            return Status(ErrorCode::PolicyViolation, "the artifact did not advance to the requested stage",
                          std::string(to_string(stage)));
        }
        if (stage == target) {
            return Status::success();
        }
    }
    return Status(ErrorCode::InvalidStage, "the requested stage is not on the promotion chain");
}

// Registers one artifact revision without touching the Scenario identity
// generators, so it can be called from a worker thread.
Result<ArtifactRecord> register_revision(PromotionEngine& engine, ArtifactId id, std::string name,
                                         std::string digest_seed, ArtifactKind kind) {
    ArtifactRegistration registration;
    registration.id = id;
    registration.kind = kind;
    registration.digest = Digest::from_string(digest_seed);
    registration.size_bytes = 2048;
    registration.name = std::move(name);

    ProvenanceRecord provenance;
    provenance.reference = ProvenanceRef::from_parts(id.high(), id.low());
    provenance.source = "research-ledger";
    provenance.subject = "ledger:" + id.to_string();
    provenance.resolution = ProvenanceResolution::Resolved;
    registration.provenance.push_back(provenance);
    return engine.register_artifact(registration);
}

// Submits one evidence record against the current revision of an artifact,
// reading the revision through the engine so it is safe on a worker thread.
std::size_t submit_current_evidence(PromotionEngine& engine, ArtifactId id, EvidenceType type,
                                    std::uint64_t salt) {
    const auto view = engine.inspect_artifact(id);
    if (!view.has_value()) {
        return 1;
    }
    EvidenceSubmission submission;
    submission.subject = id;
    submission.subject_revision = view.value().artifact.revision;
    submission.subject_digest = view.value().artifact.digest;
    submission.type = type;
    submission.result = EvidenceResult::Pass;
    submission.confidence_milli = 900;
    submission.measurement = "concurrent-reader-writer";
    submission.detail = "submitted while reader threads were reading engine state";
    submission.payload_digest = Digest::from_string("payload:" + id.to_string() + ":" + std::to_string(salt) + ":" +
                                                    std::to_string(static_cast<unsigned>(type)));
    submission.produced_unix_millis = PromotionEngine::now_millis();
    return engine.submit_evidence(submission).has_value() ? 0 : 1;
}

std::size_t count_authoritative(Scenario& scenario, const std::vector<ArtifactId>& ids) {
    std::size_t authoritative = 0;
    for (const ArtifactId id : ids) {
        if (scenario.current(id).currently_authoritative()) {
            ++authoritative;
        }
    }
    return authoritative;
}

std::optional<PromotionRecord> committed_promotion(Scenario& scenario, ArtifactId id, ArtifactRevision revision) {
    for (const PromotionRecord& record : scenario.engine().promotion_history(id)) {
        if (record.artifact_revision == revision && record.to == Stage::Promoted) {
            return record;
        }
    }
    return std::nullopt;
}

std::size_t count_committed_promotions(Scenario& scenario, ArtifactId id, ArtifactRevision revision) {
    std::size_t count = 0;
    for (const PromotionRecord& record : scenario.engine().promotion_history(id)) {
        if (record.artifact_revision == revision && record.to == Stage::Promoted) {
            ++count;
        }
    }
    return count;
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. Different request identities, one artifact, one destination stage.
//
// Only one authority-granting transition may commit. The losers are not
// queued and not silently retried: they observe a conflict, a lost reservation,
// or an artifact that is already promoted.
// ---------------------------------------------------------------------------
AP_TEST(duplicate_promotion_race) {
    constexpr std::size_t kThreads = 16;

    Scenario scenario;
    ThreadIdentities setup(0x1111ULL);
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord registered =
        scenario.register_artifact(id, ArtifactKind::Library, "race-artifact-one", "digest-race-one");
    AP_REQUIRE(registered.id.valid());
    const Status evidence_submitted = submit_reference_evidence(scenario, id);
    AP_REQUIRE(evidence_submitted.ok());
    const Status driven = advance_through(scenario, id, Stage::Approved, setup);
    AP_REQUIRE(driven.ok());
    const ArtifactRevision revision = scenario.current(id).revision;

    std::array<AttemptRecord, kThreads> results{};
    std::barrier<> start_line(static_cast<std::ptrdiff_t>(kThreads));
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (std::size_t index = 0; index < kThreads; ++index) {
        workers.emplace_back([&scenario, &results, &start_line, id, index]() {
            // Every thread owns a distinct salt, so every thread presents a
            // different request identity for the same artifact and stage.
            ThreadIdentities identities(0x1000ULL + index * 0x40ULL + 1ULL);
            start_line.arrive_and_wait();
            results[index] = promote_once(scenario, id, Stage::Promoted, identities);
        });
    }
    for (std::thread& worker : workers) {
        worker.join();
    }

    std::size_t committed_records = 0;
    std::size_t refused = 0;
    std::size_t non_committing = 0;
    for (const AttemptRecord& slot : results) {
        if (slot.status != ErrorCode::Ok) {
            ++refused;
            continue;
        }
        if (slot.has_record) {
            ++committed_records;
            continue;
        }
        const bool acceptable = slot.outcome == PromotionOutcome::Conflict ||
                                slot.outcome == PromotionOutcome::AlreadyPromoted ||
                                slot.outcome == PromotionOutcome::PromotionIneligible ||
                                slot.outcome == PromotionOutcome::RevalidationRequired ||
                                slot.outcome == PromotionOutcome::TransitionIllegal;
        if (acceptable) {
            ++non_committing;
        }
    }

    const ArtifactRecord final_record = scenario.current(id);
    AP_CHECK_EQ(refused, static_cast<std::size_t>(0));
    AP_CHECK_EQ(committed_records, static_cast<std::size_t>(1));
    AP_CHECK_EQ(committed_records + non_committing, kThreads);
    AP_CHECK_EQ(final_record.stage, Stage::Promoted);
    AP_CHECK(final_record.currently_authoritative());
    AP_CHECK_EQ(count_committed_promotions(scenario, id, revision), static_cast<std::size_t>(1));
    AP_CHECK_EQ(scenario.engine().count_pending_transitions(), static_cast<std::size_t>(0));
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);

    context.record("duplicate_promotion_race.threads", std::to_string(kThreads));
    context.record("duplicate_promotion_race.committed_records", std::to_string(committed_records));
    context.record("duplicate_promotion_race.non_committing_outcomes", std::to_string(non_committing));
}

// ---------------------------------------------------------------------------
// 2. Same request identity, identical content, many concurrent callers.
//
// Idempotency is a property of request identity, not of timing: every caller
// must be answered with the same decision identity, and exactly one promotion
// record may exist.
// ---------------------------------------------------------------------------
AP_TEST(duplicate_request_identity_race) {
    constexpr std::size_t kThreads = 12;

    Scenario scenario;
    ThreadIdentities setup(0x2222ULL);
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord registered =
        scenario.register_artifact(id, ArtifactKind::Library, "race-artifact-two", "digest-race-two");
    AP_REQUIRE(registered.id.valid());
    const Status evidence_submitted = submit_reference_evidence(scenario, id);
    AP_REQUIRE(evidence_submitted.ok());
    const Status driven = advance_through(scenario, id, Stage::Approved, setup);
    AP_REQUIRE(driven.ok());
    const ArtifactRevision revision = scenario.current(id).revision;

    const PromotionRequestId shared_request = scenario.make_request_id();
    const PromotionAttemptId shared_attempt = scenario.make_attempt_id();

    std::array<AttemptRecord, kThreads> results{};
    std::barrier<> start_line(static_cast<std::ptrdiff_t>(kThreads));
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (std::size_t index = 0; index < kThreads; ++index) {
        workers.emplace_back([&scenario, &results, &start_line, id, shared_request, shared_attempt, index]() {
            start_line.arrive_and_wait();
            results[index] =
                promote_with_identity(scenario, id, Stage::Promoted, shared_request, shared_attempt);
        });
    }
    for (std::thread& worker : workers) {
        worker.join();
    }

    std::size_t committed_records = 0;
    std::size_t replays = 0;
    std::size_t eligible_replays = 0;
    std::size_t refused = 0;
    bool same_decision = true;
    PromotionDecisionId observed{};
    bool observed_set = false;
    for (const AttemptRecord& slot : results) {
        if (slot.status != ErrorCode::Ok) {
            ++refused;
            continue;
        }
        if (slot.has_record) {
            ++committed_records;
        } else if (slot.outcome == PromotionOutcome::PromotionCommitted) {
            ++replays;
        } else if (slot.outcome == PromotionOutcome::PromotionEligible) {
            ++eligible_replays;
        }
        if (!slot.decision.valid()) {
            same_decision = false;
        } else if (!observed_set) {
            observed = slot.decision;
            observed_set = true;
        } else if (!(slot.decision == observed)) {
            same_decision = false;
        }
    }

    const ArtifactRecord final_record = scenario.current(id);
    const std::optional<PromotionRecord> committed = committed_promotion(scenario, id, revision);
    AP_REQUIRE(committed.has_value());
    AP_CHECK_EQ(refused, static_cast<std::size_t>(0));
    AP_CHECK_EQ(committed_records, static_cast<std::size_t>(1));
    AP_CHECK_EQ(committed_records + replays + eligible_replays, kThreads);
    AP_CHECK(same_decision);
    AP_CHECK(observed_set);
    AP_CHECK(observed == committed.value().decision);
    AP_CHECK_EQ(final_record.stage, Stage::Promoted);
    AP_CHECK(final_record.currently_authoritative());
    AP_CHECK_EQ(count_committed_promotions(scenario, id, revision), static_cast<std::size_t>(1));
    AP_CHECK_EQ(scenario.engine().count_pending_transitions(), static_cast<std::size_t>(0));
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);

    context.record("duplicate_request_identity_race.threads", std::to_string(kThreads));
    context.record("duplicate_request_identity_race.committed_records", std::to_string(committed_records));
    context.record("duplicate_request_identity_race.decision_replays", std::to_string(replays + eligible_replays));
}

// ---------------------------------------------------------------------------
// 3. Promotion to PROMOTED races revocation of the same artifact.
//
// Whatever the interleaving, the artifact is never simultaneously authoritative
// and revoked: revocation either lands on the committed promotion or the
// promotion never happens.
// ---------------------------------------------------------------------------
AP_TEST(promote_vs_revoke_race) {
    Scenario scenario;
    ThreadIdentities setup(0x3333ULL);
    ThreadIdentities promoter_ids(0x3300ULL);
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord registered =
        scenario.register_artifact(id, ArtifactKind::Library, "race-artifact-three", "digest-race-three");
    AP_REQUIRE(registered.id.valid());
    const Status evidence_submitted = submit_reference_evidence(scenario, id);
    AP_REQUIRE(evidence_submitted.ok());
    const Status driven = advance_through(scenario, id, Stage::Approved, setup);
    AP_REQUIRE(driven.ok());

    AttemptRecord promotion;
    TrustAttempt revocation;
    std::barrier<> start_line(2);
    std::thread promoter([&scenario, &promotion, &start_line, id, &promoter_ids]() {
        start_line.arrive_and_wait();
        promotion = promote_once(scenario, id, Stage::Promoted, promoter_ids);
    });
    std::thread revoker([&scenario, &revocation, &start_line, id]() {
        start_line.arrive_and_wait();
        revocation = run_trust([&scenario, id]() {
            return scenario.engine().revoke(id, PromotionDecisionId{}, "security_finding",
                                            "revoked while a promotion was in flight", scenario.authority());
        });
    });
    promoter.join();
    revoker.join();

    const ArtifactRecord final_record = scenario.current(id);
    const bool committed_during_race =
        promotion.status == ErrorCode::Ok && promotion.outcome == PromotionOutcome::PromotionCommitted;
    const std::size_t promotions = count_committed_promotions(scenario, id, final_record.revision);

    AP_CHECK_EQ(promotion.status, ErrorCode::Ok);
    AP_CHECK_EQ(revocation.status, ErrorCode::Ok);
    AP_CHECK_EQ(revocation.outcome, PromotionOutcome::Revoked);
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
    AP_CHECK(promotions <= static_cast<std::size_t>(1));
    AP_CHECK_EQ(promotions == static_cast<std::size_t>(1), committed_during_race);
    AP_CHECK(!(final_record.revocation.active && final_record.currently_authoritative()));
    AP_CHECK(final_record.currently_authoritative() || final_record.revocation.active);
    if (final_record.revocation.active) {
        AP_CHECK_EQ(final_record.stage, Stage::Revoked);
        AP_CHECK(!final_record.promoted);
    } else {
        AP_CHECK_EQ(final_record.stage, Stage::Promoted);
        AP_CHECK(promotion.has_record);
    }

    context.record("promote_vs_revoke_race.revocation_applied", final_record.revocation.active ? "yes" : "no");
    context.record("promote_vs_revoke_race.promotion_outcome", std::string(to_string(promotion.outcome)));
}

// ---------------------------------------------------------------------------
// 4. Promotion to PROMOTED races quarantine of the same artifact.
//
// Quarantine is reachable from PROMOTED as well as from APPROVED, so both
// orders are legal - but no artifact may ever be quarantined and promoted at
// the same time.
// ---------------------------------------------------------------------------
AP_TEST(promote_vs_quarantine_race) {
    Scenario scenario;
    ThreadIdentities setup(0x4444ULL);
    ThreadIdentities promoter_ids(0x4400ULL);
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord registered =
        scenario.register_artifact(id, ArtifactKind::Library, "race-artifact-four", "digest-race-four");
    AP_REQUIRE(registered.id.valid());
    const Status evidence_submitted = submit_reference_evidence(scenario, id);
    AP_REQUIRE(evidence_submitted.ok());
    const Status driven = advance_through(scenario, id, Stage::Approved, setup);
    AP_REQUIRE(driven.ok());

    AttemptRecord promotion;
    TrustAttempt quarantine;
    std::barrier<> start_line(2);
    std::thread promoter([&scenario, &promotion, &start_line, id, &promoter_ids]() {
        start_line.arrive_and_wait();
        promotion = promote_once(scenario, id, Stage::Promoted, promoter_ids);
    });
    std::thread quarantiner([&scenario, &quarantine, &start_line, id]() {
        start_line.arrive_and_wait();
        quarantine = run_trust([&scenario, id]() {
            return scenario.engine().quarantine(id, "security_finding",
                                                "quarantined while a promotion was in flight",
                                                scenario.authority());
        });
    });
    promoter.join();
    quarantiner.join();

    const ArtifactRecord final_record = scenario.current(id);
    const bool committed_during_race =
        promotion.status == ErrorCode::Ok && promotion.outcome == PromotionOutcome::PromotionCommitted;

    AP_CHECK_EQ(promotion.status, ErrorCode::Ok);
    AP_CHECK_EQ(quarantine.status, ErrorCode::Ok);
    AP_CHECK_EQ(quarantine.outcome, PromotionOutcome::Quarantined);
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
    AP_CHECK(final_record.quarantine.active);
    AP_CHECK(!(final_record.quarantine.active && final_record.stage == Stage::Promoted));
    AP_CHECK(!final_record.currently_authoritative());
    // Quarantine lands either before the commit (nothing was promoted) or
    // after it (the promotion is recorded but no longer authoritative).
    AP_CHECK_EQ(final_record.promoted, committed_during_race);

    context.record("promote_vs_quarantine_race.quarantined", final_record.quarantine.active ? "yes" : "no");
    context.record("promote_vs_quarantine_race.promotion_outcome", std::string(to_string(promotion.outcome)));
}

// ---------------------------------------------------------------------------
// 5. Promotion to PROMOTED races supersession of the same artifact.
//
// Supersession means "a newer artifact is current", not "the older artifact is
// invalid", so both orders are legal. What must hold either way is that the
// artifact never keeps authority after being superseded, and that the engine
// still considers its own state consistent.
// ---------------------------------------------------------------------------
AP_TEST(promote_vs_supersede_race) {
    Scenario scenario;
    ThreadIdentities setup(0x5555ULL);
    ThreadIdentities promoter_ids(0x5500ULL);
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord registered =
        scenario.register_artifact(id, ArtifactKind::Library, "race-artifact-five", "digest-race-five");
    AP_REQUIRE(registered.id.valid());
    const ArtifactId successor = scenario.make_artifact_id();
    const ArtifactRecord successor_record = scenario.register_artifact(
        successor, ArtifactKind::Library, "race-artifact-five-successor", "digest-race-five-successor");
    AP_REQUIRE(successor_record.id.valid());
    const Status evidence_submitted = submit_reference_evidence(scenario, id);
    AP_REQUIRE(evidence_submitted.ok());
    const Status driven = advance_through(scenario, id, Stage::Approved, setup);
    AP_REQUIRE(driven.ok());
    const ArtifactRevision revision = scenario.current(id).revision;

    AttemptRecord promotion;
    TrustAttempt supersession;
    std::barrier<> start_line(2);
    std::thread promoter([&scenario, &promotion, &start_line, id, &promoter_ids]() {
        start_line.arrive_and_wait();
        promotion = promote_once(scenario, id, Stage::Promoted, promoter_ids);
    });
    std::thread superseder([&scenario, &supersession, &start_line, id, successor]() {
        start_line.arrive_and_wait();
        supersession = run_trust([&scenario, id, successor]() {
            return scenario.engine().supersede(id, successor, "replaced while a promotion was in flight",
                                               scenario.authority());
        });
    });
    promoter.join();
    superseder.join();

    const ArtifactRecord final_record = scenario.current(id);
    const Status invariants = scenario.engine().check_invariants();
    const bool committed_during_race =
        promotion.status == ErrorCode::Ok && promotion.outcome == PromotionOutcome::PromotionCommitted;
    const std::size_t promotions = count_committed_promotions(scenario, id, revision);

    AP_CHECK_EQ(promotion.status, ErrorCode::Ok);
    AP_CHECK_EQ(supersession.status, ErrorCode::Ok);
    AP_CHECK_EQ(supersession.outcome, PromotionOutcome::Superseded);
    AP_CHECK(final_record.supersession.active);
    AP_CHECK_EQ(final_record.stage, Stage::Superseded);
    AP_CHECK(!final_record.promoted);
    AP_CHECK(!final_record.currently_authoritative());
    AP_CHECK(promotions <= static_cast<std::size_t>(1));
    AP_CHECK_EQ(promotions == static_cast<std::size_t>(1), committed_during_race);
    AP_CHECK_EQ(invariants.code(), ErrorCode::Ok);
    if (invariants.failed()) {
        context.fail("check_invariants reported: " + invariants.render(), __FILE__, __LINE__);
    }

    // The race above only reaches the supersede-first ordering when the
    // superseding thread wins, so the same obligation is pinned here without a
    // race: superseding a revision that never held promotion authority is still
    // a governed operation, and the engine must consider its own state
    // consistent afterwards.
    Scenario unpromoted_scenario;
    const ArtifactId unpromoted = unpromoted_scenario.make_artifact_id();
    const ArtifactRecord unpromoted_record = unpromoted_scenario.register_artifact(
        unpromoted, ArtifactKind::Library, "race-artifact-five-unpromoted", "digest-race-five-unpromoted");
    AP_REQUIRE(unpromoted_record.id.valid());
    const ArtifactId unpromoted_successor = unpromoted_scenario.make_artifact_id();
    const ArtifactRecord unpromoted_successor_record =
        unpromoted_scenario.register_artifact(unpromoted_successor, ArtifactKind::Library,
                                              "race-artifact-five-unpromoted-successor",
                                              "digest-race-five-unpromoted-successor");
    AP_REQUIRE(unpromoted_successor_record.id.valid());

    // The revision is put in exactly the stage the race uses - APPROVED, one
    // transition short of authority - and is then superseded with no other
    // thread running. Whether the coordinator permits that supersession is a
    // policy decision; what is not a policy decision is that the coordinator's
    // own state stays consistent afterwards.
    ThreadIdentities unpromoted_ids(0x5501ULL);
    const Status unpromoted_evidence = submit_reference_evidence(unpromoted_scenario, unpromoted);
    AP_REQUIRE(unpromoted_evidence.ok());
    const Status unpromoted_drive =
        advance_through(unpromoted_scenario, unpromoted, Stage::Approved, unpromoted_ids);
    AP_REQUIRE(unpromoted_drive.ok());

    const TrustAttempt unpromoted_supersession =
        run_trust([&unpromoted_scenario, unpromoted, unpromoted_successor]() {
            return unpromoted_scenario.engine().supersede(unpromoted, unpromoted_successor,
                                                          "superseded before any promotion",
                                                          unpromoted_scenario.authority());
        });
    const ArtifactRecord unpromoted_after = unpromoted_scenario.current(unpromoted);
    const Status unpromoted_invariants = unpromoted_scenario.engine().check_invariants();

    AP_CHECK(unpromoted_supersession.status == ErrorCode::Ok ||
             unpromoted_supersession.status == ErrorCode::TransitionIllegal);
    AP_CHECK_EQ(unpromoted_after.supersession.active, unpromoted_supersession.status == ErrorCode::Ok);
    AP_CHECK_EQ(unpromoted_invariants.code(), ErrorCode::Ok);
    if (unpromoted_invariants.failed()) {
        context.fail("check_invariants after superseding an unpromoted revision: " + unpromoted_invariants.render(),
                     __FILE__, __LINE__);
    }

    context.record("promote_vs_supersede_race.promotion_outcome", std::string(to_string(promotion.outcome)));
    context.record("promote_vs_supersede_race.invariants", invariants.render());
    context.record("promote_vs_supersede_race.unpromoted_invariants", unpromoted_invariants.render());
    context.record("promote_vs_supersede_race.unpromoted_supersession_status",
                   std::string(to_string(unpromoted_supersession.status)));
}

// ---------------------------------------------------------------------------
// 6. Many readers against concurrent writers.
//
// Readers call the const surface - inspect, history, explain, and the invariant
// checker - while writers register artifacts and submit evidence. A reader must
// never observe a malformed record, a foreign record, or a broken invariant.
// ---------------------------------------------------------------------------
AP_TEST(readers_during_writers) {
    constexpr std::size_t kReaderThreads = 4;
    constexpr std::size_t kWriterThreads = 3;
    constexpr std::size_t kPreRegistered = 4;
    constexpr std::size_t kAdditional = 12;
    constexpr std::size_t kTotal = kPreRegistered + kAdditional;
    constexpr std::size_t kPerWriter = kAdditional / kWriterThreads;

    Scenario scenario;
    std::array<ArtifactId, kTotal> ids{};
    for (std::size_t index = 0; index < kTotal; ++index) {
        ids[index] = scenario.make_artifact_id();
    }
    // Readers must always have something to read, so a first set of artifacts
    // exists before any thread starts.
    for (std::size_t index = 0; index < kPreRegistered; ++index) {
        const ArtifactRecord seeded = scenario.register_artifact(ids[index], ArtifactKind::Library,
                                                                 "reader-writer-" + std::to_string(index),
                                                                 "digest-reader-writer-" + std::to_string(index));
        AP_REQUIRE(seeded.id.valid());
    }

    std::atomic<bool> writers_finished{false};
    std::atomic<std::size_t> reader_checks{0};
    std::atomic<std::size_t> reader_failures{0};
    std::atomic<std::size_t> writer_failures{0};

    std::vector<std::thread> readers;
    readers.reserve(kReaderThreads);
    for (std::size_t reader = 0; reader < kReaderThreads; ++reader) {
        readers.emplace_back([&scenario, &ids, &writers_finished, &reader_checks, &reader_failures, reader]() {
            std::size_t checks = 0;
            std::size_t failures = 0;
            do {
                for (std::size_t step = 0; step < kTotal; ++step) {
                    const ArtifactId id = ids[(step + reader) % kTotal];
                    const auto view = scenario.engine().inspect_artifact(id);
                    ++checks;
                    if (view.has_value() && !view.value().artifact.valid()) {
                        ++failures;
                    }
                    const std::vector<PromotionRecord> history = scenario.engine().promotion_history(id);
                    ++checks;
                    for (const PromotionRecord& record : history) {
                        if (record.artifact != id || !record.valid()) {
                            ++failures;
                        }
                    }
                    const auto explanation = scenario.engine().explain(id, Stage::Promoted);
                    ++checks;
                    if (explanation.has_value() &&
                        (explanation.value().artifact != id || explanation.value().to != Stage::Promoted)) {
                        ++failures;
                    }
                    const std::vector<HistoryEvent> events = scenario.engine().artifact_history(id, 16);
                    ++checks;
                    for (const HistoryEvent& event : events) {
                        if (event.artifact != id) {
                            ++failures;
                        }
                    }
                    ++checks;
                    if (scenario.engine().count_pending_transitions() > kTotal) {
                        ++failures;
                    }
                }
                ++checks;
                if (scenario.engine().check_invariants().failed()) {
                    ++failures;
                }
            } while (!writers_finished.load());
            reader_checks.fetch_add(checks);
            reader_failures.fetch_add(failures);
        });
    }

    std::vector<std::thread> writers;
    writers.reserve(kWriterThreads);
    for (std::size_t writer = 0; writer < kWriterThreads; ++writer) {
        writers.emplace_back([&scenario, &ids, &writer_failures, writer]() {
            std::size_t failures = 0;
            const std::size_t begin = kPreRegistered + writer * kPerWriter;
            const std::size_t end = begin + kPerWriter;
            for (std::size_t index = begin; index < end; ++index) {
                const ArtifactId id = ids[index];
                auto registered =
                    register_revision(scenario.engine(), id, "reader-writer-new-" + std::to_string(index),
                                      "digest-reader-writer-new-" + std::to_string(index), ArtifactKind::Library);
                if (!registered.has_value()) {
                    ++failures;
                    continue;
                }
                failures += submit_current_evidence(scenario.engine(), id, EvidenceType::ProvenanceComplete, index);
                failures += submit_current_evidence(scenario.engine(), id, EvidenceType::BuildPass, index);
            }
            writer_failures.fetch_add(failures);
        });
    }

    for (std::thread& writer : writers) {
        writer.join();
    }
    writers_finished.store(true);
    for (std::thread& reader : readers) {
        reader.join();
    }

    AP_CHECK_EQ(writer_failures.load(), static_cast<std::size_t>(0));
    AP_CHECK_EQ(reader_failures.load(), static_cast<std::size_t>(0));
    AP_CHECK(reader_checks.load() > 0);
    AP_CHECK_EQ(scenario.engine().count_artifacts(), kTotal);
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);

    context.record("readers_during_writers.reader_threads", std::to_string(kReaderThreads));
    context.record("readers_during_writers.writer_threads", std::to_string(kWriterThreads));
    context.record("readers_during_writers.reader_checks", std::to_string(reader_checks.load()));
}

// ---------------------------------------------------------------------------
// 7. Independent promotions scale.
//
// Eight threads each drive a distinct artifact from CANDIDATE to PROMOTED at
// the same time. Every drive must commit, and the runtime must hold exactly the
// authority those commits granted - no more, no less.
// ---------------------------------------------------------------------------
AP_TEST(independent_promotions_scale) {
    constexpr std::size_t kArtifacts = 8;

    Scenario scenario;
    std::array<ArtifactId, kArtifacts> ids{};
    std::array<ArtifactRevision, kArtifacts> revisions{};
    for (std::size_t index = 0; index < kArtifacts; ++index) {
        ids[index] = scenario.make_artifact_id();
        const ArtifactRecord registered =
            scenario.register_artifact(ids[index], ArtifactKind::Executable,
                                       "scale-executable-" + std::to_string(index),
                                       "digest-scale-" + std::to_string(index));
        AP_REQUIRE(registered.id.valid());
        revisions[index] = registered.revision;
    }

    std::array<ErrorCode, kArtifacts> evidence_failures{};
    std::array<ErrorCode, kArtifacts> drive_failures{};

    std::barrier<> start_line(static_cast<std::ptrdiff_t>(kArtifacts));
    std::vector<std::thread> workers;
    workers.reserve(kArtifacts);
    for (std::size_t index = 0; index < kArtifacts; ++index) {
        workers.emplace_back([&scenario, &ids, &evidence_failures, &drive_failures, &start_line, index]() {
            ThreadIdentities identities(0x7000ULL + index * 0x100ULL + 1ULL);
            start_line.arrive_and_wait();
            const Status evidence = submit_reference_evidence(scenario, ids[index]);
            if (evidence.failed()) {
                evidence_failures[index] = evidence.code();
                return;
            }
            const Status driven = advance_through(scenario, ids[index], Stage::Promoted, identities);
            if (driven.failed()) {
                drive_failures[index] = driven.code();
            }
        });
    }
    for (std::thread& worker : workers) {
        worker.join();
    }

    std::vector<ArtifactId> all_ids(ids.begin(), ids.end());
    std::size_t evidence_failed = 0;
    std::size_t drive_failed = 0;
    for (std::size_t index = 0; index < kArtifacts; ++index) {
        if (evidence_failures[index] != ErrorCode::Ok) {
            ++evidence_failed;
        }
        if (drive_failures[index] != ErrorCode::Ok) {
            ++drive_failed;
        }
    }

    AP_CHECK_EQ(evidence_failed, static_cast<std::size_t>(0));
    AP_CHECK_EQ(drive_failed, static_cast<std::size_t>(0));
    AP_CHECK_EQ(scenario.engine().count_artifacts(), kArtifacts);
    AP_CHECK_EQ(count_authoritative(scenario, all_ids), kArtifacts);
    AP_CHECK_EQ(scenario.engine().count_pending_transitions(), static_cast<std::size_t>(0));
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
    for (std::size_t index = 0; index < kArtifacts; ++index) {
        AP_CHECK_EQ(count_committed_promotions(scenario, ids[index], revisions[index]), static_cast<std::size_t>(1));
    }

    context.record("independent_promotions_scale.threads", std::to_string(kArtifacts));
    context.record("independent_promotions_scale.authoritative", std::to_string(count_authoritative(scenario, all_ids)));
}

// ---------------------------------------------------------------------------
// 8. Evidence revocation races the commit that depends on it.
//
// The PROMOTED transition requires SIGNATURE_VALID evidence. Revoking that
// record while the commit is in flight must never let a revoked record satisfy
// a committed transition: either the commit happened first (and the revocation
// carries a later commit sequence), or the commit never happens at all.
// ---------------------------------------------------------------------------
AP_TEST(evidence_revocation_vs_commit) {
    Scenario scenario;
    ThreadIdentities setup(0x8888ULL);
    ThreadIdentities promoter_ids(0x8800ULL);
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord registered =
        scenario.register_artifact(id, ArtifactKind::Library, "race-artifact-eight", "digest-race-eight");
    AP_REQUIRE(registered.id.valid());
    const Status base_evidence = submit_reference_evidence(scenario, id, false);
    AP_REQUIRE(base_evidence.ok());

    Scenario::EvidenceSpec signature;
    signature.type = EvidenceType::SignatureValid;
    const EvidenceRecord signature_record = scenario.submit_spec(id, signature);
    AP_REQUIRE(signature_record.valid());
    const EvidenceId signature_id = signature_record.id;
    const Status driven = advance_through(scenario, id, Stage::Approved, setup);
    AP_REQUIRE(driven.ok());
    const ArtifactRevision revision = scenario.current(id).revision;

    AttemptRecord promotion;
    TrustAttempt revocation;
    std::barrier<> start_line(2);
    std::thread promoter([&scenario, &promotion, &start_line, id, &promoter_ids]() {
        start_line.arrive_and_wait();
        promotion = promote_once(scenario, id, Stage::Promoted, promoter_ids);
    });
    std::thread revoker([&scenario, &revocation, &start_line, signature_id]() {
        start_line.arrive_and_wait();
        revocation = run_trust([&scenario, signature_id]() {
            return scenario.engine().revoke_evidence(signature_id, "producer retracted the signature",
                                                     scenario.authority());
        });
    });
    promoter.join();
    revoker.join();

    const ArtifactRecord final_record = scenario.current(id);
    const std::optional<EvidenceRecord> evidence = scenario.engine().inspect_evidence(signature_id);
    AP_REQUIRE(evidence.has_value());
    const std::optional<PromotionRecord> committed = committed_promotion(scenario, id, revision);

    AP_CHECK_EQ(promotion.status, ErrorCode::Ok);
    AP_CHECK_EQ(revocation.status, ErrorCode::Ok);
    AP_CHECK_EQ(revocation.outcome, PromotionOutcome::EvidenceRevoked);
    AP_CHECK(evidence.value().revoked);
    AP_CHECK(committed.has_value() || !final_record.currently_authoritative());
    if (committed.has_value()) {
        // A committed transition can only be preceded by evidence it was
        // allowed to use: the revocation sequence must be strictly later.
        context.record("evidence_revocation_vs_commit.commit_sequence", committed.value().sequence.to_string());
        context.record("evidence_revocation_vs_commit.revocation_sequence",
                       evidence.value().revocation_sequence.to_string());
        context.record("evidence_revocation_vs_commit.evidence_created_sequence",
                       evidence.value().created_sequence.to_string());
        AP_CHECK(evidence.value().revocation_sequence > committed.value().sequence);
    }
    if (!final_record.currently_authoritative()) {
        // The evidence is gone, so the same transition must now be refused with
        // a typed reason instead of being silently satisfied.
        ThreadIdentities retry_ids(0x8801ULL);
        const AttemptRecord retry = promote_once(scenario, id, Stage::Promoted, retry_ids);
        AP_CHECK_EQ(retry.status, ErrorCode::Ok);
        AP_CHECK_EQ(retry.outcome, PromotionOutcome::EvidenceRevoked);
        AP_CHECK(!retry.has_record);
    }
    AP_CHECK(count_committed_promotions(scenario, id, revision) <= static_cast<std::size_t>(1));
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);

    // The race above only reaches the revoke-first ordering when the revoking
    // thread wins, so the same obligation is pinned here without any race:
    // evidence that is already revoked before the evaluation may not satisfy
    // the gate that exists to require it.
    Scenario revoked_scenario;
    const ArtifactId revoked_id = revoked_scenario.make_artifact_id();
    const ArtifactRecord revoked_registration = revoked_scenario.register_artifact(
        revoked_id, ArtifactKind::Library, "race-artifact-eight-unpromoted", "digest-race-eight-unpromoted");
    AP_REQUIRE(revoked_registration.id.valid());
    const Status revoked_base_evidence = submit_reference_evidence(revoked_scenario, revoked_id, false);
    AP_REQUIRE(revoked_base_evidence.ok());

    Scenario::EvidenceSpec revoked_signature;
    revoked_signature.type = EvidenceType::SignatureValid;
    const EvidenceRecord revoked_signature_record = revoked_scenario.submit_spec(revoked_id, revoked_signature);
    AP_REQUIRE(revoked_signature_record.valid());

    ThreadIdentities revoked_ids(0x8802ULL);
    const Status revoked_drive = advance_through(revoked_scenario, revoked_id, Stage::Approved, revoked_ids);
    AP_REQUIRE(revoked_drive.ok());

    const auto revoked_status = revoked_scenario.engine().revoke_evidence(
        revoked_signature_record.id, "producer retracted the signature", revoked_scenario.authority());
    AP_REQUIRE(revoked_status.has_value());
    const AttemptRecord after_revocation = promote_once(revoked_scenario, revoked_id, Stage::Promoted, revoked_ids);
    AP_CHECK_EQ(after_revocation.status, ErrorCode::Ok);
    AP_CHECK_EQ(after_revocation.outcome, PromotionOutcome::EvidenceRevoked);
    AP_CHECK(!after_revocation.has_record);
    AP_CHECK_EQ(revoked_scenario.engine().check_invariants().code(), ErrorCode::Ok);

    context.record("evidence_revocation_vs_commit.promotion_outcome", std::string(to_string(promotion.outcome)));
    context.record("evidence_revocation_vs_commit.committed", committed.has_value() ? "yes" : "no");
    context.record("evidence_revocation_vs_commit.outcome_after_revocation",
                   std::string(to_string(after_revocation.outcome)));
}

// ---------------------------------------------------------------------------
// 9. Fast result arrival.
//
// A worker completes a promotion while the main thread reads state as fast as
// it can. Readers may observe the pre-commit or the post-commit state, but
// never a torn one, and the reservation accounting must close exactly once the
// worker has returned.
// ---------------------------------------------------------------------------
AP_TEST(fast_result_arrival) {
    Scenario scenario;
    ThreadIdentities setup(0x9999ULL);
    ThreadIdentities worker_ids(0x9900ULL);
    const ArtifactId id = scenario.make_artifact_id();
    const ArtifactRecord registered =
        scenario.register_artifact(id, ArtifactKind::Library, "race-artifact-nine", "digest-race-nine");
    AP_REQUIRE(registered.id.valid());
    const Status evidence_submitted = submit_reference_evidence(scenario, id);
    AP_REQUIRE(evidence_submitted.ok());
    const Status driven = advance_through(scenario, id, Stage::Approved, setup);
    AP_REQUIRE(driven.ok());
    const ArtifactRevision revision = scenario.current(id).revision;

    std::atomic<bool> worker_finished{false};
    AttemptRecord promotion;
    std::thread worker([&scenario, &promotion, &worker_finished, id, &worker_ids]() {
        promotion = promote_once(scenario, id, Stage::Promoted, worker_ids);
        worker_finished.store(true);
    });

    std::size_t queries = 0;
    std::size_t torn = 0;
    do {
        const auto view = scenario.engine().inspect_artifact(id);
        ++queries;
        if (!view.has_value()) {
            ++torn;
        } else {
            const ArtifactRecord& record = view.value().artifact;
            if (!record.valid()) {
                ++torn;
            }
            // Promotion authority and the PROMOTED stage are written together
            // under one lock, so no reader may see one without the other.
            if (record.promoted != (record.stage == Stage::Promoted)) {
                ++torn;
            }
            // Promotion identity, authority, and stage are written inside one
            // critical section, so none of them may appear alone.
            if (record.promoted && !record.promotion_decision.valid()) {
                ++torn;
            }
            if (record.promoted && !record.promotion_authority.valid()) {
                ++torn;
            }
            // Every committed transition has a record, so a torn observation is
            // a second record for the one authority-granting transition.
            const std::vector<PromotionRecord> history = scenario.engine().promotion_history(id);
            ++queries;
            if (count_committed_promotions(scenario, id, revision) > 1) {
                ++torn;
            }
            for (const PromotionRecord& history_entry : history) {
                if (history_entry.artifact != id || !history_entry.valid()) {
                    ++torn;
                }
            }
        }
        const auto pending = scenario.engine().pending_transition(id);
        ++queries;
        if (pending.has_value() && pending.value().artifact != id) {
            ++torn;
        }
        if (scenario.engine().count_pending_transitions() > 1) {
            ++torn;
        }
        if (scenario.engine().check_invariants().failed()) {
            ++torn;
        }
    } while (!worker_finished.load());
    worker.join();

    AP_CHECK_EQ(promotion.status, ErrorCode::Ok);
    AP_CHECK_EQ(promotion.outcome, PromotionOutcome::PromotionCommitted);
    AP_CHECK(promotion.has_record);
    AP_CHECK(torn == 0);
    AP_CHECK(queries > 0);
    AP_CHECK_EQ(scenario.engine().count_pending_transitions(), static_cast<std::size_t>(0));
    AP_CHECK_EQ(count_committed_promotions(scenario, id, revision), static_cast<std::size_t>(1));
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);

    context.record("fast_result_arrival.queries_during_commit", std::to_string(queries));
    context.record("fast_result_arrival.torn_observations", std::to_string(torn));
}

// ---------------------------------------------------------------------------
// 10. Shutdown during active work.
//
// Admission closes while workers are promoting. Governed mutations are then
// refused with ShuttingDown, while the read-only surface keeps answering and
// the invariants keep holding - including for reservations that were already
// held when admission closed.
// ---------------------------------------------------------------------------
AP_TEST(shutdown_during_active_work) {
    constexpr std::size_t kWorkers = 4;

    Scenario scenario;
    std::array<ArtifactId, kWorkers> ids{};
    for (std::size_t index = 0; index < kWorkers; ++index) {
        ids[index] = scenario.make_artifact_id();
        const ArtifactRecord registered =
            scenario.register_artifact(ids[index], ArtifactKind::Library,
                                       "shutdown-artifact-" + std::to_string(index),
                                       "digest-shutdown-" + std::to_string(index));
        AP_REQUIRE(registered.id.valid());
        const Status seeded_evidence = submit_reference_evidence(scenario, ids[index]);
        AP_REQUIRE(seeded_evidence.ok());
    }

    std::array<AttemptRecord, kWorkers> last_attempts{};
    std::atomic<std::size_t> completed{0};
    std::atomic<std::size_t> interrupted{0};
    std::atomic<std::size_t> unexpected{0};

    std::barrier<> start_line(static_cast<std::ptrdiff_t>(kWorkers));
    std::vector<std::thread> workers;
    workers.reserve(kWorkers);
    for (std::size_t index = 0; index < kWorkers; ++index) {
        workers.emplace_back([&scenario, &ids, &last_attempts, &completed, &interrupted, &unexpected, &start_line,
                              index]() {
            ThreadIdentities identities(0xA000ULL + index * 0x100ULL + 1ULL);
            start_line.arrive_and_wait();
            for (const Stage stage : kPromotionChain) {
                const AttemptRecord attempt = promote_once(scenario, ids[index], stage, identities);
                last_attempts[index] = attempt;
                if (attempt.status != ErrorCode::Ok) {
                    interrupted.fetch_add(1);
                    return;
                }
                if (attempt.outcome != PromotionOutcome::PromotionCommitted) {
                    unexpected.fetch_add(1);
                    return;
                }
            }
            completed.fetch_add(1);
        });
    }

    // Admission closes while the workers above are mid-drive.
    scenario.engine().close_admission();

    for (std::thread& worker : workers) {
        worker.join();
    }

    AP_CHECK(!scenario.engine().admission_open());
    AP_CHECK_EQ(unexpected.load(), static_cast<std::size_t>(0));
    AP_CHECK_EQ(completed.load() + interrupted.load(), kWorkers);

    // Governed mutations are refused at the admission boundary.
    ThreadIdentities post_shutdown(0xB000ULL);
    const AttemptRecord refused_promotion = promote_once(scenario, ids[0], Stage::Promoted, post_shutdown);
    AP_CHECK_EQ(refused_promotion.status, ErrorCode::ShuttingDown);

    const ArtifactId fresh = scenario.make_artifact_id();
    const auto refused_registration =
        register_revision(scenario.engine(), fresh, "shutdown-artifact-late", "digest-shutdown-late",
                          ArtifactKind::Library);
    AP_CHECK_EQ(refused_registration.code(), ErrorCode::ShuttingDown);

    const Status refused_quarantine =
        scenario.engine()
            .quarantine(ids[0], "security_finding", "attempted while the coordinator was shutting down",
                        scenario.authority())
            .status();
    AP_CHECK_EQ(refused_quarantine.code(), ErrorCode::ShuttingDown);

    const Status refused_revocation =
        scenario.engine()
            .revoke(ids[0], PromotionDecisionId{}, "security_finding",
                    "attempted while the coordinator was shutting down", scenario.authority())
            .status();
    AP_CHECK_EQ(refused_revocation.code(), ErrorCode::ShuttingDown);

    const Status refused_supersession =
        scenario.engine().supersede(ids[0], ids[1], "attempted while shutting down", scenario.authority()).status();
    AP_CHECK_EQ(refused_supersession.code(), ErrorCode::ShuttingDown);

    const Status refused_evidence_revocation =
        scenario.engine()
            .revoke_evidence(EvidenceId::from_parts(0x1234ULL, 0x5678ULL), "attempted while shutting down",
                             scenario.authority())
            .status();
    AP_CHECK_EQ(refused_evidence_revocation.code(), ErrorCode::ShuttingDown);

    // Readers keep working, and the artifacts the workers left behind are
    // internally consistent.
    std::size_t authoritative = 0;
    std::size_t promotion_records = 0;
    for (const ArtifactId id : ids) {
        const auto view = scenario.engine().inspect_artifact(id);
        AP_CHECK(view.has_value());
        if (!view.has_value()) {
            continue;
        }
        const ArtifactRecord& record = view.value().artifact;
        AP_CHECK(record.valid());
        AP_CHECK(record.promoted == (record.stage == Stage::Promoted));
        if (record.currently_authoritative()) {
            ++authoritative;
        }
        promotion_records += count_committed_promotions(scenario, id, record.revision);
        AP_CHECK(scenario.engine().explain(id, Stage::Promoted).has_value());
        AP_CHECK(scenario.engine().snapshot().coordinator == scenario.engine().coordinator_id());
    }
    AP_CHECK_EQ(authoritative, promotion_records);
    AP_CHECK_EQ(scenario.engine().count_artifacts(), kWorkers);
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);

    context.record("shutdown_during_active_work.completed_drives", std::to_string(completed.load()));
    context.record("shutdown_during_active_work.interrupted_drives", std::to_string(interrupted.load()));
    context.record("shutdown_during_active_work.authoritative_artifacts", std::to_string(authoritative));
}

int main() {
    return TestContext::instance().run_all("concurrency");
}
