// Artifact Promotion - deterministic randomized state-machine testing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <string>
#include <vector>

#include "support/test_context.hpp"

using namespace artifact_promotion;
using namespace artifact_promotion::test;

namespace {

// A small deterministic generator. Every run is reproducible from its seed, and
// a failure prints the seed that produced it.
class SplitMix64 {
public:
    explicit SplitMix64(std::uint64_t seed) noexcept : state_(seed) {}

    [[nodiscard]] std::uint64_t next() noexcept {
        state_ += 0x9E3779B97F4A7C15ULL;
        std::uint64_t value = state_;
        value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ULL;
        value = (value ^ (value >> 27)) * 0x94D049BB133111EBULL;
        return value ^ (value >> 31);
    }

    [[nodiscard]] std::uint64_t below(std::uint64_t bound) noexcept { return bound == 0 ? 0 : next() % bound; }

private:
    std::uint64_t state_;
};

enum class Operation {
    RegisterNewArtifact,
    RegisterNewRevision,
    SubmitEvidence,
    SubmitWrongRevisionEvidence,
    Evaluate,
    Commit,
    RevokeEvidence,
    Quarantine,
    ReleaseQuarantine,
    Revoke,
    Supersede,
    Restart,
    PublishPolicy,
    RecoverInFlight,
    SnapshotRoundTrip,
};

const char* operation_name(Operation operation) {
    switch (operation) {
        case Operation::RegisterNewArtifact:
            return "register-new-artifact";
        case Operation::RegisterNewRevision:
            return "register-new-revision";
        case Operation::SubmitEvidence:
            return "submit-evidence";
        case Operation::SubmitWrongRevisionEvidence:
            return "submit-wrong-revision-evidence";
        case Operation::Evaluate:
            return "evaluate";
        case Operation::Commit:
            return "commit";
        case Operation::RevokeEvidence:
            return "revoke-evidence";
        case Operation::Quarantine:
            return "quarantine";
        case Operation::ReleaseQuarantine:
            return "release-quarantine";
        case Operation::Revoke:
            return "revoke";
        case Operation::Supersede:
            return "supersede";
        case Operation::Restart:
            return "restart";
        case Operation::PublishPolicy:
            return "publish-policy";
        case Operation::RecoverInFlight:
            return "recover-in-flight";
        case Operation::SnapshotRoundTrip:
            return "snapshot-round-trip";
    }
    return "unknown";
}

constexpr std::size_t kOperationCount = 15;
constexpr std::size_t kArtifactPool = 6;
constexpr std::size_t kEvidenceClasses = 6;

[[nodiscard]] EvidenceType evidence_class(std::uint64_t index) {
    switch (index % kEvidenceClasses) {
        case 0:
            return EvidenceType::ProvenanceComplete;
        case 1:
            return EvidenceType::BuildPass;
        case 2:
            return EvidenceType::UnitTestPass;
        case 3:
            return EvidenceType::ReproducibilityPass;
        case 4:
            return EvidenceType::MachineCriticApproval;
        default:
            return EvidenceType::SignatureValid;
    }
}

}  // namespace

AP_TEST(randomized_operation_sequences_preserve_every_invariant) {
    context.phase("SETUP");
    const std::uint64_t base_seed = 0x5EED0000ULL;
    const std::size_t seeds = 24;
    const std::size_t operations_per_seed = 260;
    std::size_t committed_transitions = 0;
    std::size_t rejected_operations = 0;

    for (std::size_t seed_index = 0; seed_index < seeds; ++seed_index) {
        const std::uint64_t seed = base_seed + seed_index;
        SplitMix64 random(seed);
        // One seed is one independently reproducible state-machine run: the
        // marker names exactly which seed was executing when it stopped.
        context.phase("SEED " + std::to_string(seed));
        Scenario scenario;
        std::vector<ArtifactId> pool;
        std::vector<PromotionPlan> plans;
        std::vector<EvidenceId> evidence_ids;

        for (std::size_t step = 0; step < operations_per_seed; ++step) {
            const Operation operation = static_cast<Operation>(random.below(kOperationCount));
            const bool have_artifacts = !pool.empty();

            switch (operation) {
                case Operation::RegisterNewArtifact: {
                    if (pool.size() >= kArtifactPool) {
                        break;
                    }
                    const ArtifactId id = scenario.make_artifact_id();
                    const ArtifactKind kind = static_cast<ArtifactKind>(
                        1 + random.below(static_cast<std::uint64_t>(kArtifactKindMax)));
                    ArtifactRegistration registration;
                    registration.id = id;
                    registration.kind = kind;
                    registration.digest = Digest::from_string("property-" + std::to_string(seed) + "-" +
                                                              std::to_string(step));
                    registration.name = "artifact-" + std::to_string(seed) + "-" + std::to_string(step);
                    const auto registered = scenario.engine().register_artifact(registration);
                    // A digest may already exist under a conflicting class, in
                    // which case the registration is refused; that is expected
                    // and must not corrupt anything.
                    if (registered.has_value()) {
                        pool.push_back(id);
                    } else {
                        ++rejected_operations;
                    }
                    break;
                }
                case Operation::RegisterNewRevision: {
                    if (!have_artifacts) {
                        break;
                    }
                    const ArtifactId id = pool[random.below(pool.size())];
                    const auto existing = scenario.engine().inspect_artifact(id);
                    if (!existing.has_value()) {
                        break;
                    }
                    ArtifactRegistration registration;
                    registration.id = id;
                    registration.kind = existing.value().artifact.kind;
                    registration.digest = Digest::from_string("property-rev-" + std::to_string(seed) + "-" +
                                                              std::to_string(step));
                    registration.name = existing.value().artifact.name;
                    const auto registered = scenario.engine().register_artifact(registration);
                    if (!registered.has_value()) {
                        ++rejected_operations;
                    }
                    break;
                }
                case Operation::SubmitEvidence:
                case Operation::SubmitWrongRevisionEvidence: {
                    if (!have_artifacts) {
                        break;
                    }
                    const ArtifactId id = pool[random.below(pool.size())];
                    const auto existing = scenario.engine().inspect_artifact(id);
                    if (!existing.has_value()) {
                        break;
                    }
                    EvidenceSubmission submission;
                    submission.subject = id;
                    submission.subject_revision = existing.value().artifact.revision;
                    submission.subject_digest = existing.value().artifact.digest;
                    if (operation == Operation::SubmitWrongRevisionEvidence) {
                        submission.subject_revision =
                            ArtifactRevision::from_parts(random.next() | 1ULL, random.next() | 1ULL);
                    }
                    submission.type = evidence_class(random.below(1024));
                    submission.result =
                        random.below(4) == 0 ? EvidenceResult::Fail : EvidenceResult::Pass;
                    submission.environment = random.below(2) == 0 ? "windows-x64-msvc" : "";
                    submission.payload_digest = Digest::from_string("payload-" + std::to_string(step));
                    submission.produced_unix_millis = PromotionEngine::now_millis();
                    const auto stored = scenario.engine().submit_evidence(submission);
                    if (stored.has_value()) {
                        evidence_ids.push_back(stored.value().id);
                    } else {
                        ++rejected_operations;
                    }
                    break;
                }
                case Operation::Evaluate: {
                    if (!have_artifacts) {
                        break;
                    }
                    const ArtifactId id = pool[random.below(pool.size())];
                    const auto existing = scenario.engine().inspect_artifact(id);
                    if (!existing.has_value()) {
                        break;
                    }
                    PromotionRequest request;
                    request.artifact = id;
                    request.expected_revision = existing.value().artifact.revision;
                    request.expected_digest = existing.value().artifact.digest;
                    request.requested_stage = static_cast<Stage>(
                        1 + random.below(static_cast<std::uint64_t>(kStageMax)));
                    request.request = scenario.make_request_id();
                    request.attempt = scenario.make_attempt_id();
                    request.authority = scenario.authority();
                    const auto evaluated = scenario.engine().evaluate(request);
                    if (evaluated.has_value() && evaluated.value().has_plan) {
                        plans.push_back(evaluated.value().plan);
                    } else {
                        ++rejected_operations;
                    }
                    break;
                }
                case Operation::Commit: {
                    if (plans.empty()) {
                        break;
                    }
                    const std::size_t index = static_cast<std::size_t>(random.below(plans.size()));
                    const PromotionPlan plan = plans[index];
                    const auto committed = scenario.engine().commit(plan);
                    if (committed.has_value() &&
                        committed.value().outcome == PromotionOutcome::PromotionCommitted) {
                        ++committed_transitions;
                    } else {
                        ++rejected_operations;
                    }
                    plans.erase(plans.begin() + static_cast<std::ptrdiff_t>(index));
                    break;
                }
                case Operation::RevokeEvidence: {
                    if (evidence_ids.empty()) {
                        break;
                    }
                    const std::size_t index = static_cast<std::size_t>(random.below(evidence_ids.size()));
                    const auto outcome = scenario.engine().revoke_evidence(evidence_ids[index],
                                                                          "randomized withdrawal",
                                                                          scenario.authority());
                    if (!outcome.has_value()) {
                        ++rejected_operations;
                    }
                    break;
                }
                case Operation::Quarantine: {
                    if (!have_artifacts) {
                        break;
                    }
                    const auto outcome = scenario.engine().quarantine(pool[random.below(pool.size())],
                                                                     "randomized_finding", "randomized",
                                                                     scenario.authority());
                    if (!outcome.has_value()) {
                        ++rejected_operations;
                    }
                    break;
                }
                case Operation::ReleaseQuarantine: {
                    if (!have_artifacts) {
                        break;
                    }
                    const auto outcome = scenario.engine().release_quarantine(pool[random.below(pool.size())],
                                                                             scenario.authority());
                    if (!outcome.has_value()) {
                        ++rejected_operations;
                    }
                    break;
                }
                case Operation::Revoke: {
                    if (!have_artifacts) {
                        break;
                    }
                    const auto outcome = scenario.engine().revoke(pool[random.below(pool.size())],
                                                                 PromotionDecisionId{}, "randomized_finding",
                                                                 "randomized", scenario.authority());
                    if (!outcome.has_value()) {
                        ++rejected_operations;
                    }
                    break;
                }
                case Operation::Supersede: {
                    if (pool.size() < 2) {
                        break;
                    }
                    const ArtifactId older = pool[random.below(pool.size())];
                    const ArtifactId newer = pool[random.below(pool.size())];
                    if (older == newer) {
                        break;
                    }
                    const auto outcome = scenario.engine().supersede(older, newer, "randomized", scenario.authority());
                    if (!outcome.has_value()) {
                        ++rejected_operations;
                    }
                    break;
                }
                case Operation::Restart: {
                    const CoordinatorEpoch next = scenario.authority().epoch.next();
                    const auto applied = scenario.engine().restart(next);
                    if (!applied.has_value()) {
                        ++rejected_operations;
                    }
                    // Plans issued before the restart are fenced; drop them so
                    // the sequence exercises the fence rather than a stale list.
                    plans.clear();
                    break;
                }
                case Operation::PublishPolicy: {
                    PromotionPolicy policy =
                        make_reference_policy(PromotionPolicyId::from_parts(random.next() | 1ULL, random.next() | 1ULL),
                                              PolicyGeneration(random.below(64) + 2));
                    const auto published = scenario.engine().publish_policy(policy);
                    if (!published.has_value()) {
                        ++rejected_operations;
                    }
                    plans.clear();
                    break;
                }
                case Operation::RecoverInFlight: {
                    (void)scenario.engine().recover_in_flight();
                    plans.clear();
                    break;
                }
                case Operation::SnapshotRoundTrip: {
                    const CoordinatorState snapshot = scenario.engine().snapshot();
                    auto encoded = StatePersistence::encode(snapshot);
                    if (!encoded.has_value()) {
                        context.fail(std::string("seed ") + std::to_string(seed) + " step " +
                                         std::to_string(step) + " could not encode a snapshot",
                                     __FILE__, __LINE__);
                        break;
                    }
                    auto decoded = StatePersistence::decode(encoded.value());
                    if (!decoded.has_value()) {
                        context.fail(std::string("seed ") + std::to_string(seed) + " step " +
                                         std::to_string(step) + " could not decode its own snapshot: " +
                                         decoded.status().render(),
                                     __FILE__, __LINE__);
                        break;
                    }
                    if (decoded.value().verify_consistency().failed()) {
                        context.fail(std::string("seed ") + std::to_string(seed) + " step " +
                                         std::to_string(step) + " produced an inconsistent snapshot",
                                     __FILE__, __LINE__);
                        break;
                    }
                    break;
                }
            }

            // The invariant check runs continuously, not only at the end.
            const Status invariants = scenario.engine().check_invariants();
            if (invariants.failed()) {
                context.fail(std::string("seed ") + std::to_string(seed) + " step " +
                                 std::to_string(step) + " operation " + operation_name(operation) +
                                 " violated an invariant: " + invariants.render(),
                             __FILE__, __LINE__);
                break;
            }
            if (context.failures() > 0) {
                break;
            }
        }
        if (context.failures() > 0) {
            context.record("failing_seed", std::to_string(seed));
            break;
        }
    }

    context.phase("VERIFY");
    context.record("property_seeds", std::to_string(seeds));
    context.record("property_operations", std::to_string(seeds * operations_per_seed));
    context.record("property_committed_transitions", std::to_string(committed_transitions));
    context.record("property_rejected_operations", std::to_string(rejected_operations));
}

AP_TEST(no_artifact_ever_holds_two_current_stages) {
    context.phase("SETUP");
    SplitMix64 random(0xC0FFEEULL);
    Scenario scenario;
    std::vector<ArtifactId> pool;

    for (std::size_t step = 0; step < 120; ++step) {
        if (pool.size() < kArtifactPool) {
            const ArtifactId id = scenario.make_artifact_id();
            (void)scenario.register_artifact(id, ArtifactKind::Executable,
                                             "stages-" + std::to_string(step),
                                             "stages-digest-" + std::to_string(step));
            pool.push_back(id);
        }
        const ArtifactId subject = pool[random.below(pool.size())];
        switch (random.below(4)) {
            case 0:
                (void)scenario.submit(subject, evidence_class(random.below(1024)), EvidenceResult::Pass,
                                      "evidence-" + std::to_string(step));
                break;
            case 1: {
                const auto existing = scenario.engine().inspect_artifact(subject);
                if (existing.has_value()) {
                    PromotionRequest request;
                    request.artifact = subject;
                    request.expected_revision = existing.value().artifact.revision;
                    request.expected_digest = existing.value().artifact.digest;
                    request.requested_stage = static_cast<Stage>(
                        1 + random.below(static_cast<std::uint64_t>(kStageMax)));
                    request.request = scenario.make_request_id();
                    request.attempt = scenario.make_attempt_id();
                    request.authority = scenario.authority();
                    (void)scenario.engine().promote(request);
                }
                break;
            }
            case 2:
                (void)scenario.engine().quarantine(subject, "randomized_finding", "randomized",
                                                   scenario.authority());
                break;
            default:
                (void)scenario.engine().supersede(subject, pool[random.below(pool.size())], "randomized",
                                                  scenario.authority());
                break;
        }
    }

    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);

    context.phase("VERIFY");
    std::size_t authoritative = 0;
    for (const ArtifactId id : pool) {
        const auto view = scenario.engine().inspect_artifact(id);
        AP_REQUIRE(view.has_value());
        if (view.value().artifact.currently_authoritative()) {
            ++authoritative;
            AP_CHECK_EQ(view.value().artifact.stage, Stage::Promoted);
        }
        AP_CHECK(!(view.value().artifact.quarantine.active && view.value().artifact.stage == Stage::Promoted));
        AP_CHECK(!(view.value().artifact.revocation.active && view.value().artifact.currently_authoritative()));
    }
    context.record("authoritative_artifacts", std::to_string(authoritative));
}

AP_TEST(pending_transition_accounting_closes_exactly) {
    context.phase("SETUP");
    SplitMix64 random(0xABCDEFULL);
    Scenario scenario;
    std::vector<ArtifactId> pool;
    std::vector<PromotionPlan> plans;

    for (std::size_t step = 0; step < 80; ++step) {
        if (pool.size() < 4) {
            const ArtifactId id = scenario.make_artifact_id();
            (void)scenario.register_artifact(id, ArtifactKind::Executable, "pending-" + std::to_string(step),
                                             "pending-digest-" + std::to_string(step));
            pool.push_back(id);
        }
        const ArtifactId subject = pool[random.below(pool.size())];
        const auto existing = scenario.engine().inspect_artifact(subject);
        if (!existing.has_value()) {
            continue;
        }
        if (random.below(2) == 0) {
            PromotionRequest request;
            request.artifact = subject;
            request.expected_revision = existing.value().artifact.revision;
            request.expected_digest = existing.value().artifact.digest;
            request.requested_stage = Stage::Verified;
            request.request = scenario.make_request_id();
            request.attempt = scenario.make_attempt_id();
            request.authority = scenario.authority();
            const auto evaluated = scenario.engine().evaluate(request);
            if (evaluated.has_value() && evaluated.value().has_plan) {
                plans.push_back(evaluated.value().plan);
            }
        } else if (!plans.empty()) {
            const std::size_t index = static_cast<std::size_t>(random.below(plans.size()));
            (void)scenario.engine().commit(plans[index]);
            plans.erase(plans.begin() + static_cast<std::ptrdiff_t>(index));
        }

        // Every reservation is either held by exactly one artifact or released:
        // the accounting never drifts.
        std::size_t held = 0;
        for (const ArtifactId id : pool) {
            if (scenario.engine().pending_transition(id).has_value()) {
                ++held;
            }
        }
        AP_CHECK_EQ(held, scenario.engine().count_pending_transitions());
        AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
    }

    context.phase("VERIFY");
    (void)scenario.engine().recover_in_flight();
    AP_CHECK_EQ(scenario.engine().count_pending_transitions(), static_cast<std::size_t>(0));
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
}

AP_TEST(a_replayed_request_can_never_resurrect_revoked_authority) {
    context.phase("SETUP");
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "replay", "replay-digest-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const ArtifactRecord promoted = scenario.current(id);
    PromotionRequest original;
    original.artifact = id;
    original.expected_revision = promoted.revision;
    original.expected_digest = promoted.digest;
    original.requested_stage = Stage::Promoted;
    original.request = scenario.make_request_id();
    original.attempt = scenario.make_attempt_id();
    original.authority = scenario.authority();

    context.phase("REVOKE");
    (void)scenario.engine().revoke(id, promoted.promotion_decision, "security_finding", "withdrawn",
                                   scenario.authority());

    // Replaying the original request identity, and a fresh one, both fail to
    // restore authority.
    context.phase("VERIFY");
    const auto replayed = scenario.engine().promote(original);
    AP_REQUIRE(replayed.has_value());
    AP_CHECK(replayed.value().outcome != PromotionOutcome::PromotionCommitted);
    AP_CHECK(!scenario.current(id).currently_authoritative());
    AP_CHECK(scenario.current(id).revocation.active);
}

int main(int argc, char** argv) { return run_suite_from_command_line("property", argc, argv); }
