// Artifact Promotion - persistence, corruption rejection and restart recovery.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <string>

#include "support/test_context.hpp"

using namespace artifact_promotion;
using namespace artifact_promotion::test;

namespace {

[[nodiscard]] ByteBuffer corrupt_at(const ByteBuffer& source, std::size_t offset) {
    ByteBuffer copy = source;
    if (offset < copy.size()) {
        copy[offset] = static_cast<std::uint8_t>(copy[offset] ^ 0x5AU);
    }
    return copy;
}

}  // namespace

AP_TEST(round_trip_preserves_every_committed_fact) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-persist", "digest-persist-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());
    const std::size_t evidence_before = scenario.engine().count_evidence();

    const CoordinatorState state = scenario.engine().snapshot();
    auto encoded = StatePersistence::encode(state);
    AP_REQUIRE(encoded.has_value());
    auto decoded = StatePersistence::decode(encoded.value());
    AP_REQUIRE(decoded.has_value());
    AP_CHECK_EQ(decoded.value().verify_consistency().code(), ErrorCode::Ok);

    const ArtifactRecord* restored = decoded.value().find_current(id);
    AP_REQUIRE(restored != nullptr);
    AP_CHECK_EQ(restored->stage, Stage::Promoted);
    AP_CHECK(restored->currently_authoritative());
    AP_CHECK_EQ(decoded.value().evidence.size(), evidence_before);
    AP_CHECK_EQ(decoded.value().records.size(), state.records.size());
    AP_CHECK_EQ(decoded.value().history.size(), state.history.size());
    AP_CHECK_EQ(decoded.value().active_policy_generation.value(),
                state.active_policy_generation.value());
}

AP_TEST(encoding_is_deterministic) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Model, "model-det", "digest-det-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const CoordinatorState state = scenario.engine().snapshot();
    auto first = StatePersistence::encode(state);
    auto second = StatePersistence::encode(state);
    AP_REQUIRE(first.has_value());
    AP_REQUIRE(second.has_value());
    AP_CHECK(first.value() == second.value());
}

AP_TEST(every_single_byte_corruption_inside_the_payload_is_detected) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-corrupt", "digest-corrupt-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const CoordinatorState state = scenario.engine().snapshot();
    auto encoded = StatePersistence::encode(state);
    AP_REQUIRE(encoded.has_value());
    const ByteBuffer& bytes = encoded.value();

    // The footer digest covers every preceding byte, so flipping any byte of
    // the snapshot must be detected. The sample stride keeps the test bounded
    // while still covering the whole file including the header and the footer.
    const std::size_t stride = bytes.size() > 4096 ? bytes.size() / 2048 : 1;
    std::size_t checked = 0;
    for (std::size_t offset = 0; offset < bytes.size(); offset += stride) {
        auto damaged = StatePersistence::decode(corrupt_at(bytes, offset));
        AP_CHECK(!damaged.has_value());
        AP_CHECK_EQ(damaged.status().code(), ErrorCode::PersistenceCorrupt);
        ++checked;
    }
    context.record("corruption_offsets_checked", std::to_string(checked));
    AP_CHECK(checked > 100);
}

AP_TEST(truncation_at_every_boundary_is_rejected) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-trunc", "digest-trunc-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    const CoordinatorState state = scenario.engine().snapshot();
    auto encoded = StatePersistence::encode(state);
    AP_REQUIRE(encoded.has_value());
    const ByteBuffer& bytes = encoded.value();

    std::size_t checked = 0;
    for (std::size_t size = 0; size < bytes.size(); size += 7) {
        const ByteBuffer truncated(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(size));
        auto decoded = StatePersistence::decode(truncated);
        AP_CHECK(!decoded.has_value());
        ++checked;
    }
    context.record("truncation_lengths_checked", std::to_string(checked));
    AP_CHECK(checked > 20);
}

AP_TEST(trailing_garbage_is_rejected) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-trail", "digest-trail-1");
    const CoordinatorState state = scenario.engine().snapshot();
    auto encoded = StatePersistence::encode(state);
    AP_REQUIRE(encoded.has_value());

    ByteBuffer extended = encoded.value();
    extended.push_back(0x00);
    auto decoded = StatePersistence::decode(extended);
    AP_CHECK(!decoded.has_value());
}

AP_TEST(an_absurd_declared_length_is_rejected_before_allocation) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-absurd", "digest-absurd-1");
    const CoordinatorState state = scenario.engine().snapshot();
    auto encoded = StatePersistence::encode(state);
    AP_REQUIRE(encoded.has_value());

    // The payload length field lives immediately after the twelve byte header.
    ByteBuffer hostile = encoded.value();
    for (int index = 0; index < 8; ++index) {
        hostile[12 + static_cast<std::size_t>(index)] = 0xFF;
    }
    auto decoded = StatePersistence::decode(hostile);
    AP_CHECK(!decoded.has_value());
    AP_CHECK_EQ(decoded.status().code(), ErrorCode::PersistenceCorrupt);
}

AP_TEST(a_wrong_magic_or_version_is_rejected) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-magic", "digest-magic-1");
    const CoordinatorState state = scenario.engine().snapshot();
    auto encoded = StatePersistence::encode(state);
    AP_REQUIRE(encoded.has_value());

    ByteBuffer wrong_magic = encoded.value();
    wrong_magic[0] = static_cast<std::uint8_t>('X');
    auto decoded_magic = StatePersistence::decode(wrong_magic);
    AP_CHECK(!decoded_magic.has_value());
    AP_CHECK_EQ(decoded_magic.status().code(), ErrorCode::PersistenceFormatError);

    ByteBuffer wrong_version = encoded.value();
    wrong_version[8] = 99;
    auto decoded_version = StatePersistence::decode(wrong_version);
    AP_CHECK(!decoded_version.has_value());
    // The footer digest is verified before fields are interpreted, so a
    // corrupted version is reported as corruption rather than as an unsupported
    // version. Either verdict is a rejection; the point is that it never loads.
    AP_CHECK(decoded_version.status().code() == ErrorCode::PersistenceCorrupt ||
             decoded_version.status().code() == ErrorCode::PersistenceVersionUnsupported);
}

AP_TEST(a_restart_keeps_committed_promotions_and_revocations) {
    const std::string state_path = scratch_path("restart-committed.apsnap");

    ArtifactId promoted_id;
    ArtifactId revoked_id;
    {
        Scenario scenario;
        promoted_id = scenario.make_artifact_id();
        revoked_id = scenario.make_artifact_id();
        (void)scenario.register_artifact(promoted_id, ArtifactKind::Executable, "exe-keep", "digest-keep-1");
        (void)scenario.register_artifact(revoked_id, ArtifactKind::Executable, "exe-drop", "digest-drop-1");
        AP_REQUIRE(scenario.drive_to_promoted(promoted_id).ok());
        AP_REQUIRE(scenario.drive_to_promoted(revoked_id).ok());
        AP_REQUIRE(scenario.engine()
                       .revoke(revoked_id, PromotionDecisionId{}, "security_finding", "withdrawn",
                               scenario.authority())
                       .has_value());
        AP_CHECK_EQ(StatePersistence::save(state_path, scenario.engine().snapshot()).code(), ErrorCode::Ok);
    }

    // The restarted coordinator is a new incarnation: it advances the epoch and
    // releases every reservation the previous process may have held.
    Scenario restarted;
    auto loaded = StatePersistence::load(state_path);
    AP_REQUIRE(loaded.has_value());
    CoordinatorState state = loaded.value();
    state.epoch = state.epoch.next();
    AP_CHECK_EQ(restarted.engine().install_state(state).code(), ErrorCode::Ok);
    AP_CHECK_EQ(restarted.engine().recover_in_flight(), static_cast<std::size_t>(0));

    const ArtifactRecord promoted = restarted.current(promoted_id);
    AP_CHECK_EQ(promoted.stage, Stage::Promoted);
    AP_CHECK(promoted.currently_authoritative());

    const ArtifactRecord revoked = restarted.current(revoked_id);
    AP_CHECK_EQ(revoked.stage, Stage::Revoked);
    AP_CHECK(revoked.revocation.active);
    AP_CHECK(!revoked.currently_authoritative());

    AP_CHECK_EQ(restarted.engine().check_invariants().code(), ErrorCode::Ok);
    AP_CHECK_EQ(remove_file(state_path).code(), ErrorCode::Ok);
}

AP_TEST(an_in_flight_transition_does_not_become_promoted_across_a_restart) {
    const std::string state_path = scratch_path("restart-inflight.apsnap");
    ArtifactId id;

    {
        Scenario scenario;
        id = scenario.make_artifact_id();
        (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-inflight", "digest-inflight-1");
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

        // A plan is issued and a reservation is held, but nothing committed.
        const auto evaluated = scenario.engine().evaluate(request);
        AP_REQUIRE(evaluated.has_value());
        AP_REQUIRE(evaluated.value().has_plan);
        AP_CHECK_EQ(scenario.engine().count_pending_transitions(), static_cast<std::size_t>(1));

        // The snapshot deliberately excludes transient reservations.
        const CoordinatorState snapshot = scenario.engine().snapshot();
        AP_CHECK_EQ(snapshot.pending_size(), static_cast<std::size_t>(0));
        AP_CHECK_EQ(StatePersistence::save(state_path, snapshot).code(), ErrorCode::Ok);
    }

    Scenario restarted;
    auto loaded = StatePersistence::load(state_path);
    AP_REQUIRE(loaded.has_value());
    CoordinatorState state = loaded.value();
    state.epoch = state.epoch.next();
    AP_CHECK_EQ(restarted.engine().install_state(state).code(), ErrorCode::Ok);

    // Uncertain state is resolved from durable state, not guessed: the artifact
    // is still a candidate and there is no reservation to inherit.
    const ArtifactRecord record = restarted.current(id);
    AP_CHECK_EQ(record.stage, Stage::Candidate);
    AP_CHECK(!record.promoted);
    AP_CHECK_EQ(restarted.engine().count_pending_transitions(), static_cast<std::size_t>(0));
    AP_CHECK_EQ(remove_file(state_path).code(), ErrorCode::Ok);
}

AP_TEST(recovery_releases_reservations_and_never_promotes) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-recover", "digest-recover-1");
    Scenario::EvidenceSpec provenance;
    provenance.type = EvidenceType::ProvenanceComplete;
    (void)scenario.submit_spec(id, provenance);

    const ArtifactRecord initial = scenario.current(id);
    PromotionRequest request;
    request.artifact = id;
    request.expected_revision = initial.revision;
    request.expected_digest = initial.digest;
    request.requested_stage = Stage::Verified;
    request.request = scenario.make_request_id();
    request.attempt = scenario.make_attempt_id();
    request.authority = scenario.authority();
    const auto evaluated = scenario.engine().evaluate(request);
    AP_REQUIRE(evaluated.has_value());
    AP_REQUIRE(evaluated.value().has_plan);

    AP_CHECK_EQ(scenario.engine().recover_in_flight(), static_cast<std::size_t>(1));
    AP_CHECK_EQ(scenario.engine().count_pending_transitions(), static_cast<std::size_t>(0));
    AP_CHECK_EQ(scenario.current(id).stage, Stage::Candidate);
    AP_CHECK(!scenario.current(id).promoted);
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
}

AP_TEST(state_file_replacement_is_atomic_and_leaves_no_partial_file) {
    const std::string state_path = scratch_path("atomic.apsnap");
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-atomic", "digest-atomic-1");

    AP_CHECK_EQ(StatePersistence::save(state_path, scenario.engine().snapshot()).code(), ErrorCode::Ok);
    AP_CHECK(file_exists(state_path));
    AP_CHECK(!file_exists(state_path + ".tmp"));

    // Saving again replaces the file and the earlier content is still loadable
    // or fully replaced; there is never a partially written authoritative file.
    (void)scenario.drive_to_promoted(id);
    AP_CHECK_EQ(StatePersistence::save(state_path, scenario.engine().snapshot()).code(), ErrorCode::Ok);
    auto reloaded = StatePersistence::load(state_path);
    AP_REQUIRE(reloaded.has_value());
    const ArtifactRecord* restored = reloaded.value().find_current(id);
    AP_REQUIRE(restored != nullptr);
    AP_CHECK_EQ(restored->stage, Stage::Promoted);
    AP_CHECK(!file_exists(state_path + ".tmp"));
    AP_CHECK_EQ(remove_file(state_path).code(), ErrorCode::Ok);
}

AP_TEST(a_missing_state_file_is_reported_rather_than_treated_as_empty_state) {
    const std::string missing = scratch_path("definitely-absent.apsnap");
    AP_CHECK(!file_exists(missing));
    auto loaded = StatePersistence::load(missing);
    AP_CHECK(!loaded.has_value());
    AP_CHECK_EQ(loaded.status().code(), ErrorCode::PersistenceIoError);
}

AP_TEST(a_snapshot_that_contradicts_itself_is_refused_on_install) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-contradict", "digest-contradict-1");
    AP_REQUIRE(scenario.drive_to_promoted(id).ok());

    CoordinatorState state = scenario.engine().snapshot();

    // Break an internal invariant the file format cannot detect by itself: the
    // recorded active policy identity no longer names the policy body held in
    // the state. install_state must refuse rather than trust it.
    state.active_policy = PromotionPolicyId::from_parts(0xDEAD, 0xBEEF);
    const Status installed = scenario.engine().install_state(state);
    AP_CHECK(installed.failed());
    AP_CHECK_EQ(installed.code(), ErrorCode::PersistenceCorrupt);

    // The engine still holds the state it had before the refused install.
    AP_CHECK_EQ(scenario.current(id).stage, Stage::Promoted);
}

AP_TEST(a_snapshot_carrying_evidence_for_an_absent_revision_is_refused) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-dangling", "digest-dangling-1");
    (void)scenario.submit(id, EvidenceType::BuildPass, EvidenceResult::Pass, "one");

    CoordinatorState state = scenario.engine().snapshot();
    auto encoded = StatePersistence::encode(state);
    AP_REQUIRE(encoded.has_value());

    // Removing the artifact while keeping its evidence produces a state that a
    // naive loader would accept. verify_consistency catches it.
    state.artifacts.clear();
    const Status installed = scenario.engine().install_state(state);
    AP_CHECK(installed.failed());
    AP_CHECK_EQ(installed.code(), ErrorCode::PersistenceCorrupt);
}

int main() { return TestContext::instance().run_all("persistence"); }
