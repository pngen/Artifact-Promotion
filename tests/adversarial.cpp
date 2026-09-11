// Artifact Promotion - adversarial hardening against hostile input.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <string>

#include "support/test_context.hpp"

using namespace artifact_promotion;
using namespace artifact_promotion::test;
using namespace artifact_promotion::protocol;

namespace {

// A small deterministic evidence class selector used by the bounded-collection
// test.
[[nodiscard]] EvidenceType evidence_class(std::uint64_t index) {
    switch (index % 6) {
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

AP_TEST(a_validated_frame_round_trips) {
    Frame frame;
    frame.type = MessageType::RegisterArtifactRequest;
    frame.request = PromotionRequestId::from_parts(0x1234, 0x5678);
    frame.worker = WorkerId::from_parts(0xAAAA, 0xBBBB);
    frame.boot = WorkerBootId::from_parts(0xCCCC, 0xDDDD);
    frame.payload = ByteBuffer{1, 2, 3, 4};

    auto encoded = encode_frame(frame);
    AP_REQUIRE(encoded.has_value());
    AP_CHECK_EQ(encoded.value().size(), kFrameHeaderSize + 4 + kFrameFooterSize);

    auto decoded = decode_frame(encoded.value());
    AP_REQUIRE(decoded.has_value());
    AP_CHECK_EQ(decoded.value().request, frame.request);
    AP_CHECK_EQ(decoded.value().worker, frame.worker);
    AP_CHECK(decoded.value().payload == frame.payload);
}

AP_TEST(a_truncated_frame_is_rejected) {
    Frame frame;
    frame.type = MessageType::PromotionRequest;
    frame.request = PromotionRequestId::from_parts(1, 2);
    frame.payload = ByteBuffer(64, 0x5A);
    auto encoded = encode_frame(frame);
    AP_REQUIRE(encoded.has_value());

    for (std::size_t size : {std::size_t{0}, std::size_t{1}, kFrameHeaderSize - 1, kFrameHeaderSize,
                             encoded.value().size() - 1}) {
        const ByteBuffer truncated(encoded.value().begin(),
                                   encoded.value().begin() + static_cast<std::ptrdiff_t>(size));
        auto decoded = decode_frame(truncated);
        AP_CHECK(!decoded.has_value());
    }
}

AP_TEST(a_frame_with_a_declared_length_beyond_the_bound_is_rejected) {
    Frame frame;
    frame.type = MessageType::PromotionRequest;
    frame.request = PromotionRequestId::from_parts(1, 2);
    auto encoded = encode_frame(frame);
    AP_REQUIRE(encoded.has_value());

    ByteBuffer hostile = encoded.value();
    // The payload length field is at offset twelve and is little-endian.
    const std::uint32_t absurd = static_cast<std::uint32_t>(kMaxFrameBytes + 1);
    for (int index = 0; index < 4; ++index) {
        hostile[12 + static_cast<std::size_t>(index)] =
            static_cast<std::uint8_t>((absurd >> (8 * index)) & 0xFFU);
    }
    auto decoded = decode_frame(hostile);
    AP_CHECK(!decoded.has_value());
}

AP_TEST(an_unknown_message_type_is_rejected) {
    Frame frame;
    frame.type = MessageType::PromotionRequest;
    frame.request = PromotionRequestId::from_parts(1, 2);
    auto encoded = encode_frame(frame);
    AP_REQUIRE(encoded.has_value());

    ByteBuffer hostile = encoded.value();
    hostile[6] = 0x7F;
    hostile[7] = 0x00;
    auto decoded = decode_frame(hostile);
    AP_CHECK(!decoded.has_value());
    AP_CHECK_EQ(decoded.status().code(), ErrorCode::ProtocolMalformed);
}

AP_TEST(a_frame_with_unknown_flag_bits_is_rejected) {
    Frame frame;
    frame.type = MessageType::PromotionRequest;
    frame.request = PromotionRequestId::from_parts(1, 2);
    frame.flags = kFlagNonIdempotent;
    auto encoded = encode_frame(frame);
    AP_REQUIRE(encoded.has_value());
    AP_CHECK(decode_frame(encoded.value()).has_value());

    // A flag the protocol does not define is a hard failure, never a silent
    // downgrade of the request's semantics.
    const auto flagged = encode_frame([&] {
                 Frame upgraded = frame;
                 upgraded.flags = 0x80000000U;
                 return upgraded;
             }());
    AP_CHECK(!flagged.has_value());
}

AP_TEST(a_frame_without_any_identity_is_rejected) {
    Frame frame;
    frame.type = MessageType::PromotionRequest;
    const auto refused = encode_frame(frame);
    AP_CHECK(!refused.has_value());
    AP_CHECK_EQ(refused.status().code(), ErrorCode::ProtocolMalformed);
}

AP_TEST(every_single_byte_corruption_of_a_frame_is_detected) {
    Frame frame;
    frame.type = MessageType::PromotionRequest;
    frame.request = PromotionRequestId::from_parts(0x9999, 0x8888);
    frame.worker = WorkerId::from_parts(0x7777, 0x6666);
    frame.boot = WorkerBootId::from_parts(0x5555, 0x4444);
    frame.payload = ByteBuffer{9, 8, 7, 6, 5, 4, 3, 2, 1};
    auto encoded = encode_frame(frame);
    AP_REQUIRE(encoded.has_value());

    std::size_t detected = 0;
    for (std::size_t offset = 0; offset < encoded.value().size(); ++offset) {
        ByteBuffer damaged = encoded.value();
        damaged[offset] = static_cast<std::uint8_t>(damaged[offset] ^ 0xFFU);
        // A corrupted header field can be rejected either by the digest or by
        // field validation; either way it must never decode successfully.
        AP_CHECK(!decode_frame(damaged).has_value());
        ++detected;
    }
    context.record("frame_corruptions_detected", std::to_string(detected));
}

AP_TEST(an_unsupported_protocol_version_is_rejected) {
    Frame frame;
    frame.type = MessageType::PromotionRequest;
    frame.request = PromotionRequestId::from_parts(1, 2);
    auto encoded = encode_frame(frame);
    AP_REQUIRE(encoded.has_value());

    ByteBuffer hostile = encoded.value();
    hostile[4] = 2;
    hostile[5] = 0;
    auto decoded = decode_frame(hostile);
    AP_CHECK(!decoded.has_value());
}

AP_TEST(a_promotion_payload_carrying_an_unknown_stage_is_rejected) {
    PromotionPayload payload;
    payload.artifact = ArtifactId::from_parts(1, 2);
    payload.revision = ArtifactRevision::from_parts(3, 4);
    payload.digest = Digest::from_string("digest");
    payload.requested_stage = Stage::Promoted;
    ByteBuffer bytes;
    AP_CHECK_EQ(encode_promotion_request(payload, bytes).code(), ErrorCode::Ok);
    AP_CHECK(decode_promotion_request(bytes).has_value());

    // The stage field is the first byte after the two identities and the digest.
    bytes[16 + 16 + 32] = 200;
    auto decoded = decode_promotion_request(bytes);
    AP_CHECK(!decoded.has_value());
    AP_CHECK_EQ(decoded.status().code(), ErrorCode::InvalidStage);
}

AP_TEST(a_promotion_payload_with_trailing_bytes_is_rejected) {
    PromotionPayload payload;
    payload.artifact = ArtifactId::from_parts(1, 2);
    payload.revision = ArtifactRevision::from_parts(3, 4);
    payload.digest = Digest::from_string("digest");
    payload.requested_stage = Stage::Verified;
    ByteBuffer bytes;
    AP_CHECK_EQ(encode_promotion_request(payload, bytes).code(), ErrorCode::Ok);
    bytes.push_back(0xAB);
    auto decoded = decode_promotion_request(bytes);
    AP_CHECK(!decoded.has_value());
}

AP_TEST(an_evidence_payload_with_an_absurd_confidence_is_rejected) {
    EvidencePayload payload;
    payload.type = EvidenceType::BuildPass;
    payload.subject = ArtifactId::from_parts(1, 2);
    payload.subject_digest = Digest::from_string("digest");
    payload.subject_revision = ArtifactRevision::from_parts(3, 4);
    payload.result = EvidenceResult::Pass;
    payload.confidence_milli = 999;
    payload.payload_digest = Digest::from_string("payload");
    ByteBuffer bytes;
    AP_CHECK_EQ(encode_evidence_submission(payload, bytes).code(), ErrorCode::Ok);
    AP_CHECK(decode_evidence_submission(bytes).has_value());

    payload.confidence_milli = 100000;
    ByteBuffer hostile;
    AP_CHECK_EQ(encode_evidence_submission(payload, hostile).code(), ErrorCode::Ok);
    auto decoded = decode_evidence_submission(hostile);
    AP_CHECK(!decoded.has_value());
    AP_CHECK_EQ(decoded.status().code(), ErrorCode::InvalidArgument);
}

AP_TEST(a_registration_payload_carrying_an_unknown_class_is_rejected) {
    RegisterArtifactPayload payload;
    payload.artifact = ArtifactId::from_parts(1, 2);
    payload.kind = ArtifactKind::Executable;
    payload.digest = Digest::from_string("digest");
    payload.name = "hostile";
    ByteBuffer bytes;
    AP_CHECK_EQ(encode_register_artifact(payload, bytes).code(), ErrorCode::Ok);
    bytes[16] = 99;
    auto decoded = decode_register_artifact(bytes);
    AP_CHECK(!decoded.has_value());
    AP_CHECK_EQ(decoded.status().code(), ErrorCode::InvalidEnum);
}

AP_TEST(a_registration_payload_with_an_oversized_name_is_rejected) {
    RegisterArtifactPayload payload;
    payload.artifact = ArtifactId::from_parts(1, 2);
    payload.kind = ArtifactKind::Executable;
    payload.digest = Digest::from_string("digest");
    payload.name = std::string(kMaxNameLength + 1, 'a');
    ByteBuffer bytes;
    const Status refused = encode_register_artifact(payload, bytes);
    AP_CHECK(refused.failed());
    AP_CHECK_EQ(refused.code(), ErrorCode::InvalidName);
}

AP_TEST(an_identity_substitution_cannot_promote_a_different_artifact) {
    Scenario scenario;
    const ArtifactId first = scenario.make_artifact_id();
    const ArtifactId second = scenario.make_artifact_id();
    (void)scenario.register_artifact(first, ArtifactKind::Executable, "exe-hostile-a", "hostile-a");
    (void)scenario.register_artifact(second, ArtifactKind::Executable, "exe-hostile-b", "hostile-b");
    AP_REQUIRE(scenario.drive_to_promoted(first).ok());

    // Presenting artifact A's promoted identity while claiming artifact B's
    // digest must never be accepted as evidence about B.
    const ArtifactRecord promoted = scenario.current(first);
    const ArtifactRecord other = scenario.current(second);

    EvidenceSubmission substitution;
    substitution.subject = second;
    substitution.subject_revision = other.revision;
    substitution.subject_digest = promoted.digest;
    substitution.type = EvidenceType::ProvenanceComplete;
    substitution.result = EvidenceResult::Pass;
    substitution.payload_digest = Digest::from_string("payload");
    const auto refused = scenario.engine().submit_evidence(substitution);
    AP_CHECK(!refused.has_value());
    AP_CHECK_EQ(refused.status().code(), ErrorCode::DigestMismatch);

    AP_CHECK_EQ(scenario.step(second, Stage::Verified), PromotionOutcome::EvidenceMissing);
    AP_CHECK_EQ(scenario.current(second).stage, Stage::Candidate);
}

AP_TEST(a_lifecycle_graph_that_permits_a_jump_does_not_leak_into_another_engine) {
    Scenario permissive;
    PromotionPolicy jump =
        make_reference_policy(PromotionPolicyId::from_parts(0xF00D, 0xBEEF), PolicyGeneration(2));
    (void)jump.graph.add_edge(Stage::Candidate, Stage::Promoted);
    jump.graph.canonicalize();
    PolicyRule direct;
    direct.from = Stage::Candidate;
    direct.to = Stage::Promoted;
    Gate identity;
    identity.kind = GateKind::ArtifactIdentity;
    identity.label = "artifact identity is valid";
    direct.requirements.push_back(identity);
    jump.rules.push_back(direct);
    AP_CHECK_EQ(jump.validate().code(), ErrorCode::Ok);
    AP_REQUIRE(permissive.engine().publish_policy(jump).has_value());

    Scenario strict;
    const ArtifactId id = strict.make_artifact_id();
    (void)strict.register_artifact(id, ArtifactKind::Executable, "exe-policy-leak", "policy-leak");
    AP_CHECK_EQ(strict.step(id, Stage::Promoted), PromotionOutcome::TransitionIllegal);

    // The permissive policy only affects the engine it was published to.
    const ArtifactId permissive_id = permissive.make_artifact_id();
    (void)permissive.register_artifact(permissive_id, ArtifactKind::Executable, "exe-permissive", "permissive");
    AP_CHECK_EQ(permissive.step(permissive_id, Stage::Promoted), PromotionOutcome::PromotionCommitted);
}

AP_TEST(bounded_metadata_collections_are_enforced) {
    EngineConfig config;
    config.max_artifact_revisions_per_id = 2;
    config.max_evidence_per_artifact_revision = 3;
    ScenarioOptions options;
    options.engine = config;
    Scenario scenario(options);

    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-bounded", "bounded-1");
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-bounded", "bounded-2");

    const auto beyond = scenario.engine().register_artifact([&] {
        ArtifactRegistration registration;
        registration.id = id;
        registration.kind = ArtifactKind::Executable;
        registration.digest = Digest::from_string("bounded-3");
        registration.name = "exe-bounded";
        return registration;
    }());
    AP_CHECK(!beyond.has_value());
    AP_CHECK_EQ(beyond.status().code(), ErrorCode::AdmissionRejected);

    for (int index = 0; index < 3; ++index) {
        (void)scenario.submit(id, evidence_class(static_cast<std::uint64_t>(index)), EvidenceResult::Pass,
                              "bounded-evidence");
    }
    EvidenceSubmission overflow;
    overflow.subject = id;
    const ArtifactRecord record = scenario.current(id);
    overflow.subject_revision = record.revision;
    overflow.subject_digest = record.digest;
    overflow.type = EvidenceType::Custom;
    overflow.custom_type = "extra_class";
    overflow.result = EvidenceResult::Pass;
    overflow.payload_digest = Digest::from_string("payload");
    const auto refused = scenario.engine().submit_evidence(overflow);
    AP_CHECK(!refused.has_value());
    AP_CHECK_EQ(refused.status().code(), ErrorCode::AdmissionRejected);
    AP_CHECK_EQ(scenario.engine().count_evidence(), static_cast<std::size_t>(3));
}

AP_TEST(admission_can_be_closed_and_reopened_without_corrupting_state) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-admission", "admission-1");

    scenario.engine().close_admission();
    AP_CHECK(!scenario.engine().admission_open());

    const auto refused_registration = scenario.engine().register_artifact([&] {
        ArtifactRegistration registration;
        registration.id = scenario.make_artifact_id();
        registration.kind = ArtifactKind::Executable;
        registration.digest = Digest::from_string("admission-2");
        registration.name = "exe-refused";
        return registration;
    }());
    AP_CHECK(!refused_registration.has_value());
    AP_CHECK_EQ(refused_registration.status().code(), ErrorCode::ShuttingDown);

    // Readers keep working while admission is closed.
    AP_CHECK(scenario.engine().inspect_artifact(id).has_value());
    AP_CHECK_EQ(scenario.engine().count_artifacts(), static_cast<std::size_t>(1));

    scenario.engine().open_admission();
    AP_CHECK(scenario.engine().admission_open());
    AP_CHECK_EQ(scenario.engine().check_invariants().code(), ErrorCode::Ok);
}

AP_TEST(a_hostile_snapshot_claiming_a_huge_record_count_is_refused) {
    Scenario scenario;
    const ArtifactId id = scenario.make_artifact_id();
    (void)scenario.register_artifact(id, ArtifactKind::Executable, "exe-count", "count-1");
    const CoordinatorState state = scenario.engine().snapshot();
    auto encoded = StatePersistence::encode(state);
    AP_REQUIRE(encoded.has_value());

    // Craft a file whose sections claim far more records than exist. The section
    // length check must reject it before any container grows.
    ByteBuffer hostile = encoded.value();
    for (std::size_t offset = 0; offset + 1 < hostile.size(); ++offset) {
        // Find the artifact section header and rewrite its declared length.
        if (hostile[offset] == 0x02 && hostile[offset + 1] == 0x00) {
            for (int index = 0; index < 4; ++index) {
                hostile[offset + 2 + static_cast<std::size_t>(index)] = 0xFF;
            }
            break;
        }
    }
    auto decoded = StatePersistence::decode(hostile);
    AP_CHECK(!decoded.has_value());
}

int main(int argc, char** argv) { return run_suite_from_command_line("adversarial", argc, argv); }
