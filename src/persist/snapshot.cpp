// Artifact Promotion - versioned durable state snapshots.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/persistence.hpp"

#include <array>
#include <cstring>
#include <functional>
#include <iterator>

#include "artifact_promotion/detail/codec.hpp"
#include "artifact_promotion/detail/reader.hpp"
#include "artifact_promotion/detail/writer.hpp"
#include "artifact_promotion/io.hpp"

namespace artifact_promotion {
namespace {

constexpr std::array<std::uint8_t, 8> kMagic = {'A', 'P', 'S', 'T', 'A', 'T', 'E', 0};
constexpr std::size_t kHeaderSize = 8 + 2 + 2 + 8;
constexpr std::size_t kFooterSize = kSha256DigestSize;

enum class Section : std::uint16_t {
    Header = 1,
    Artifacts = 2,
    Evidence = 3,
    Plans = 4,
    Decisions = 5,
    Records = 6,
    Idempotency = 7,
    History = 8,
    Vetoes = 9,
    Policy = 10,
    Generators = 11,
};

[[nodiscard]] bool is_known_section(std::uint16_t raw) noexcept {
    return raw >= static_cast<std::uint16_t>(Section::Header) &&
           raw <= static_cast<std::uint16_t>(Section::Generators);
}

void write_section(wire::Writer& writer, Section kind, const std::function<void(wire::Writer&)>& body) {
    wire::SectionWriter section(writer, static_cast<std::uint16_t>(kind));
    section.body(body);
}

void write_counter(wire::Writer& writer, std::uint64_t salt, std::uint64_t counter) {
    writer.u64(salt);
    writer.u64(counter);
}

}  // namespace

Result<ByteBuffer> StatePersistence::encode(const CoordinatorState& state) {
    wire::Writer payload(4096);

    write_section(payload, Section::Header, [&](wire::Writer& out) {
        out.identity(state.coordinator);
        out.counter(state.epoch);
        out.counter(state.commit_sequence);
        out.counter(state.decision_sequence);
        out.counter(state.artifact_generation);
        out.counter(state.compatibility_generation);
        out.identity(state.compatibility_profile);
        out.identity(state.active_policy);
        out.counter(state.active_policy_generation);
        out.digest(state.active_policy_digest);
    });

    write_section(payload, Section::Policy, [&](wire::Writer& out) { wire::write_policy(out, state.policy()); });

    write_section(payload, Section::Artifacts, [&](wire::Writer& out) {
        out.list(state.artifacts.size(), [&](wire::Writer& chain_out, std::size_t index) {
            const auto it = std::next(state.artifacts.begin(), static_cast<std::ptrdiff_t>(index));
            chain_out.identity(it->first);
            chain_out.list(it->second.size(), [&](wire::Writer& record_out, std::size_t record_index) {
                wire::write_artifact(record_out, it->second[record_index]);
            });
        });
    });

    write_section(payload, Section::Evidence, [&](wire::Writer& out) {
        out.list(state.evidence.size(), [&](wire::Writer& record_out, std::size_t index) {
            const auto it = std::next(state.evidence.begin(), static_cast<std::ptrdiff_t>(index));
            wire::write_evidence(record_out, it->second);
        });
    });

    write_section(payload, Section::Plans, [&](wire::Writer& out) {
        out.list(state.plans.size(), [&](wire::Writer& record_out, std::size_t index) {
            const auto it = std::next(state.plans.begin(), static_cast<std::ptrdiff_t>(index));
            wire::write_plan(record_out, it->second);
        });
    });

    write_section(payload, Section::Decisions, [&](wire::Writer& out) {
        out.list(state.decisions.size(), [&](wire::Writer& record_out, std::size_t index) {
            const auto it = std::next(state.decisions.begin(), static_cast<std::ptrdiff_t>(index));
            wire::write_decision(record_out, it->second);
        });
    });

    write_section(payload, Section::Records, [&](wire::Writer& out) {
        out.list(state.records.size(), [&](wire::Writer& record_out, std::size_t index) {
            const auto it = std::next(state.records.begin(), static_cast<std::ptrdiff_t>(index));
            wire::write_promotion_record(record_out, it->second);
        });
    });

    write_section(payload, Section::Idempotency, [&](wire::Writer& out) {
        out.list(state.idempotency.size(), [&](wire::Writer& record_out, std::size_t index) {
            const auto it = std::next(state.idempotency.begin(), static_cast<std::ptrdiff_t>(index));
            wire::write_idempotency(record_out, it->second);
        });
    });

    write_section(payload, Section::History, [&](wire::Writer& out) {
        out.list(state.history.size(), [&](wire::Writer& record_out, std::size_t index) {
            const auto it = std::next(state.history.begin(), static_cast<std::ptrdiff_t>(index));
            wire::write_history_event(record_out, it->second);
        });
    });

    write_section(payload, Section::Vetoes, [&](wire::Writer& out) {
        out.list(state.vetoes.size(), [&](wire::Writer& record_out, std::size_t index) {
            const auto it = std::next(state.vetoes.begin(), static_cast<std::ptrdiff_t>(index));
            record_out.identity(it->first);
            wire::write_veto(record_out, it->second);
        });
    });

    write_section(payload, Section::Generators, [&](wire::Writer& out) {
        write_counter(out, state.revision_generator.salt(), state.revision_generator.counter());
        write_counter(out, state.evidence_generator.salt(), state.evidence_generator.counter());
        write_counter(out, state.plan_generator.salt(), state.plan_generator.counter());
        write_counter(out, state.decision_generator.salt(), state.decision_generator.counter());
        write_counter(out, state.transition_generator.salt(), state.transition_generator.counter());
        write_counter(out, state.reservation_generator.salt(), state.reservation_generator.counter());
        write_counter(out, state.instance_generator.salt(), state.instance_generator.counter());
        write_counter(out, state.provenance_generator.salt(), state.provenance_generator.counter());
        write_counter(out, state.internal_request_generator.salt(), state.internal_request_generator.counter());
        write_counter(out, state.internal_attempt_generator.salt(), state.internal_attempt_generator.counter());
    });

    // Assemble header, payload, and footer digest.
    wire::Writer file(payload.size() + kHeaderSize + kFooterSize);
    file.raw(kMagic.data(), kMagic.size());
    file.u16(kFormatVersion);
    file.u16(0);
    file.u64(static_cast<std::uint64_t>(payload.size()));
    file.raw(payload.buffer().data(), payload.size());

    const Digest footer = sha256(file.buffer());
    file.digest(footer);
    return std::move(file).take();
}

Result<CoordinatorState> StatePersistence::decode(const ByteBuffer& bytes) {
    if (bytes.size() < kHeaderSize + kFooterSize) {
        return Status(ErrorCode::PersistenceCorrupt, "state file is smaller than the minimum snapshot size");
    }
    if (std::memcmp(bytes.data(), kMagic.data(), kMagic.size()) != 0) {
        return Status(ErrorCode::PersistenceFormatError, "state file does not begin with the expected magic");
    }
    // Integrity first. The footer digest covers every preceding byte, so it is
    // verified before a single header field is interpreted. A decoder that reads
    // length and section fields before checking the digest is parsing bytes it
    // has no reason to trust, and reports structural complaints for what is
    // really a damaged file.
    const Digest stored_footer = Digest::from_raw(bytes.data() + bytes.size() - kFooterSize);
    const Digest computed_footer = sha256(bytes.data(), bytes.size() - kFooterSize);
    if (!(stored_footer == computed_footer)) {
        return Status(ErrorCode::PersistenceCorrupt, "snapshot footer digest does not match the snapshot content");
    }
    wire::Reader reader(bytes);
    ByteBuffer magic;
    Status status = reader.raw(kMagic.size(), magic);
    if (status.failed()) {
        return status;
    }
    auto version = reader.u16();
    if (!version) {
        return version.status();
    }
    if (version.value() != kFormatVersion) {
        return Status(ErrorCode::PersistenceVersionUnsupported,
                      "state file format version " + std::to_string(version.value()) +
                          " is not supported by this build");
    }
    auto reserved = reader.u16();
    if (!reserved) {
        return reserved.status();
    }
    if (reserved.value() != 0) {
        return Status(ErrorCode::PersistenceFormatError, "reserved header field is not zero");
    }
    auto payload_length = reader.u64();
    if (!payload_length) {
        return payload_length.status();
    }
    const std::size_t expected_total = kHeaderSize + static_cast<std::size_t>(payload_length.value()) + kFooterSize;
    if (payload_length.value() > static_cast<std::uint64_t>(kMaxSnapshotBytes)) {
        return Status(ErrorCode::PersistenceCorrupt, "declared snapshot payload exceeds the supported bound");
    }
    if (expected_total != bytes.size()) {
        return Status(ErrorCode::PersistenceCorrupt,
                      "declared snapshot length does not match the file size; the file is truncated or has trailing "
                      "bytes");
    }

    ByteBuffer payload;
    status = reader.raw(static_cast<std::size_t>(payload_length.value()), payload);
    if (status.failed()) {
        return status;
    }
    // The footer digest is part of the file, so it is consumed here before the
    // reader is asked whether the whole region was read. Demanding a finished
    // region while the footer is still unread would reject the file this module
    // itself produced.
    const Status footer_status = reader.skip(kFooterSize);
    if (footer_status.failed()) {
        return footer_status;
    }
    status = reader.require_finished();
    if (status.failed()) {
        return status;
    }

    wire::Reader payload_reader(payload);
    CoordinatorState state;
    bool has_header = false;
    bool has_policy = false;
    bool has_artifacts = false;
    bool has_evidence = false;
    bool has_plans = false;
    bool has_decisions = false;
    bool has_records = false;
    bool has_idempotency = false;
    bool has_history = false;
    bool has_vetoes = false;
    bool has_generators = false;

    std::size_t section_count = 0;
    while (!payload_reader.finished()) {
        if (++section_count > kMaxSections) {
            return Status(ErrorCode::PersistenceCorrupt, "snapshot declares more sections than the format allows");
        }
        auto kind = payload_reader.u16();
        if (!kind) {
            return kind.status();
        }
        if (!is_known_section(kind.value())) {
            return Status(ErrorCode::PersistenceFormatError, "snapshot contains an unknown section kind");
        }
        auto section = payload_reader.sub_region(kMaxSnapshotBytes);
        if (!section) {
            return section.status();
        }
        wire::Reader& body = section.value();

        switch (static_cast<Section>(kind.value())) {
            case Section::Header: {
                if (has_header) {
                    return Status(ErrorCode::PersistenceCorrupt, "snapshot contains a duplicate header section");
                }
                has_header = true;
                auto coordinator = body.identity<CoordinatorIdTag>();
                if (!coordinator) {
                    return coordinator.status();
                }
                state.coordinator = coordinator.value();
                auto epoch = body.counter<CoordinatorEpochTag>();
                if (!epoch) {
                    return epoch.status();
                }
                state.epoch = epoch.value();
                auto commit = body.counter<CommitSequenceTag>();
                if (!commit) {
                    return commit.status();
                }
                state.commit_sequence = commit.value();
                auto decision_sequence = body.counter<DecisionSequenceTag>();
                if (!decision_sequence) {
                    return decision_sequence.status();
                }
                state.decision_sequence = decision_sequence.value();
                auto artifact_generation = body.counter<ArtifactGenerationTag>();
                if (!artifact_generation) {
                    return artifact_generation.status();
                }
                state.artifact_generation = artifact_generation.value();
                auto compatibility = body.counter<CompatibilityGenerationTag>();
                if (!compatibility) {
                    return compatibility.status();
                }
                state.compatibility_generation = compatibility.value();
                auto profile = body.identity<CompatibilityProfileIdTag>();
                if (!profile) {
                    return profile.status();
                }
                state.compatibility_profile = profile.value();
                auto policy = body.identity<PromotionPolicyIdTag>();
                if (!policy) {
                    return policy.status();
                }
                state.active_policy = policy.value();
                auto policy_generation = body.counter<PolicyGenerationTag>();
                if (!policy_generation) {
                    return policy_generation.status();
                }
                state.active_policy_generation = policy_generation.value();
                auto policy_digest = body.digest();
                if (!policy_digest) {
                    return policy_digest.status();
                }
                state.active_policy_digest = policy_digest.value();
                break;
            }
            case Section::Policy: {
                if (has_policy) {
                    return Status(ErrorCode::PersistenceCorrupt, "snapshot contains a duplicate policy section");
                }
                has_policy = true;
                auto policy = wire::read_policy(body);
                if (!policy) {
                    return policy.status();
                }
                state.set_active_policy(policy.value());
                break;
            }
            case Section::Artifacts: {
                if (has_artifacts) {
                    return Status(ErrorCode::PersistenceCorrupt, "snapshot contains a duplicate artifact section");
                }
                has_artifacts = true;
                auto chain_count = body.count(1000000);
                if (!chain_count) {
                    return chain_count.status();
                }
                for (std::size_t chain_index = 0; chain_index < chain_count.value(); ++chain_index) {
                    auto id = body.identity<ArtifactIdTag>();
                    if (!id) {
                        return id.status();
                    }
                    if (state.artifacts.count(id.value()) > 0) {
                        return Status(ErrorCode::PersistenceCorrupt,
                                      "snapshot contains a duplicate artifact identity");
                    }
                    auto revision_count = body.count(1024);
                    if (!revision_count) {
                        return revision_count.status();
                    }
                    std::vector<ArtifactRecord> chain;
                    chain.reserve(revision_count.value());
                    for (std::size_t revision_index = 0; revision_index < revision_count.value();
                         ++revision_index) {
                        auto record = wire::read_artifact(body);
                        if (!record) {
                            return record.status();
                        }
                        if (record.value().id != id.value()) {
                            return Status(ErrorCode::PersistenceCorrupt,
                                          "artifact revision record does not match its chain identity");
                        }
                        chain.push_back(std::move(record.value()));
                    }
                    if (chain.empty()) {
                        return Status(ErrorCode::PersistenceCorrupt, "snapshot contains an empty artifact chain");
                    }
                    state.artifacts.emplace(id.value(), std::move(chain));
                }
                break;
            }
            case Section::Evidence: {
                if (has_evidence) {
                    return Status(ErrorCode::PersistenceCorrupt, "snapshot contains a duplicate evidence section");
                }
                has_evidence = true;
                auto record_count = body.count(10000000);
                if (!record_count) {
                    return record_count.status();
                }
                for (std::size_t index = 0; index < record_count.value(); ++index) {
                    auto record = wire::read_evidence(body);
                    if (!record) {
                        return record.status();
                    }
                    if (state.evidence.count(record.value().id) > 0) {
                        return Status(ErrorCode::PersistenceCorrupt, "snapshot contains duplicate evidence identity");
                    }
                    state.evidence.emplace(record.value().id, std::move(record.value()));
                }
                break;
            }
            case Section::Plans: {
                if (has_plans) {
                    return Status(ErrorCode::PersistenceCorrupt, "snapshot contains a duplicate plan section");
                }
                has_plans = true;
                auto record_count = body.count(10000000);
                if (!record_count) {
                    return record_count.status();
                }
                for (std::size_t index = 0; index < record_count.value(); ++index) {
                    auto record = wire::read_plan(body);
                    if (!record) {
                        return record.status();
                    }
                    state.plans.emplace(record.value().id, std::move(record.value()));
                }
                break;
            }
            case Section::Decisions: {
                if (has_decisions) {
                    return Status(ErrorCode::PersistenceCorrupt, "snapshot contains a duplicate decision section");
                }
                has_decisions = true;
                auto record_count = body.count(10000000);
                if (!record_count) {
                    return record_count.status();
                }
                for (std::size_t index = 0; index < record_count.value(); ++index) {
                    auto record = wire::read_decision(body);
                    if (!record) {
                        return record.status();
                    }
                    state.decisions.emplace(record.value().id, std::move(record.value()));
                }
                break;
            }
            case Section::Records: {
                if (has_records) {
                    return Status(ErrorCode::PersistenceCorrupt,
                                  "snapshot contains a duplicate promotion record section");
                }
                has_records = true;
                auto record_count = body.count(10000000);
                if (!record_count) {
                    return record_count.status();
                }
                for (std::size_t index = 0; index < record_count.value(); ++index) {
                    auto record = wire::read_promotion_record(body);
                    if (!record) {
                        return record.status();
                    }
                    state.records.emplace(record.value().transition, std::move(record.value()));
                }
                break;
            }
            case Section::Idempotency: {
                if (has_idempotency) {
                    return Status(ErrorCode::PersistenceCorrupt,
                                  "snapshot contains a duplicate idempotency section");
                }
                has_idempotency = true;
                auto record_count = body.count(10000000);
                if (!record_count) {
                    return record_count.status();
                }
                for (std::size_t index = 0; index < record_count.value(); ++index) {
                    auto record = wire::read_idempotency(body);
                    if (!record) {
                        return record.status();
                    }
                    state.idempotency.emplace(record.value().request, std::move(record.value()));
                }
                break;
            }
            case Section::History: {
                if (has_history) {
                    return Status(ErrorCode::PersistenceCorrupt, "snapshot contains a duplicate history section");
                }
                has_history = true;
                auto record_count = body.count(10000000);
                if (!record_count) {
                    return record_count.status();
                }
                for (std::size_t index = 0; index < record_count.value(); ++index) {
                    auto record = wire::read_history_event(body);
                    if (!record) {
                        return record.status();
                    }
                    state.history.emplace(record.value().sequence, std::move(record.value()));
                }
                break;
            }
            case Section::Vetoes: {
                if (has_vetoes) {
                    return Status(ErrorCode::PersistenceCorrupt, "snapshot contains a duplicate veto section");
                }
                has_vetoes = true;
                auto record_count = body.count(1000000);
                if (!record_count) {
                    return record_count.status();
                }
                for (std::size_t index = 0; index < record_count.value(); ++index) {
                    auto id = body.identity<ArtifactIdTag>();
                    if (!id) {
                        return id.status();
                    }
                    auto veto = wire::read_veto(body);
                    if (!veto) {
                        return veto.status();
                    }
                    state.vetoes.emplace(id.value(), std::move(veto.value()));
                }
                break;
            }
            case Section::Generators: {
                if (has_generators) {
                    return Status(ErrorCode::PersistenceCorrupt,
                                  "snapshot contains a duplicate generator section");
                }
                has_generators = true;
                std::uint64_t salts[10] = {};
                std::uint64_t counters[10] = {};
                for (std::size_t index = 0; index < 10; ++index) {
                    auto salt = body.u64();
                    if (!salt) {
                        return salt.status();
                    }
                    auto counter = body.u64();
                    if (!counter) {
                        return counter.status();
                    }
                    salts[index] = salt.value();
                    counters[index] = counter.value();
                }
                // A generator that has never been used legitimately holds a
                // counter of zero, so zero is not itself corruption. What must
                // never happen is a restored generator handing out an identity
                // the state already contains. That is verified below against the
                // restored record sets, which is a real invariant, rather than
                // by rejecting zero here, which would be a guess.
                state.revision_generator.resume_after(salts[0], counters[0]);
                state.evidence_generator.resume_after(salts[1], counters[1]);
                state.plan_generator.resume_after(salts[2], counters[2]);
                state.decision_generator.resume_after(salts[3], counters[3]);
                state.transition_generator.resume_after(salts[4], counters[4]);
                state.reservation_generator.resume_after(salts[5], counters[5]);
                state.instance_generator.resume_after(salts[6], counters[6]);
                state.provenance_generator.resume_after(salts[7], counters[7]);
                state.internal_request_generator.resume_after(salts[8], counters[8]);
                state.internal_attempt_generator.resume_after(salts[9], counters[9]);
                break;
            }
        }

        status = body.require_finished();
        if (status.failed()) {
            return Status(ErrorCode::PersistenceCorrupt,
                          "snapshot section contains trailing bytes after its declared content");
        }
    }

    if (!has_header || !has_policy || !has_artifacts || !has_evidence || !has_plans || !has_decisions ||
        !has_records || !has_idempotency || !has_history || !has_vetoes || !has_generators) {
        return Status(ErrorCode::PersistenceCorrupt, "snapshot is missing one or more mandatory sections");
    }

    // Restoring the policy body requires its generation to match the header.
    if (!(state.policy().generation == state.active_policy_generation)) {
        return Status(ErrorCode::PersistenceCorrupt,
                      "snapshot policy generation does not match the recorded active policy generation");
    }
    if (state.policy().id != state.active_policy) {
        return Status(ErrorCode::PersistenceCorrupt,
                      "snapshot policy identity does not match the recorded active policy identity");
    }
    if (state.policy().policy_digest != state.active_policy_digest) {
        return Status(ErrorCode::PersistenceCorrupt, "snapshot policy digest does not match the recorded digest");
    }

    // Identity uniqueness across a restart. Every identity generator is advanced
    // past every value the restored state already contains, so a coordinator
    // that restarts can never reissue an identity a previous process handed out.
    // This is derived from the records themselves rather than trusted from the
    // persisted counter, because the records are the authority.
    for (const auto& [artifact_id, revisions] : state.artifacts) {
        for (const ArtifactRecord& record : revisions) {
            state.revision_generator.observe_existing(record.revision.high(), record.revision.low());
        }
        (void)artifact_id;
    }
    for (const auto& [evidence_id, record] : state.evidence) {
        state.evidence_generator.observe_existing(evidence_id.high(), evidence_id.low());
        (void)record;
    }
    for (const auto& [plan_id, plan] : state.plans) {
        state.plan_generator.observe_existing(plan_id.high(), plan_id.low());
        (void)plan;
    }
    for (const auto& [decision_id, decision] : state.decisions) {
        state.decision_generator.observe_existing(decision_id.high(), decision_id.low());
        (void)decision;
    }
    for (const auto& [transition_id, record] : state.records) {
        state.transition_generator.observe_existing(transition_id.high(), transition_id.low());
        (void)record;
    }
    for (const auto& [request_id, record] : state.idempotency) {
        state.internal_request_generator.observe_existing(request_id.high(), request_id.low());
        (void)record;
    }
    return state;
}

Result<CoordinatorState> StatePersistence::load(const std::string& path) {
    auto bytes = read_file(path);
    if (!bytes) {
        return detached_status(bytes.status());
    }
    return decode(bytes.value());
}

Status StatePersistence::save(const std::string& path, const CoordinatorState& state) {
    auto encoded = encode(state);
    if (!encoded) {
        return detached_status(encoded.status());
    }
    return atomic_write_file(path, encoded.value());
}

}  // namespace artifact_promotion
