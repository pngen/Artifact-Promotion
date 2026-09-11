// Artifact Promotion - coordinator core: registration, evidence, state.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <chrono>
#include <functional>
#include <sstream>
#include <thread>

#include "artifact_promotion/engine.hpp"

namespace artifact_promotion {
namespace {

[[nodiscard]] std::uint64_t entropy() noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto thread_hash = std::hash<std::thread::id>{}(std::this_thread::get_id());
    std::uint64_t mixed = static_cast<std::uint64_t>(now) ^ static_cast<std::uint64_t>(thread_hash);
    mixed ^= 0x9E3779B97F4A7C15ULL;
    mixed ^= mixed >> 30;
    mixed *= 0xBF58476D1CE4E5B9ULL;
    mixed ^= mixed >> 27;
    mixed *= 0x94D049BB133111EBULL;
    mixed ^= mixed >> 31;
    return mixed == 0 ? 1 : mixed;
}

[[nodiscard]] std::uint64_t seed_from(std::uint64_t base, std::uint64_t index) noexcept {
    std::uint64_t mixed = base + (index * 0x9E3779B97F4A7C15ULL);
    mixed ^= mixed >> 30;
    mixed *= 0xBF58476D1CE4E5B9ULL;
    mixed ^= mixed >> 27;
    mixed *= 0x94D049BB133111EBULL;
    mixed ^= mixed >> 31;
    return mixed == 0 ? 1 : mixed;
}

}  // namespace

PromotionEngine::PromotionEngine(EngineConfig config, CoordinatorEpoch epoch) : config_(config) {
    if (!config_.valid()) {
        config_ = EngineConfig::defaults();
    }
    const std::uint64_t salt = seed_from(config_.identity_salt_seed, entropy());
    state_.coordinator = CoordinatorId::from_parts(salt, entropy());
    state_.epoch = epoch.valid() ? epoch : CoordinatorEpoch(1);

    // Each identity domain gets an independent generator salt so a value
    // generated for one domain can never collide with another domain's value.
    state_.revision_generator = IdentityGenerator<ArtifactRevisionTag>(seed_from(salt, 1));
    state_.evidence_generator = IdentityGenerator<EvidenceIdTag>(seed_from(salt, 2));
    state_.plan_generator = IdentityGenerator<PromotionPlanIdTag>(seed_from(salt, 3));
    state_.decision_generator = IdentityGenerator<PromotionDecisionIdTag>(seed_from(salt, 4));
    state_.transition_generator = IdentityGenerator<TransitionIdTag>(seed_from(salt, 5));
    state_.reservation_generator = IdentityGenerator<ReservationIdTag>(seed_from(salt, 6));
    state_.instance_generator = IdentityGenerator<ArtifactInstanceIdTag>(seed_from(salt, 7));
    state_.provenance_generator = IdentityGenerator<ProvenanceRefTag>(seed_from(salt, 8));

    PromotionPolicy policy = make_reference_policy(PromotionPolicyId::from_parts(salt, 0xA1), PolicyGeneration(1));
    state_.set_active_policy(std::move(policy));
    state_.compatibility_generation = CompatibilityGeneration(1);
    state_.compatibility_profile = CompatibilityProfileId::from_parts(salt, 0xB2);
}

PromotionEngine::~PromotionEngine() = default;

PromotionEngine::Clock PromotionEngine::now_millis() noexcept {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    return millis < 0 ? 0 : static_cast<Clock>(millis);
}

// Runs the registered change listener without holding any engine lock. The
// listener is expected to persist an authoritative snapshot; the epoch
// bookkeeping guarantees that the state produced by every mutation is either
// captured by this write or by a later one.
void PromotionEngine::notify_change() {
    std::function<void()> listener;
    std::uint64_t target_epoch = 0;
    {
        std::unique_lock<std::shared_mutex> persist_lock(persist_mutex_);
        std::shared_lock<std::shared_mutex> state_lock(state_mutex_);
        if (listener_) {
            if (persist_clean_epoch_ == persist_epoch_) {
                return;
            }
            target_epoch = persist_epoch_;
            listener = listener_;
        } else {
            return;
        }
    }
    listener();
    {
        std::unique_lock<std::shared_mutex> persist_lock(persist_mutex_);
        if (target_epoch > persist_clean_epoch_) {
            persist_clean_epoch_ = target_epoch;
        }
    }
}

void PromotionEngine::set_change_listener(ChangeListener listener) {
    std::unique_lock<std::shared_mutex> lock(state_mutex_);
    listener_ = std::move(listener);
}

void PromotionEngine::close_admission() {
    std::unique_lock<std::shared_mutex> lock(state_mutex_);
    admission_open_ = false;
}

void PromotionEngine::open_admission() {
    std::unique_lock<std::shared_mutex> lock(state_mutex_);
    admission_open_ = true;
}

bool PromotionEngine::admission_open() const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    return admission_open_;
}

CoordinatorAuthority PromotionEngine::authority() const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    return CoordinatorAuthority{state_.coordinator, state_.epoch};
}

CoordinatorId PromotionEngine::coordinator_id() const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    return state_.coordinator;
}

EngineConfig PromotionEngine::config() const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    return config_;
}

Result<PolicyGeneration> PromotionEngine::publish_policy(PromotionPolicy policy) {
    const Status validation = policy.validate();
    if (validation.failed()) {
        return validation;
    }
    policy.policy_digest = policy.compute_digest();
    const PolicyGeneration generation = policy.generation;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (policy.id == state_.active_policy && !(policy.generation > state_.active_policy_generation)) {
            return Status(ErrorCode::Conflict,
                          "republishing the same policy identity requires an advancing generation");
        }
        state_.set_active_policy(std::move(policy));
        ++persist_epoch_;

        HistoryEvent event;
        event.sequence = state_.next_sequence();
        event.kind = HistoryEventKind::PolicyPublished;
        event.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
        event.note = "policy generation " + generation.to_string() + " published";
        if (state_.history.size() >= config_.max_history_events) {
            state_.history.erase(state_.history.begin());
        }
        state_.history[event.sequence] = event;
    }
    notify_change();
    return generation;
}

Result<CoordinatorEpoch> PromotionEngine::restart(CoordinatorEpoch epoch) {
    const CoordinatorEpoch applied = epoch;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!epoch.valid() || !(epoch > state_.epoch)) {
            return Status(ErrorCode::InvalidCount, "a coordinator restart must advance the coordinator epoch");
        }
        state_.epoch = epoch;
        ++persist_epoch_;

        // Reservations held under the previous epoch are not authority. They
        // are released so a crashed holder cannot permanently block progress,
        // and a conservative recovery note records the release.
        std::vector<ArtifactId> released;
        released.reserve(state_.pending.size());
        for (const auto& [id, pending] : state_.pending) {
            (void)pending;
            released.push_back(id);
        }
        for (const ArtifactId& id : released) {
            const auto it = state_.pending.find(id);
            if (it == state_.pending.end()) {
                continue;
            }
            HistoryEvent event;
            event.sequence = state_.next_sequence();
            event.kind = HistoryEventKind::RecoveryNote;
            event.artifact = id;
            event.artifact_revision = it->second.artifact_revision;
            event.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
            event.note = "reservation released by coordinator restart; plan " + it->second.plan.to_string() +
                         " is not authority under the new epoch";
            state_.history[event.sequence] = event;
            state_.pending.erase(it);
        }
    }
    notify_change();
    return applied;
}

std::size_t PromotionEngine::recover_in_flight() {
    std::size_t released = 0;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        std::vector<ArtifactId> ids;
        ids.reserve(state_.pending.size());
        for (const auto& [id, pending] : state_.pending) {
            (void)pending;
            ids.push_back(id);
        }
        for (const ArtifactId& id : ids) {
            const auto it = state_.pending.find(id);
            if (it == state_.pending.end()) {
                continue;
            }
            HistoryEvent event;
            event.sequence = state_.next_sequence();
            event.kind = HistoryEventKind::RecoveryNote;
            event.artifact = id;
            event.artifact_revision = it->second.artifact_revision;
            event.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
            event.note = "in-flight transition recovered conservatively: not promoted, reservation released";
            state_.history[event.sequence] = event;
            state_.pending.erase(it);
            ++released;
        }
        if (released > 0) {
            ++persist_epoch_;
        }
    }
    if (released > 0) {
        notify_change();
    }
    return released;
}

Result<ArtifactRecord> PromotionEngine::register_artifact(const ArtifactRegistration& registration) {
    const Status validation = registration.validate();
    if (validation.failed()) {
        return validation;
    }
    ArtifactRecord stored;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!admission_open_) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is not admitting new work");
        }
        const auto existing = state_.artifacts.find(registration.id);
        if (existing == state_.artifacts.end() && state_.artifacts.size() >= config_.max_artifacts) {
            return Status(ErrorCode::AdmissionRejected, "artifact registry is at its configured bound");
        }

        // One content digest must not be registered under two artifact classes:
        // a digest names content, and conflicting classification of identical
        // content is a governance error rather than a second artifact.
        for (const auto& [other_id, other_chain] : state_.artifacts) {
            for (const ArtifactRecord& other : other_chain) {
                if (other.digest == registration.digest && other.kind != registration.kind) {
                    return Status(ErrorCode::Conflict,
                                  "this content digest is already registered under a different artifact class",
                                  other_id.to_string());
                }
            }
        }

        ArtifactRecord record;
        record.id = registration.id;
        record.kind = registration.kind;
        record.digest = registration.digest;
        record.size_bytes = registration.size_bytes;
        record.name = registration.name;
        record.producer = registration.producer;
        record.provenance = registration.provenance;
        std::sort(record.provenance.begin(), record.provenance.end());
        record.dependencies = registration.dependencies;
        std::sort(record.dependencies.begin(), record.dependencies.end());
        record.dependencies.erase(std::unique(record.dependencies.begin(), record.dependencies.end()),
                                  record.dependencies.end());
        record.revision = state_.revision_generator.next();
        record.stage_generation = StageGeneration(1);
        record.stage = state_.policy().entry_stage;

        std::vector<ArtifactRecord>& chain = state_.artifacts[registration.id];
        if (chain.size() >= config_.max_artifact_revisions_per_id) {
            return Status(ErrorCode::AdmissionRejected,
                          "artifact identity has reached its configured revision bound");
        }
        if (!chain.empty() && chain.back().digest == registration.digest) {
            return Status(ErrorCode::AlreadyExists,
                          "artifact identity already has this exact content digest as its current revision",
                          registration.id.to_string());
        }

        // A new revision supersedes the previous revision's current authority.
        // The earlier revision keeps its history: it is not erased and not
        // declared invalid, only no longer current.
        if (!chain.empty()) {
            ArtifactRecord& previous = chain.back();
            previous.supersession.active = true;
            previous.supersession.successor = record.id;
            previous.supersession.successor_revision = record.revision;
            previous.supersession.reason = "newer revision of the same artifact identity was registered";
            previous.supersession.authority =
                AuthorityId::from_parts(state_.coordinator.high(), state_.epoch.value());
            previous.supersession.sequence = state_.next_sequence();
            previous.last_sequence = previous.supersession.sequence;
            if (previous.stage != Stage::Promoted && previous.stage != Stage::Revoked &&
                previous.stage != Stage::Retired) {
                previous.stage = Stage::Superseded;
                previous.stage_generation = previous.stage_generation.next();
            }

            HistoryEvent supersede_event;
            supersede_event.sequence = previous.supersession.sequence;
            supersede_event.kind = HistoryEventKind::ArtifactSupersededRegistration;
            supersede_event.artifact = previous.id;
            supersede_event.artifact_revision = previous.revision;
            supersede_event.from = previous.stage;
            supersede_event.to = previous.stage;
            supersede_event.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
            supersede_event.note = "superseded by revision " + record.revision.to_string();
            state_.history[supersede_event.sequence] = supersede_event;
        }

        record.created_sequence = state_.next_sequence();
        record.created_unix_millis = now_millis();
        record.last_sequence = record.created_sequence;
        record.generation = ArtifactGeneration(static_cast<std::uint64_t>(chain.size()) + 1);

        state_.artifact_generation = state_.artifact_generation.next();
        chain.push_back(record);
        stored = record;
        ++persist_epoch_;

        HistoryEvent event;
        event.sequence = record.created_sequence;
        event.kind = HistoryEventKind::ArtifactRegistered;
        event.artifact = record.id;
        event.artifact_revision = record.revision;
        event.to = record.stage;
        event.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
        event.note = "revision " + record.revision.to_string() + " digest " + record.digest.to_string();
        if (state_.history.size() >= config_.max_history_events) {
            state_.history.erase(state_.history.begin());
        }
        state_.history[event.sequence] = event;
    }
    notify_change();
    return stored;
}

Result<EvidenceRecord> PromotionEngine::submit_evidence(const EvidenceSubmission& submission) {
    const Status validation = submission.validate();
    if (validation.failed()) {
        return validation;
    }
    EvidenceRecord stored;
    {
        std::unique_lock<std::shared_mutex> lock(state_mutex_);
        if (!admission_open_) {
            return Status(ErrorCode::ShuttingDown, "the coordinator is not admitting new work");
        }
        const ArtifactRecord* subject = state_.find_revision(submission.subject, submission.subject_revision);
        if (subject == nullptr) {
            return Status(ErrorCode::ArtifactNotFound,
                          "evidence references an artifact revision this coordinator does not hold",
                          submission.subject.to_string());
        }
        if (subject->digest != submission.subject_digest) {
            return Status(ErrorCode::DigestMismatch,
                          "evidence subject digest does not match the registered artifact revision",
                          submission.subject.to_string());
        }

        EvidenceKey key;
        key.subject = submission.subject;
        key.subject_revision = submission.subject_revision;
        key.type = submission.type;
        key.custom_type = submission.custom_type;
        key.producer = submission.producer;

        // An identical resubmission by the same producer incarnation is a new
        // generation of the same evidence key, not a second record that shares
        // the identity of the one it replaces. The published revision of that
        // key keeps its own identity and is marked superseded, pointing at its
        // successor, so a query can still show what was believed before.
        EvidenceId previous{};
        EvidenceGeneration previous_generation{};
        bool replaced = false;
        for (const auto& [id, record] : state_.evidence) {
            if (EvidenceKey::of(record) == key && !record.superseded) {
                previous = id;
                previous_generation = record.generation;
                replaced = true;
                break;
            }
        }

        std::size_t per_revision = 0;
        for (const auto& [id, record] : state_.evidence) {
            (void)id;
            if (record.subject == submission.subject && record.subject_revision == submission.subject_revision) {
                ++per_revision;
            }
        }
        if (!replaced) {
            if (state_.evidence.size() >= config_.max_evidence_records) {
                return Status(ErrorCode::AdmissionRejected, "evidence store is at its configured bound");
            }
            if (per_revision >= config_.max_evidence_per_artifact_revision) {
                return Status(ErrorCode::AdmissionRejected,
                              "artifact revision has reached its configured evidence bound");
            }
        }

        EvidenceRecord record;
        record.id = state_.evidence_generator.next();
        record.type = submission.type;
        record.custom_type = submission.custom_type;
        record.subject = submission.subject;
        record.subject_digest = submission.subject_digest;
        record.subject_revision = submission.subject_revision;
        record.producer = submission.producer;
        record.result = submission.result;
        record.confidence_milli = submission.confidence_milli;
        record.measurement = submission.measurement;
        record.detail = submission.detail;
        record.payload_digest = submission.payload_digest;
        record.provenance = submission.provenance;
        record.created_sequence = state_.next_sequence();
        record.produced_unix_millis = submission.produced_unix_millis;
        record.has_validity_window = submission.has_validity_window;
        record.valid_from_unix_millis = submission.valid_from_unix_millis;
        record.valid_until_unix_millis = submission.valid_until_unix_millis;
        record.environment = submission.environment;

        if (replaced) {
            EvidenceRecord updated = state_.evidence.at(previous);
            record.generation = previous_generation.next();
            updated.superseded = true;
            updated.superseded_by = record.id;
            state_.evidence[previous] = updated;

            HistoryEvent supersede_event;
            supersede_event.sequence = state_.next_sequence();
            supersede_event.kind = HistoryEventKind::EvidenceSuperseded;
            supersede_event.artifact = record.subject;
            supersede_event.artifact_revision = record.subject_revision;
            supersede_event.evidence = record.id;
            supersede_event.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
            supersede_event.note = "evidence generation " + record.generation.to_string() +
                                   " replaced the previous record for this producer and class";
            if (state_.history.size() >= config_.max_history_events) {
                state_.history.erase(state_.history.begin());
            }
            state_.history[supersede_event.sequence] = supersede_event;
        } else {
            record.generation = EvidenceGeneration(1);
        }

        record.integrity_digest = compute_evidence_integrity(record);
        state_.evidence[record.id] = record;
        stored = record;
        ++persist_epoch_;

        HistoryEvent event;
        event.sequence = record.created_sequence;
        event.kind = HistoryEventKind::EvidenceSubmitted;
        event.artifact = record.subject;
        event.artifact_revision = record.subject_revision;
        event.evidence = record.id;
        event.authority = CoordinatorAuthority{state_.coordinator, state_.epoch};
        event.note = std::string(to_string(record.type)) + ' ' + to_string(record.result) + " generation " +
                     record.generation.to_string();
        if (state_.history.size() >= config_.max_history_events) {
            state_.history.erase(state_.history.begin());
        }
        state_.history[event.sequence] = event;
    }
    notify_change();
    return stored;
}

std::optional<PromotionEngine::ArtifactView> PromotionEngine::inspect_artifact(ArtifactId id) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    const ArtifactRecord* record = state_.find_current(id);
    if (record == nullptr) {
        return std::nullopt;
    }
    ArtifactView view;
    view.artifact = *record;
    for (const auto& [evidence_id, evidence] : state_.evidence) {
        (void)evidence_id;
        if (evidence.subject == id && evidence.subject_revision == record->revision) {
            ++view.evidence_count;
        }
    }
    for (const auto& [transition, promotion] : state_.records) {
        (void)transition;
        if (promotion.artifact == id) {
            ++view.promotion_record_count;
        }
    }
    view.has_active_reservation = state_.pending.count(id) > 0;
    return view;
}

std::optional<ArtifactRecord> PromotionEngine::inspect_revision(ArtifactId id, ArtifactRevision revision) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    const ArtifactRecord* record = state_.find_revision(id, revision);
    if (record == nullptr) {
        return std::nullopt;
    }
    return *record;
}

std::optional<EvidenceRecord> PromotionEngine::inspect_evidence(EvidenceId id) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    const auto it = state_.evidence.find(id);
    if (it == state_.evidence.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<PromotionDecision> PromotionEngine::inspect_decision(PromotionDecisionId id) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    const auto it = state_.decisions.find(id);
    if (it == state_.decisions.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<PromotionPlan> PromotionEngine::inspect_plan(PromotionPlanId id) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    const auto it = state_.plans.find(id);
    if (it == state_.plans.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<PromotionRecord> PromotionEngine::promotion_history(ArtifactId id) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    std::vector<PromotionRecord> out;
    for (const auto& [transition, record] : state_.records) {
        (void)transition;
        if (record.artifact == id) {
            out.push_back(record);
        }
    }
    std::sort(out.begin(), out.end(), [](const PromotionRecord& lhs, const PromotionRecord& rhs) {
        return lhs.sequence < rhs.sequence;
    });
    return out;
}

std::vector<HistoryEvent> PromotionEngine::artifact_history(ArtifactId id, std::size_t limit) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    std::vector<HistoryEvent> out;
    for (const auto& [sequence, event] : state_.history) {
        (void)sequence;
        if (event.artifact == id) {
            out.push_back(event);
        }
    }
    std::sort(out.begin(), out.end(), [](const HistoryEvent& lhs, const HistoryEvent& rhs) {
        return lhs.sequence < rhs.sequence;
    });
    if (out.size() > limit) {
        out.erase(out.begin(), out.end() - static_cast<std::ptrdiff_t>(limit));
    }
    return out;
}

std::vector<EvidenceRecord> PromotionEngine::evidence_for(ArtifactId id, ArtifactRevision revision) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    std::vector<EvidenceRecord> out;
    for (const auto& [evidence_id, record] : state_.evidence) {
        (void)evidence_id;
        if (record.subject == id && record.subject_revision == revision) {
            out.push_back(record);
        }
    }
    std::sort(out.begin(), out.end(), [](const EvidenceRecord& lhs, const EvidenceRecord& rhs) {
        return lhs.created_sequence < rhs.created_sequence;
    });
    return out;
}

std::optional<PendingTransition> PromotionEngine::pending_transition(ArtifactId id) const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    const auto it = state_.pending.find(id);
    if (it == state_.pending.end()) {
        return std::nullopt;
    }
    return it->second;
}

CoordinatorState PromotionEngine::snapshot() const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    CoordinatorState copy;
    copy.coordinator = state_.coordinator;
    copy.epoch = state_.epoch;
    copy.commit_sequence = state_.commit_sequence;
    copy.decision_sequence = state_.decision_sequence;
    copy.artifact_generation = state_.artifact_generation;
    copy.compatibility_generation = state_.compatibility_generation;
    copy.compatibility_profile = state_.compatibility_profile;
    copy.artifacts = state_.artifacts;
    copy.evidence = state_.evidence;
    copy.plans = state_.plans;
    copy.decisions = state_.decisions;
    copy.records = state_.records;
    copy.idempotency = state_.idempotency;
    copy.history = state_.history;
    copy.vetoes = state_.vetoes;
    copy.set_active_policy(state_.policy());
    // Identity generators are snapshotted so a restart never reissues an
    // identity that a previous process already handed out.
    copy.revision_generator = state_.revision_generator;
    copy.evidence_generator = state_.evidence_generator;
    copy.plan_generator = state_.plan_generator;
    copy.decision_generator = state_.decision_generator;
    copy.transition_generator = state_.transition_generator;
    copy.reservation_generator = state_.reservation_generator;
    copy.instance_generator = state_.instance_generator;
    copy.provenance_generator = state_.provenance_generator;
    // Reservations are deliberately excluded: a reservation held by a process
    // that no longer exists is not authority.
    return copy;
}

Status PromotionEngine::install_state(CoordinatorState state) {
    state.pending.clear();
    const Status consistency = state.verify_consistency();
    if (consistency.failed()) {
        return consistency;
    }
    std::unique_lock<std::shared_mutex> lock(state_mutex_);
    state_ = std::move(state);
    ++persist_epoch_;
    return Status::success();
}

Status PromotionEngine::check_invariants() const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);

    for (const auto& [id, revisions] : state_.artifacts) {
        if (revisions.empty()) {
            return Status(ErrorCode::InvariantViolation, "artifact identity has an empty revision chain");
        }
        std::size_t authoritative = 0;
        for (const ArtifactRecord& record : revisions) {
            if (!record.valid()) {
                return Status(ErrorCode::InvariantViolation, "artifact record is malformed", id.to_string());
            }
            if (record.currently_authoritative()) {
                ++authoritative;
            }
        }
        if (authoritative > 1) {
            return Status(ErrorCode::InvariantViolation,
                          "artifact identity has more than one currently promoted revision", id.to_string());
        }
    }

    // Reservations and artifact state must account exactly.
    for (const auto& [id, pending] : state_.pending) {
        const ArtifactRecord* record = state_.find_revision(pending.artifact, pending.artifact_revision);
        if (record == nullptr) {
            return Status(ErrorCode::InvariantViolation, "reservation references an unknown artifact revision",
                          id.to_string());
        }
        if (record->stage_generation != pending.stage_generation) {
            return Status(ErrorCode::InvariantViolation,
                          "reservation is bound to a stage generation that no longer exists", id.to_string());
        }
        if (record->stage != pending.from) {
            return Status(ErrorCode::InvariantViolation, "reservation source stage does not match artifact state",
                          id.to_string());
        }
    }

    // Every promoted revision must have a matching committed promotion record.
    for (const auto& [id, revisions] : state_.artifacts) {
        for (const ArtifactRecord& record : revisions) {
            if (!record.promoted) {
                continue;
            }
            bool found = false;
            for (const auto& [transition, promotion] : state_.records) {
                (void)transition;
                if (promotion.artifact_revision == record.revision && promotion.to == Stage::Promoted &&
                    promotion.artifact == record.id) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return Status(ErrorCode::InvariantViolation,
                              "promoted artifact has no committed promotion record", id.to_string());
            }
        }
    }

    // Evidence must never cross artifact identity, and its integrity must hold.
    for (const auto& [id, evidence] : state_.evidence) {
        const ArtifactRecord* subject = state_.find_revision(evidence.subject, evidence.subject_revision);
        if (subject == nullptr || subject->digest != evidence.subject_digest) {
            return Status(ErrorCode::InvariantViolation, "evidence is not bound to its artifact revision",
                          id.to_string());
        }
        if (compute_evidence_integrity(evidence) != evidence.integrity_digest) {
            return Status(ErrorCode::InvariantViolation, "evidence integrity digest does not match its content",
                          id.to_string());
        }
    }

    // A quarantined or revoked artifact must never be currently authoritative.
    for (const auto& [id, revisions] : state_.artifacts) {
        const ArtifactRecord& current = revisions.back();
        if (current.quarantine.active && current.stage == Stage::Promoted) {
            return Status(ErrorCode::InvariantViolation, "artifact is simultaneously quarantined and promoted",
                          id.to_string());
        }
        if (current.revocation.active && current.currently_authoritative()) {
            return Status(ErrorCode::InvariantViolation, "artifact is simultaneously revoked and authoritative",
                          id.to_string());
        }
    }

    // Committed promotion records must reference a live revision and decision.
    for (const auto& [transition, record] : state_.records) {
        const ArtifactRecord* subject = state_.find_revision(record.artifact, record.artifact_revision);
        if (subject == nullptr) {
            return Status(ErrorCode::InvariantViolation,
                          "promotion record references an unknown artifact revision", transition.to_string());
        }
        // Only a record that actually promotes an artifact cites a decision. A
        // supersession, a quarantine release, or a revocation is not produced by
        // a promotion decision, so requiring one there would reject the state the
        // engine itself just committed.
        if (record.to == Stage::Promoted && !state_.decisions.count(record.decision)) {
            return Status(ErrorCode::InvariantViolation, "promotion record references an unknown decision",
                          transition.to_string());
        }
    }
    return Status::success();
}

std::size_t PromotionEngine::count_pending_transitions() const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    return state_.pending.size();
}

std::size_t PromotionEngine::count_artifacts() const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    return state_.artifacts.size();
}

std::size_t PromotionEngine::count_evidence() const {
    std::shared_lock<std::shared_mutex> lock(state_mutex_);
    return state_.evidence.size();
}

}  // namespace artifact_promotion
