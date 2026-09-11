# Artifact Promotion 1.0.0 - frozen public API contract

Generated for authors of tests, examples, and benchmarks. Every symbol below
already compiles under MSVC /W4 /WX. Do not invent additional API; read the
headers under include/artifact_promotion/ for the authoritative declarations.

Build entry points
==================
- `find_package(ArtifactPromotion CONFIG REQUIRED)`, targets `Summon::ArtifactPromotion`
  and `Summon::ArtifactPromotionDistributed`.
- In-tree tests link `artifact_promotion_test_support` which links both.
- Include root: `#include "artifact_promotion/engine.hpp"` etc.
- Namespace: `artifact_promotion` (nested `artifact_promotion::protocol`, `artifact_promotion::net`, `artifact_promotion::wire`).
- C++20. No exceptions used for expected failures: everything returns `Result<T>` or `Status`.
- Warnings are errors. Avoid unused variables/parameters and signed/unsigned narrowing.

Core value types
================
```
ErrorCode        enum class, plus to_string(ErrorCode), is_retryable(code)
StaticString     fixed 192-char string; .view() -> std::string_view
Reason           { ErrorCode code; StaticString text; std::string subject; }  .render() -> std::string
Status           Status::success(); Status(code, message, subject=std::string{});
                 .ok() .failed() .code() .message() .subject() .render()
Result<T>        .has_value() .value() .status() .code()   (implicit from T or Status)
detached_status(const Status&) -> Status
```

Strong identity domains (all distinct types; `.valid()`, `.invalid()`, `.to_string()`, static `parse()`)
```
ArtifactId ArtifactRevision ArtifactInstanceId PromotionRequestId PromotionAttemptId
PromotionDecisionId PromotionPlanId PromotionPolicyId EvidenceId WorkerId WorkerBootId
CoordinatorId CompatibilityProfileId ApprovalId AuthorityId SnapshotId TransitionId
ReservationId ProvenanceRef  ArtifactDigest
```
Construction: `X::from_parts(high, low)` (both non-zero for validity), `IdentityGenerator<Tag>` with `.next()`.
Counter types: `ArtifactGeneration PolicyGeneration EvidenceGeneration CoordinatorEpoch
StageGeneration CommitSequence CompatibilityGeneration DecisionSequence`, each `Counter<Tag>`
with `Counter(n)`, `.value()`, `.valid()`, `.next()`, `.to_string()`.

Digest
```
Digest::from_string(std::string_view) -> Digest      // SHA-256
Digest::from_bytes(const uint8_t*, size_t)
Digest::parse(std::string_view) -> std::optional<Digest>   // 64 lower-case hex, non-zero
digest.to_string() -> std::string ; digest.valid() ; digest.to_identity() -> ArtifactDigest
sha256(std::string_view | const ByteBuffer& | const uint8_t*, size_t) -> Digest
```

Lifecycle
```
enum class Stage : uint8_t { Invalid, Candidate, Verified, Qualified, Staged, Approved,
                             Promoted, Quarantined, Revoked, Superseded, Retired }
to_string(Stage), stage_from_string(string_view) -> optional<Stage>, is_valid_stage_value(uint64)
LifecycleGraph: .reference() static; .add_edge(from,to) -> bool (nodiscard);
                .has_edge(from,to); .successors(from) -> vector<Stage>;
                .edges() -> const vector<Edge>& (Edge{from,to}); .validate(entry) -> Status;
                .canonicalize(); .graph_digest() -> Digest
```

Artifact model
```
enum class ArtifactKind : uint8_t { Invalid, Model, Kernel, Executable, Library, Configuration,
    Dataset, ResearchResult, BenchmarkBundle, GeneratedCode, DeploymentManifest, Opaque }
to_string(ArtifactKind), artifact_kind_from_string, is_valid_artifact_kind(uint64)

struct ProducerIncarnation { WorkerId worker; WorkerBootId boot; }   // .valid(), .process_bound()
struct ProvenanceRecord { ProvenanceRef reference; std::string source, subject; ProvenanceResolution resolution; }
enum class ProvenanceResolution : uint8_t { Unknown, Resolved, Superseded, Rejected }
struct CompatibilityDescriptor { CompatibilityProfileId profile; CompatibilityGeneration generation; }

struct ArtifactRegistration {
    ArtifactId id; ArtifactKind kind; Digest digest; std::uint64_t size_bytes;
    std::string name;                       // must satisfy is_valid_name: [A-Za-z0-9_.:/-]{1,128}
    ProducerIncarnation producer;           // {} is valid: "not process bound"
    std::vector<ProvenanceRecord> provenance;   // max 64
    std::vector<std::string> dependencies;      // max 64
    Status validate() const;
};

struct ArtifactRecord {
    ArtifactId id; ArtifactRevision revision; ArtifactGeneration generation;
    ArtifactKind kind; Digest digest; std::uint64_t size_bytes; std::string name;
    ProducerIncarnation producer; CommitSequence created_sequence; std::uint64_t created_unix_millis;
    std::vector<ProvenanceRecord> provenance; std::vector<std::string> dependencies;
    Stage stage; StageGeneration stage_generation;
    bool promoted; PromotionDecisionId promotion_decision; AuthorityId promotion_authority;
    CommitSequence promotion_sequence; CommitSequence last_sequence;
    QuarantineRecord quarantine; RevocationRecord revocation; SupersessionRecord supersession;
    bool valid() const; bool currently_authoritative() const; bool blocked_by_quarantine() const;
    bool has_provenance(ProvenanceRef) const;
};
std::string render_artifact_summary(const ArtifactRecord&);
```

Evidence model
```
enum class EvidenceType : uint8_t { Invalid, BuildPass=1, UnitTestPass, IntegrationTestPass,
  PropertyTestPass, AdversarialTestPass, SanitizerPass, SecurityScanPass, BenchmarkResult,
  CompatibilityPass, AbiCompatibilityPass, DataValidationPass, ModelEvalPass, HumanApproval,
  MachineCriticApproval, ReproducibilityPass, SignatureValid, ProvenanceComplete,
  DependencyPolicyPass, Custom=63 }
enum class EvidenceResult : uint8_t { Unknown, Pass, Fail, Inconclusive, NotApplicable }
to_string(...), is_valid_evidence_type(uint64), is_valid_evidence_result(uint64),
satisfies_mandatory_gate(EvidenceResult)

struct EvidenceSubmission {
    ArtifactId subject; Digest subject_digest; ArtifactRevision subject_revision;
    EvidenceType type; std::string custom_type;      // required iff type==Custom
    ProducerIncarnation producer;                    // set by the transport, settable in-process
    EvidenceResult result; std::uint32_t confidence_milli;   // 0..1000
    std::string measurement, detail; Digest payload_digest;  // payload_digest must be non-zero
    ProvenanceRef provenance; std::uint64_t produced_unix_millis;
    bool has_validity_window; std::uint64_t valid_from_unix_millis, valid_until_unix_millis;
    std::string environment;
    Status validate() const;
};

struct EvidenceRecord { EvidenceId id; EvidenceType type; EvidenceGeneration generation;
    std::string custom_type; ArtifactId subject; Digest subject_digest; ArtifactRevision subject_revision;
    ProducerIncarnation producer; EvidenceResult result; std::uint32_t confidence_milli;
    std::string measurement, detail; Digest payload_digest, integrity_digest; ProvenanceRef provenance;
    CommitSequence created_sequence; std::uint64_t produced_unix_millis;
    bool has_validity_window; std::uint64_t valid_from_unix_millis, valid_until_unix_millis;
    std::string environment; bool revoked; std::string revocation_reason;
    AuthorityId revocation_authority; CommitSequence revocation_sequence;
    bool superseded; EvidenceId superseded_by; bool valid() const; };

Digest compute_evidence_integrity(const EvidenceRecord&);
Digest compute_snapshot_digest(ArtifactId, ArtifactRevision, const Digest&, std::vector<EvidenceSnapshotEntry>);
```

Policy model
```
enum class GateKind : uint8_t { Invalid, EvidenceRequired, EvidenceFreshness, EvidenceIntegrity,
  ArtifactIdentity, ArtifactNotQuarantined, ArtifactNotRevoked, ArtifactNotSuperseded,
  ProvenanceRequired, ProvenanceResolved, CompatibilityGenerationCurrent, EnvironmentBinding,
  DependentArtifactPromoted, ApprovalRequired, SecurityVetoClear, DependencyVetoClear,
  PolicyGenerationCurrent, CoordinatorEpochCurrent, NoConflictingTransition }
enum class OrderingRule : uint8_t { None, LowerCommitSequence, HigherCommitSequence,
  LexicographicArtifactId, LexicographicDigest }

struct Gate { GateKind kind; EvidenceType evidence_type; std::string custom_evidence_type;
  std::uint64_t max_age_millis; CompatibilityGeneration required_compatibility_generation;
  std::string required_environment; ProvenanceRef required_provenance; std::string label;
  Status validate() const; std::string describe() const; };

struct PolicyRule { bool has_kind_scope; ArtifactKind kind_scope; Stage from, to;
  std::vector<Gate> requirements; std::vector<GateKind> preferences; OrderingRule ordering;
  bool allow_idempotent_replay, allow_rollback_eligibility, supersedes_previous;
  bool matches(ArtifactKind, Stage, Stage) const; Status validate() const; };

struct PromotionPolicy { PromotionPolicyId id; PolicyGeneration generation; std::string name, description;
  LifecycleGraph graph; Stage entry_stage; std::vector<PolicyRule> rules; Digest policy_digest;
  Status validate() const; Digest compute_digest() const;
  const PolicyRule* find_rule(ArtifactKind, Stage, Stage) const; bool allows_transition(...) const; };
PromotionPolicy make_reference_policy(PromotionPolicyId, PolicyGeneration);

struct CoordinatorAuthority { CoordinatorId coordinator; CoordinatorEpoch epoch; bool valid() const; };
```

Decision and plan
```
enum class PromotionOutcome : uint8_t { Invalid, PromotionEligible, PromotionCommitted,
  PromotionIneligible, RevalidationRequired, EvidenceMissing, EvidenceStale, EvidenceRevoked,
  EvidenceMismatch, ArtifactMismatch, DigestMismatch, TransitionIllegal, PolicyStale,
  CompatibilityFailed, ApprovalRequired, Quarantined, Revoked, Superseded, Conflict,
  AlreadyPromoted, OutcomeUnknown, Unsupported, ArtifactNotFound, PolicyNotFound, Cancelled,
  AuthorityStale, ProvenanceMissing, SecurityVeto, DependencyVeto, AdmissionRejected }
is_success_outcome(PromotionOutcome)  // Eligible || Committed || AlreadyPromoted

enum class GateStatus : uint8_t { NotEvaluated, Satisfied, Failed, Unknown, NotApplicable }
struct GateExplanation { GateKind kind; std::string label; GateStatus status; ErrorCode code;
                         std::string detail; std::string render() const; };
struct EvidenceFinding { EvidenceId id; EvidenceType type; std::string custom_type;
  EvidenceGeneration generation; EvidenceResult result; Digest subject_digest;
  ArtifactRevision subject_revision; ErrorCode code; std::string detail; };

struct PromotionDecision { PromotionDecisionId id; PromotionRequestId request; PromotionAttemptId attempt;
  ArtifactId artifact; ArtifactRevision artifact_revision; ArtifactGeneration artifact_generation;
  Digest artifact_digest; ArtifactKind artifact_kind; Stage from, to; PromotionOutcome outcome;
  PromotionPolicyId policy; PolicyGeneration policy_generation; Digest policy_digest;
  CoordinatorAuthority authority; DecisionSequence sequence; Digest evidence_snapshot_digest;
  std::vector<GateExplanation> gates; std::vector<EvidenceFinding> findings; std::vector<Reason> reasons;
  PromotionPlanId plan; bool authoritative; std::optional<std::uint64_t> decided_unix_millis;
  bool eligible() const; bool committed() const; bool succeeded() const;
  std::size_t failed_gate_count() const; std::vector<std::string> failed_gate_labels() const;
  std::string render() const; };

struct PromotionRequest { ArtifactId artifact; ArtifactRevision expected_revision; Digest expected_digest;
  Stage requested_stage; PromotionRequestId request; PromotionAttemptId attempt;
  CoordinatorAuthority authority; ProducerIncarnation requester; };

struct PromotionPlan { PromotionPlanId id; PromotionRequestId request; PromotionAttemptId attempt;
  PromotionDecisionId decision; ArtifactId artifact; ArtifactRevision artifact_revision;
  ArtifactGeneration artifact_generation; Digest artifact_digest; ArtifactKind artifact_kind;
  Stage from, to; StageGeneration stage_generation; PromotionPolicyId policy;
  PolicyGeneration policy_generation; Digest policy_digest, lifecycle_digest;
  CoordinatorAuthority authority; Digest evidence_snapshot_digest; std::size_t evidence_entry_count;
  CompatibilityProfileId compatibility_profile; CompatibilityGeneration compatibility_generation;
  CommitSequence artifact_sequence, created_sequence; DecisionSequence decision_sequence;
  bool has_expiry; std::uint64_t expires_unix_millis;
  bool valid() const; std::string render() const; bool operator==(const PromotionPlan&) const; };

struct PromotionRecord { TransitionId transition; ArtifactId artifact; ArtifactRevision artifact_revision;
  Digest artifact_digest; Stage from, to; PromotionDecisionId decision; PromotionPlanId plan;
  PromotionRequestId request; PromotionAttemptId attempt; PromotionPolicyId policy;
  PolicyGeneration policy_generation; CoordinatorAuthority authority; Digest evidence_snapshot_digest;
  CommitSequence sequence; std::uint64_t committed_unix_millis; std::string note; bool valid() const; };

Digest compute_request_digest(const PromotionRequest&);
```

Coordinator state and persistence
```
enum class HistoryEventKind : uint8_t { Invalid, ArtifactRegistered, ArtifactSupersededRegistration,
  EvidenceSubmitted, EvidenceSuperseded, EvidenceRevoked, PolicyPublished, PromotionEvaluated,
  PromotionCommitted, PromotionRejected, Quarantined, QuarantineReleased, Revoked, Superseded,
  Retired, RecoveryNote }
struct HistoryEvent { CommitSequence sequence; HistoryEventKind kind; ArtifactId artifact;
  ArtifactRevision artifact_revision; EvidenceId evidence; PromotionDecisionId decision;
  PromotionOutcome outcome; Stage from, to; CoordinatorAuthority authority; std::string note; };
struct PendingTransition { ReservationId id; ArtifactId artifact; ArtifactRevision artifact_revision;
  ArtifactGeneration artifact_generation; StageGeneration stage_generation; Stage from, to;
  PromotionPlanId plan; PromotionRequestId request; PromotionAttemptId attempt;
  CoordinatorAuthority authority; CommitSequence created_sequence; std::uint64_t created_unix_millis; };
struct IdempotencyRecord { ... };
struct VetoState { bool security_veto; std::string security_reason; bool dependency_veto; std::string dependency_reason; };
struct CoordinatorState { CoordinatorId coordinator; CoordinatorEpoch epoch; CommitSequence commit_sequence;
  DecisionSequence decision_sequence; ArtifactGeneration artifact_generation;
  CompatibilityGeneration compatibility_generation; CompatibilityProfileId compatibility_profile;
  PromotionPolicyId active_policy; PolicyGeneration active_policy_generation; Digest active_policy_digest;
  std::map<ArtifactId, std::vector<ArtifactRecord>> artifacts;
  std::map<EvidenceId, EvidenceRecord> evidence; std::map<PromotionPlanId, PromotionPlan> plans;
  std::map<PromotionDecisionId, PromotionDecision> decisions;
  std::map<TransitionId, PromotionRecord> records;
  std::map<PromotionRequestId, IdempotencyRecord> idempotency;
  std::map<CommitSequence, HistoryEvent> history; std::map<ArtifactId, VetoState> vetoes;
  std::map<ArtifactId, PendingTransition> pending;
  const ArtifactRecord* find_current(ArtifactId) const; ArtifactRecord* find_current(ArtifactId);
  const ArtifactRecord* find_revision(ArtifactId, ArtifactRevision) const;
  ArtifactRecord* find_revision(ArtifactId, ArtifactRevision);
  const PromotionPolicy& policy() const; void set_active_policy(PromotionPolicy);
  Status verify_consistency() const; std::size_t pending_size() const; };

class StatePersistence {   // artifact_promotion/persistence.hpp
  static constexpr std::uint16_t kFormatVersion = 1;
  static Result<ByteBuffer> encode(const CoordinatorState&);
  static Result<CoordinatorState> decode(const ByteBuffer&);
  static Result<CoordinatorState> load(const std::string& path);
  static Status save(const std::string& path, const CoordinatorState&);
};

File helpers (artifact_promotion/io.hpp)
  Result<ByteBuffer> read_file(const std::string&);
  Status atomic_write_file(const std::string&, const ByteBuffer&);
  Status remove_file(const std::string&); bool file_exists(const std::string&);
  std::string parent_directory(std::string_view); Status create_directories(const std::string&);
  void write_stdout(std::string_view); void write_stderr(std::string_view);
```

PromotionEngine (artifact_promotion/engine.hpp)
```
struct EngineConfig { max_artifacts=100000; max_artifact_revisions_per_id=64; max_evidence_records=500000;
  max_evidence_per_artifact_revision=256; max_policies_retained=16; max_pending_promotions=4096;
  max_plans_retained=4096; max_decisions_retained=65536; max_records_retained=65536;
  max_history_events=262144; max_evidence_per_snapshot=256; plan_ttl_millis=60000;
  reservation_stale_millis=30000; future_skew_tolerance_millis=5000; identity_salt_seed=0x5A17C0DE;
  bool valid() const; static EngineConfig defaults(); };

class PromotionEngine {
  using Clock = std::uint64_t;                       // unix epoch milliseconds
  explicit PromotionEngine(EngineConfig = defaults(), CoordinatorEpoch = CoordinatorEpoch(1));
  ~PromotionEngine();
  static Clock now_millis() noexcept;

  Result<PolicyGeneration> publish_policy(PromotionPolicy);
  Result<CoordinatorEpoch> restart(CoordinatorEpoch);
  std::size_t recover_in_flight();

  Result<ArtifactRecord> register_artifact(const ArtifactRegistration&);
  Result<EvidenceRecord> submit_evidence(const EvidenceSubmission&);

  struct ArtifactView { ArtifactRecord artifact; std::size_t evidence_count;
    std::size_t promotion_record_count; bool has_active_reservation; };
  std::optional<ArtifactView> inspect_artifact(ArtifactId) const;
  std::optional<ArtifactRecord> inspect_revision(ArtifactId, ArtifactRevision) const;
  std::optional<EvidenceRecord> inspect_evidence(EvidenceId) const;
  std::optional<PromotionDecision> inspect_decision(PromotionDecisionId) const;
  std::optional<PromotionPlan> inspect_plan(PromotionPlanId) const;
  std::vector<PromotionRecord> promotion_history(ArtifactId) const;
  std::vector<HistoryEvent> artifact_history(ArtifactId, std::size_t limit) const;
  std::vector<EvidenceRecord> evidence_for(ArtifactId, ArtifactRevision) const;
  std::optional<PendingTransition> pending_transition(ArtifactId) const;

  struct RollbackEligibility { bool eligible; PromotionOutcome outcome;
    std::vector<std::string> blocking_gates; std::string render() const; };
  RollbackEligibility evaluate_rollback_eligibility(ArtifactId) const;

  struct EvaluationResult { PromotionDecision decision; PromotionPlan plan; bool has_plan; };
  Result<EvaluationResult> evaluate(const PromotionRequest&);
  struct CommitResult { PromotionOutcome outcome; PromotionDecision decision;
    PromotionRecord record; bool has_record; };
  Result<CommitResult> commit(const PromotionPlan&);
  Result<CommitResult> promote(const PromotionRequest&);

  struct TrustMutation { PromotionOutcome outcome; ArtifactRecord artifact; PromotionRecord record;
    bool has_record; std::vector<Reason> reasons; };
  Result<TrustMutation> quarantine(ArtifactId, std::string reason_class, std::string detail, CoordinatorAuthority);
  Result<TrustMutation> release_quarantine(ArtifactId, CoordinatorAuthority);
  Result<TrustMutation> revoke(ArtifactId, PromotionDecisionId, std::string reason_class,
                               std::string detail, CoordinatorAuthority, EvidenceId cause = EvidenceId{});
  Result<TrustMutation> supersede(ArtifactId, ArtifactId successor, std::string reason, CoordinatorAuthority);
  Result<TrustMutation> retire(ArtifactId, CoordinatorAuthority);
  Result<TrustMutation> revoke_evidence(EvidenceId, std::string reason, CoordinatorAuthority);
  Status set_security_veto(ArtifactId, bool active, std::string reason);
  Status set_dependency_veto(ArtifactId, bool active, std::string reason);
  Result<CompatibilityGeneration> set_compatibility_generation(CompatibilityGeneration);

  std::optional<PromotionDecision> explain(ArtifactId, Stage destination) const;  // no mutation, unsigned

  CoordinatorState snapshot() const;
  Status install_state(CoordinatorState);
  CoordinatorAuthority authority() const; EngineConfig config() const; CoordinatorId coordinator_id() const;
  using ChangeListener = std::function<void()>;
  void set_change_listener(ChangeListener);   // invoked with NO engine lock held
  void close_admission(); void open_admission(); bool admission_open() const;
  Status check_invariants() const;
  std::size_t count_pending_transitions() const;
  std::size_t count_artifacts() const;
  std::size_t count_evidence() const;
};
```

Reference policy shape (what `make_reference_policy` installs), so tests can predict outcomes:
```
CANDIDATE -> VERIFIED      (all kinds): ArtifactIdentity, EvidenceIntegrity, ArtifactNotQuarantined,
                           ArtifactNotRevoked, SecurityVetoClear, DependencyVetoClear,
                           NoConflictingTransition, ProvenanceResolved,
                           EvidenceFreshness(PROVENANCE_COMPLETE, 30d)
VERIFIED  -> QUALIFIED     EXECUTABLE only: the common gates plus EvidenceRequired(BUILD_PASS),
                           EvidenceRequired(UNIT_TEST_PASS), EvidenceRequired(INTEGRATION_TEST_PASS),
                           EvidenceFreshness(BUILD_PASS, 7d),
                           EnvironmentBinding(UNIT_TEST_PASS, "windows-x64-msvc"),
                           CompatibilityGenerationCurrent(1), DependentArtifactPromoted
VERIFIED  -> QUALIFIED     MODEL only: the common gates plus EvidenceRequired(MODEL_EVAL_PASS),
                           EvidenceRequired(DATA_VALIDATION_PASS), EvidenceFreshness(MODEL_EVAL_PASS, 14d),
                           CompatibilityGenerationCurrent(1)
VERIFIED  -> QUALIFIED     every other kind: the common gates plus EvidenceRequired(PROVENANCE_COMPLETE)
QUALIFIED -> STAGED        all kinds: common gates + EvidenceRequired(REPRODUCIBILITY_PASS)
                           + CoordinatorEpochCurrent
STAGED    -> APPROVED      all kinds: common gates + ApprovalRequired(MACHINE_CRITIC_APPROVAL)
APPROVED  -> PROMOTED      all kinds: common gates + PolicyGenerationCurrent + CoordinatorEpochCurrent
                           + EvidenceRequired(SIGNATURE_VALID); supersedes_previous = true,
                           allow_rollback_eligibility = true
QUARANTINED -> CANDIDATE   all kinds: EvidenceRequired(SECURITY_SCAN_PASS) + EvidenceRequired(HUMAN_APPROVAL)
PROMOTED -> REVOKED        ArtifactIdentity only
PROMOTED -> SUPERSEDED     ArtifactIdentity only
No rule exists for a direct CANDIDATE->PROMOTED jump, so that request returns TransitionIllegal.
The engine's active policy supplies the lifecycle graph; the reference graph has the edges listed above.
```

Distributed reference deployment
```
#include "artifact_promotion/coordinator_server.hpp"
struct CoordinatorServer::Options { std::uint16_t port = 0; std::string state_path;
    EngineConfig engine; int backlog = 16; std::uint32_t connection_receive_timeout_millis = 250; };
class CoordinatorServer { explicit CoordinatorServer(Options); ~CoordinatorServer();
    Status start(); void stop(); std::uint16_t port() const; PromotionEngine& engine();
    const PromotionEngine& engine() const; bool running() const; std::size_t active_connections() const;
    std::uint64_t stale_authority_rejections() const; std::uint64_t duplicate_request_rejections() const;
    std::uint64_t protocol_rejections() const; Status persist_now(); };

#include "artifact_promotion/worker_client.hpp"
struct WorkerClient::Options { std::uint16_t port = 0; WorkerId worker; int connect_attempts = 20;
                               std::uint32_t connect_delay_millis = 25; };
class WorkerClient { explicit WorkerClient(Options); ~WorkerClient();
    Status connect(); void disconnect(); bool connected() const; WorkerId worker_id() const;
    WorkerBootId boot_id() const; CoordinatorId coordinator_id() const; CoordinatorEpoch epoch() const;
    Status handshake();   // re-learn authority after a coordinator restart
    Result<ArtifactRecord> register_artifact(const ArtifactRegistration&);
    Result<EvidenceRecord> submit_evidence(const EvidenceSubmission&);
    Result<PromotionEngine::CommitResult> promote(const PromotionRequest&);
    Result<PromotionEngine::EvaluationResult> evaluate(const PromotionRequest&);
    Result<protocol::ArtifactStatePayload> artifact_state(ArtifactId);
    Result<std::vector<PromotionRecord>> history(ArtifactId);
    Result<PromotionEngine::TrustMutation> quarantine(ArtifactId, std::string reason_class, std::string detail);
    Result<PromotionEngine::TrustMutation> revoke(ArtifactId, std::string reason_class, std::string detail);
    Result<PromotionDecision> explain(ArtifactId, Stage destination);
    Status request_snapshot_save();
    PromotionRequestId next_request_id(); PromotionAttemptId next_attempt_id();
    std::uint64_t frames_sent() const; };
```
The worker must complete `connect()` (which performs the handshake) before any other call.

Wire protocol (artifact_promotion/protocol.hpp)
```
namespace artifact_promotion::protocol
constexpr std::uint32_t kFrameMagic = 0x41504652; constexpr std::uint16_t kProtocolVersion = 1;
constexpr std::size_t kFrameHeaderSize = 92; constexpr std::size_t kFrameFooterSize = 32;
constexpr std::uint32_t kFlagNone = 0, kFlagNonIdempotent = 1;
enum class MessageType : std::uint16_t { Invalid, HelloRequest=1, HelloResponse, ... Error=100, Goodbye=101 };
to_string(MessageType), is_valid_message_type(uint64), is_request_type(MessageType)
struct Frame { std::uint16_t version; MessageType type; std::uint32_t flags;
  PromotionRequestId request; PromotionRequestId correlation; CoordinatorId coordinator;
  CoordinatorEpoch epoch; WorkerId worker; WorkerBootId boot; ByteBuffer payload; };
Result<ByteBuffer> encode_frame(const Frame&);
Result<Frame> decode_frame(const ByteBuffer&);
encode/decode pairs: hello, register_artifact, evidence_submission, evidence_record,
  promotion_request, promotion_result, artifact_state, history, trust, status, artifact_result
Header offsets used by a streaming reader: magic at 0, version at 4, type at 6,
  flags at 8, payload length at 12 (little-endian u32).
```

Networking (artifact_promotion/socket.hpp), namespace artifact_promotion::net
```
Status initialize_networking(); std::string last_socket_error();
class Socket { move-only; valid(); handle(); close(); Status send_all(const ByteBuf/nofer& | const uint8_t*, size_t);
  Status receive_exactly(uint8_t*, size_t); Status set_nodelay(bool);
  Status set_receive_timeout_millis(uint32_t); Status set_send_timeout_millis(uint32_t);
  std::string peer_address() const; };
class Listener { Status bind_loopback(uint16_t port); Status listen(int backlog);
  Result<Socket> accept_one(); void shutdown(); std::uint16_t bound_port() const; bool valid(); void close(); };
Result<Socket> connect_loopback(std::uint16_t port, int attempts, std::uint32_t delay_millis);
```

Test conventions in this repository
===================================
- No command lifetime limits, deadlines, or watchdogs anywhere. Tests run to natural completion.
- Tests print a single summary line and return a non-zero exit code on failure.
- On failure print the seed and a minimal reproduction context.
- Randomized tests must be seeded and deterministic; print the seed on failure.
- Concurrency tests must use genuine threads or processes, never sequential loops.
- Label proof honestly: REAL / SYNTHETIC / UNSUPPORTED.
