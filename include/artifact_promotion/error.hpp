// Artifact Promotion - typed failure semantics.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_ERROR_HPP
#define ARTIFACT_PROMOTION_ERROR_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// Bounded byte container and the global size bounds
// ---------------------------------------------------------------------------
using ByteBuffer = std::vector<std::uint8_t>;

// Text fields accepted from external callers are bounded before allocation.
inline constexpr std::size_t kMaxNameLength = 128;
inline constexpr std::size_t kMaxTextLength = 512;
inline constexpr std::size_t kMaxReferenceLength = 256;

// Bounds applied to durable state files and to single wire frames.
inline constexpr std::size_t kMaxSnapshotBytes = 256U * 1024U * 1024U;
inline constexpr std::size_t kMaxFrameBytes = 4U * 1024U * 1024U;

// ---------------------------------------------------------------------------
// ErrorCode
//
// Every meaningful failure carries a distinct code. Failure classes are never
// flattened into a single generic status, because retry policy, operator
// action, and promotion semantics differ per class.
// ---------------------------------------------------------------------------
enum class ErrorCode : int {
    Ok = 0,

    // Invalid input
    InvalidArgument,
    InvalidIdentity,
    InvalidDigest,
    InvalidName,
    InvalidCount,
    InvalidEnum,
    InvalidStage,
    InvalidTransition,
    Unsupported,
    PayloadTooLarge,
    NumericOverflow,

    // Lookup
    ArtifactNotFound,
    EvidenceNotFound,
    PolicyNotFound,
    PlanNotFound,
    DecisionNotFound,
    RequestNotFound,
    ReservationNotFound,

    // Duplicate and conflict
    AlreadyExists,
    Conflict,
    DuplicateRequest,

    // Evidence semantics
    EvidenceMissing,
    EvidenceMismatch,
    EvidenceStale,
    EvidenceRevoked,
    EvidenceSuperseded,
    EvidenceMalformed,
    EvidenceIntegrityFailure,
    EnvironmentMismatch,
    OrderingViolation,

    // Artifact semantics
    ArtifactMismatch,
    DigestMismatch,
    ArtifactGenerationStale,
    ArtifactQuarantined,
    ArtifactRevoked,
    ArtifactSuperseded,
    ArtifactRetired,

    // Policy semantics
    PolicyStale,
    PolicyViolation,
    PolicyGenerationStale,
    TransitionIllegal,
    CompatibilityFailed,
    ProvenanceMissing,
    ProvenanceMismatch,
    SecurityVeto,
    DependencyVeto,
    ApprovalRequired,

    // Authority semantics
    StaleCoordinatorEpoch,
    StaleWorkerBoot,
    StaleEvidenceGeneration,
    AuthorityStale,
    PlanExpired,
    PlanConsumed,
    NotAuthorized,

    // Transaction semantics
    ReservationHeld,
    ReservationLost,
    CommitUncertain,
    Cancelled,
    ShuttingDown,
    AdmissionRejected,

    // Persistence
    PersistenceCorrupt,
    PersistenceIoError,
    PersistenceFormatError,
    PersistenceVersionUnsupported,

    // Transport and protocol
    TransportError,
    ProtocolError,
    ProtocolTruncated,
    ProtocolOversized,
    ProtocolMalformed,
    ConnectionClosed,

    // Internal
    InternalError,
    InvariantViolation,
};

[[nodiscard]] const char* to_string(ErrorCode code) noexcept;
[[nodiscard]] bool is_retryable(ErrorCode code) noexcept;
[[nodiscard]] bool is_transport_failure(ErrorCode code) noexcept;
[[nodiscard]] bool is_semantic_failure(ErrorCode code) noexcept;

// ---------------------------------------------------------------------------
// StaticString
//
// Fixed-capacity text used for diagnostic messages. It keeps error values
// allocation-free and therefore avoids throwing paths in value plumbing.
// ---------------------------------------------------------------------------
class StaticString {
public:
    static constexpr std::size_t kCapacity = 192;

    constexpr StaticString() noexcept : size_(0) { buffer_[0] = '\0'; }

    constexpr StaticString(const char* text) noexcept : size_(0) {
        while (text != nullptr && text[size_] != '\0' && size_ < kCapacity) {
            buffer_[size_] = text[size_];
            ++size_;
        }
        buffer_[size_] = '\0';
    }

    constexpr StaticString(std::string_view text) noexcept : size_(0) {
        const std::size_t copy = text.size() < kCapacity ? text.size() : kCapacity;
        for (std::size_t i = 0; i < copy; ++i) {
            buffer_[i] = text[i];
        }
        size_ = copy;
        buffer_[size_] = '\0';
    }

    [[nodiscard]] constexpr std::string_view view() const noexcept {
        return std::string_view(buffer_, size_);
    }
    [[nodiscard]] constexpr const char* c_str() const noexcept { return buffer_; }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }

private:
    char buffer_[kCapacity + 1];
    std::size_t size_;
};

[[nodiscard]] bool operator==(const StaticString& lhs, const StaticString& rhs) noexcept;
[[nodiscard]] bool operator!=(const StaticString& lhs, const StaticString& rhs) noexcept;

// ---------------------------------------------------------------------------
// Reason
//
// Deterministic machine-readable explanation data. A promotion decision is
// never reduced to a bare boolean.
// ---------------------------------------------------------------------------
struct Reason {
    ErrorCode code = ErrorCode::Ok;
    StaticString text{};
    std::string subject{};  // operator readable identity of the offending object

    Reason() = default;
    Reason(ErrorCode c, std::string_view message, std::string subj = {})
        : code(c), text(message), subject(std::move(subj)) {}

    [[nodiscard]] std::string render() const;
    [[nodiscard]] bool ok() const noexcept { return code == ErrorCode::Ok; }
};

// ---------------------------------------------------------------------------
// Status
//
// Rich failure value: a code plus structured detail. All expected failures flow
// through Status or Result, never through exceptions used as control flow.
// ---------------------------------------------------------------------------
class Status {
public:
    Status() noexcept = default;
    Status(ErrorCode code, std::string_view message, std::string subject = {})
        : code_(code), message_(message), subject_(std::move(subject)) {}

    [[nodiscard]] static Status success() noexcept { return Status(); }

    [[nodiscard]] ErrorCode code() const noexcept { return code_; }
    [[nodiscard]] const StaticString& message() const noexcept { return message_; }
    [[nodiscard]] const std::string& subject() const noexcept { return subject_; }
    [[nodiscard]] bool ok() const noexcept { return code_ == ErrorCode::Ok; }
    [[nodiscard]] bool failed() const noexcept { return code_ != ErrorCode::Ok; }

    [[nodiscard]] bool retryable() const noexcept { return is_retryable(code_); }
    [[nodiscard]] bool transport_failure() const noexcept { return is_transport_failure(code_); }
    [[nodiscard]] bool semantic_failure() const noexcept { return is_semantic_failure(code_); }

    // Adds context to the offending subject without changing the failure class.
    Status& with_subject(std::string subject) {
        subject_ = std::move(subject);
        return *this;
    }

    [[nodiscard]] std::string render() const;

private:
    ErrorCode code_ = ErrorCode::Ok;
    StaticString message_{};
    std::string subject_{};
};

// ---------------------------------------------------------------------------
// Result<T>
// ---------------------------------------------------------------------------
template <typename T>
class Result {
public:
    Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
    Result(Status status) : storage_(std::in_place_index<1>, std::move(status)) {}

    [[nodiscard]] bool has_value() const noexcept { return storage_.index() == 0; }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] T& value() & { return std::get<0>(storage_); }
    [[nodiscard]] const T& value() const& { return std::get<0>(storage_); }
    [[nodiscard]] T&& value() && { return std::get<0>(std::move(storage_)); }

    [[nodiscard]] T value_or(T fallback) const {
        return has_value() ? std::get<0>(storage_) : std::move(fallback);
    }

    [[nodiscard]] const Status& status() const& { return std::get<1>(storage_); }
    [[nodiscard]] Status& status() & { return std::get<1>(storage_); }

    [[nodiscard]] ErrorCode code() const { return has_value() ? ErrorCode::Ok : status().code(); }

private:
    std::variant<T, Status> storage_;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
[[nodiscard]] inline Status make_status(ErrorCode code, std::string_view message, std::string subject = {}) {
    return Status(code, message, std::move(subject));
}

[[nodiscard]] inline Status from_error(ErrorCode code, std::string_view message, std::string subject = {}) {
    return Status(code, message, std::move(subject));
}

// Copies a Status out of a const Result so it can be returned by value.
[[nodiscard]] inline Status detached_status(const Status& status) { return status; }

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_ERROR_HPP
