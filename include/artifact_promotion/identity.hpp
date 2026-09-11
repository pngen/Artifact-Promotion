// Artifact Promotion - strongly typed identity domains.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_IDENTITY_HPP
#define ARTIFACT_PROMOTION_IDENTITY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace artifact_promotion {

namespace detail {

[[nodiscard]] std::string render_hex128(std::uint64_t high, std::uint64_t low);
[[nodiscard]] bool parse_hex128(std::string_view text, std::uint64_t& high, std::uint64_t& low) noexcept;

}  // namespace detail

// ---------------------------------------------------------------------------
// Identity
//
// A 128-bit value carried by a phantom tag type. Two identity domains that
// happen to hold the same bytes are different types: they cannot be compared,
// ordered, assigned, or passed to each other without an explicit conversion.
// The all-zero value is the invalid sentinel for every domain and is never
// produced by the runtime's identity generators.
// ---------------------------------------------------------------------------
template <typename Tag>
class Identity {
public:
    using tag_type = Tag;

    constexpr Identity() noexcept = default;
    constexpr Identity(std::uint64_t high, std::uint64_t low) noexcept : high_(high), low_(low) {}

    [[nodiscard]] constexpr std::uint64_t high() const noexcept { return high_; }
    [[nodiscard]] constexpr std::uint64_t low() const noexcept { return low_; }

    [[nodiscard]] constexpr bool valid() const noexcept { return high_ != 0 || low_ != 0; }
    [[nodiscard]] constexpr bool invalid() const noexcept { return !valid(); }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return valid(); }

    // Canonical rendering: exactly 32 lower-case hex characters.
    [[nodiscard]] std::string to_string() const { return detail::render_hex128(high_, low_); }

    // Strict parser: exactly 32 lower-case hex characters, non-zero value.
    // Parsing is templated on the same tag, so a serialized identity of one
    // domain cannot silently become another domain.
    [[nodiscard]] static std::optional<Identity> parse(std::string_view text) {
        std::uint64_t high = 0;
        std::uint64_t low = 0;
        if (!detail::parse_hex128(text, high, low)) {
            return std::nullopt;
        }
        if (high == 0 && low == 0) {
            return std::nullopt;
        }
        return Identity(high, low);
    }

    [[nodiscard]] friend constexpr bool operator==(const Identity& lhs, const Identity& rhs) noexcept {
        return lhs.high_ == rhs.high_ && lhs.low_ == rhs.low_;
    }
    [[nodiscard]] friend constexpr bool operator!=(const Identity& lhs, const Identity& rhs) noexcept {
        return !(lhs == rhs);
    }
    [[nodiscard]] friend constexpr bool operator<(const Identity& lhs, const Identity& rhs) noexcept {
        if (lhs.high_ != rhs.high_) {
            return lhs.high_ < rhs.high_;
        }
        return lhs.low_ < rhs.low_;
    }
    [[nodiscard]] friend constexpr bool operator>(const Identity& lhs, const Identity& rhs) noexcept {
        return rhs < lhs;
    }
    [[nodiscard]] friend constexpr bool operator<=(const Identity& lhs, const Identity& rhs) noexcept {
        return !(rhs < lhs);
    }
    [[nodiscard]] friend constexpr bool operator>=(const Identity& lhs, const Identity& rhs) noexcept {
        return !(lhs < rhs);
    }

    // Deterministic big-endian byte encoding used by canonical digests.
    void write_bytes(std::uint8_t out[16]) const noexcept {
        for (int i = 0; i < 8; ++i) {
            out[i] = static_cast<std::uint8_t>((high_ >> (8 * (7 - i))) & 0xFFU);
            out[8 + i] = static_cast<std::uint8_t>((low_ >> (8 * (7 - i))) & 0xFFU);
        }
    }

    [[nodiscard]] static constexpr Identity from_parts(std::uint64_t high, std::uint64_t low) noexcept {
        return Identity(high, low);
    }

private:
    std::uint64_t high_ = 0;
    std::uint64_t low_ = 0;
};

// Identity domain tags. Each is a distinct type.
struct ArtifactIdTag {};
struct ArtifactDigestTag {};
struct ArtifactRevisionTag {};
struct ArtifactInstanceIdTag {};
struct PromotionRequestIdTag {};
struct PromotionAttemptIdTag {};
struct PromotionDecisionIdTag {};
struct PromotionPlanIdTag {};
struct PromotionPolicyIdTag {};
struct EvidenceIdTag {};
struct WorkerIdTag {};
struct WorkerBootIdTag {};
struct CoordinatorIdTag {};
struct CompatibilityProfileIdTag {};
struct ApprovalIdTag {};
struct AuthorityIdTag {};
struct SnapshotIdTag {};
struct TransitionIdTag {};
struct ReservationIdTag {};
struct ProvenanceRefTag {};

using ArtifactId = Identity<ArtifactIdTag>;
using ArtifactDigest = Identity<ArtifactDigestTag>;
using ArtifactRevision = Identity<ArtifactRevisionTag>;
using ArtifactInstanceId = Identity<ArtifactInstanceIdTag>;
using PromotionRequestId = Identity<PromotionRequestIdTag>;
using PromotionAttemptId = Identity<PromotionAttemptIdTag>;
using PromotionDecisionId = Identity<PromotionDecisionIdTag>;
using PromotionPlanId = Identity<PromotionPlanIdTag>;
using PromotionPolicyId = Identity<PromotionPolicyIdTag>;
using EvidenceId = Identity<EvidenceIdTag>;
using WorkerId = Identity<WorkerIdTag>;
using WorkerBootId = Identity<WorkerBootIdTag>;
using CoordinatorId = Identity<CoordinatorIdTag>;
using CompatibilityProfileId = Identity<CompatibilityProfileIdTag>;
using ApprovalId = Identity<ApprovalIdTag>;
using AuthorityId = Identity<AuthorityIdTag>;
using SnapshotId = Identity<SnapshotIdTag>;
using TransitionId = Identity<TransitionIdTag>;
using ReservationId = Identity<ReservationIdTag>;
using ProvenanceRef = Identity<ProvenanceRefTag>;

// ---------------------------------------------------------------------------
// Counter
//
// Newtype wrapper around a monotonically increasing counter. It makes it
// impossible to pass a generation where a sequence, epoch, or stage ordinal is
// expected. Counter::next() saturates rather than wrapping, so a counter can
// never move backwards.
// ---------------------------------------------------------------------------
template <typename Tag>
class Counter {
public:
    using tag_type = Tag;

    constexpr Counter() noexcept = default;
    constexpr explicit Counter(std::uint64_t value) noexcept : value_(value) {}

    [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
    [[nodiscard]] constexpr bool valid() const noexcept { return value_ != 0; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return valid(); }

    [[nodiscard]] Counter next() const noexcept {
        const std::uint64_t incremented = (value_ == UINT64_MAX) ? value_ : value_ + 1;
        return Counter(incremented);
    }

    [[nodiscard]] std::string to_string() const { return std::to_string(value_); }

    [[nodiscard]] friend constexpr bool operator==(const Counter& lhs, const Counter& rhs) noexcept {
        return lhs.value_ == rhs.value_;
    }
    [[nodiscard]] friend constexpr bool operator!=(const Counter& lhs, const Counter& rhs) noexcept {
        return !(lhs == rhs);
    }
    [[nodiscard]] friend constexpr bool operator<(const Counter& lhs, const Counter& rhs) noexcept {
        return lhs.value_ < rhs.value_;
    }
    [[nodiscard]] friend constexpr bool operator>(const Counter& lhs, const Counter& rhs) noexcept {
        return rhs < lhs;
    }
    [[nodiscard]] friend constexpr bool operator<=(const Counter& lhs, const Counter& rhs) noexcept {
        return !(rhs < lhs);
    }
    [[nodiscard]] friend constexpr bool operator>=(const Counter& lhs, const Counter& rhs) noexcept {
        return !(lhs < rhs);
    }

private:
    std::uint64_t value_ = 0;
};

struct ArtifactGenerationTag {};
struct PolicyGenerationTag {};
struct EvidenceGenerationTag {};
struct CoordinatorEpochTag {};
struct StageGenerationTag {};
struct CommitSequenceTag {};
struct CompatibilityGenerationTag {};
struct DecisionSequenceTag {};

using ArtifactGeneration = Counter<ArtifactGenerationTag>;
using PolicyGeneration = Counter<PolicyGenerationTag>;
using EvidenceGeneration = Counter<EvidenceGenerationTag>;
using CoordinatorEpoch = Counter<CoordinatorEpochTag>;
using StageGeneration = Counter<StageGenerationTag>;
using CommitSequence = Counter<CommitSequenceTag>;
using CompatibilityGeneration = Counter<CompatibilityGenerationTag>;
using DecisionSequence = Counter<DecisionSequenceTag>;

// ---------------------------------------------------------------------------
// Monotonic identity generator
//
// Every identity handed out by a single runtime instance is unique. The high
// half carries a generator salt so two independently created generators cannot
// collide, and the low half is a strictly increasing allocation counter. The
// value zero is never produced.
// ---------------------------------------------------------------------------
template <typename Tag>
class IdentityGenerator {
public:
    IdentityGenerator() noexcept : salt_(1), counter_(0) {}
    explicit IdentityGenerator(std::uint64_t salt) noexcept : salt_(salt == 0 ? 1 : salt), counter_(0) {}

    [[nodiscard]] Identity<Tag> next() noexcept {
        ++counter_;
        if (counter_ == 0) {
            // Counter wrapped: advance the salt so the pair remains unique.
            ++salt_;
            if (salt_ == 0) {
                salt_ = 1;
            }
            counter_ = 1;
        }
        return Identity<Tag>(salt_, counter_);
    }

    // Restores a generator after a restart without ever reissuing a value that
    // a previous process may already have handed out.
    void resume_after(std::uint64_t salt, std::uint64_t counter) noexcept {
        salt_ = salt == 0 ? 1 : salt;
        counter_ = counter;
    }

    // Advances the allocation counter so that the next identity is strictly
    // beyond every identity already present in the restored state. A generator
    // that has never been used legitimately holds a counter of zero; what must
    // never happen is handing out a value the state already contains.
    void observe_existing(std::uint64_t salt, std::uint64_t counter) noexcept {
        if (salt != salt_) {
            return;
        }
        if (counter > counter_) {
            counter_ = counter;
        }
    }

    [[nodiscard]] std::uint64_t salt() const noexcept { return salt_; }
    [[nodiscard]] std::uint64_t counter() const noexcept { return counter_; }

private:
    std::uint64_t salt_;
    std::uint64_t counter_;
};

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_IDENTITY_HPP
