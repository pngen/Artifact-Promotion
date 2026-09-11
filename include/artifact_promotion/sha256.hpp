// Artifact Promotion - SHA-256 content identity.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_SHA256_HPP
#define ARTIFACT_PROMOTION_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/identity.hpp"

namespace artifact_promotion {

inline constexpr std::size_t kSha256DigestSize = 32;

// ---------------------------------------------------------------------------
// ArtifactDigest
//
// The 256-bit content identity of an artifact. It is the value the runtime
// binds evidence to. A digest is never derived from a path, tag, alias, or
// label: it is either supplied as an explicit content hash or computed over
// supplied bytes.
// ---------------------------------------------------------------------------
class Digest {
public:
    Digest() noexcept = default;

    [[nodiscard]] static Digest from_bytes(const std::uint8_t* data, std::size_t size) noexcept;
    [[nodiscard]] static Digest from_bytes(const ByteBuffer& data) noexcept {
        return from_bytes(data.data(), data.size());
    }
    [[nodiscard]] static Digest from_string(std::string_view text) noexcept {
        return from_bytes(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    }

    // Strict parser: exactly 64 lower-case hex characters. An all-zero digest
    // is rejected because it is the invalid sentinel, not a content identity.
    [[nodiscard]] static std::optional<Digest> parse(std::string_view text);

    // Reconstructs a digest from exactly 32 raw bytes produced by an encoder.
    [[nodiscard]] static Digest from_raw(const std::uint8_t raw[kSha256DigestSize]) noexcept;

    [[nodiscard]] const std::uint8_t* data() const noexcept { return bytes_.data(); }
    [[nodiscard]] const std::array<std::uint8_t, kSha256DigestSize>& bytes() const noexcept { return bytes_; }
    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] bool invalid() const noexcept { return !valid(); }

    // Projects the digest into the ArtifactDigest identity domain. This is a
    // one-way, well-defined conversion used when the truncated 128-bit form is
    // required by an identity-keyed index; the full digest remains authoritative.
    [[nodiscard]] ArtifactDigest to_identity() const noexcept;

    [[nodiscard]] friend bool operator==(const Digest& lhs, const Digest& rhs) noexcept {
        return lhs.bytes_ == rhs.bytes_;
    }
    [[nodiscard]] friend bool operator!=(const Digest& lhs, const Digest& rhs) noexcept {
        return !(lhs == rhs);
    }
    [[nodiscard]] friend bool operator<(const Digest& lhs, const Digest& rhs) noexcept {
        return lhs.bytes_ < rhs.bytes_;
    }

private:
    std::array<std::uint8_t, kSha256DigestSize> bytes_{};
};

// ---------------------------------------------------------------------------
// Incremental SHA-256
// ---------------------------------------------------------------------------
class Sha256 {
public:
    Sha256() noexcept { reset(); }

    void reset() noexcept;
    void update(const std::uint8_t* data, std::size_t size) noexcept;
    void update(std::string_view text) noexcept {
        update(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    }

    // Finalizes and returns the digest. The instance is reset afterwards.
    [[nodiscard]] Digest finish() noexcept;

private:
    void compress(const std::uint8_t block[64]) noexcept;

    std::uint32_t state_[8];
    std::uint64_t bit_count_;
    std::uint8_t buffer_[64];
    std::size_t buffer_size_;
};

[[nodiscard]] Digest sha256(const std::uint8_t* data, std::size_t size) noexcept;
[[nodiscard]] Digest sha256(std::string_view text) noexcept;
[[nodiscard]] Digest sha256(const ByteBuffer& data) noexcept;
[[nodiscard]] Digest sha256(const ByteBuffer& data) noexcept;
[[nodiscard]] Digest sha256(const ByteBuffer& data) noexcept;

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_SHA256_HPP
