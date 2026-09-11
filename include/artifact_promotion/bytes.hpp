// Artifact Promotion - bounded byte views, hex encoding, and checked arithmetic.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_BYTES_HPP
#define ARTIFACT_PROMOTION_BYTES_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "artifact_promotion/error.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// Hex encoding
// ---------------------------------------------------------------------------
[[nodiscard]] std::string to_hex(const std::uint8_t* data, std::size_t size);
[[nodiscard]] std::string to_hex(const ByteBuffer& data);

// Returns std::nullopt when the input is not lower-case hex of even length.
[[nodiscard]] std::optional<ByteBuffer> from_hex(std::string_view text);
[[nodiscard]] bool is_lower_hex(std::string_view text) noexcept;

// ---------------------------------------------------------------------------
// Checked arithmetic
// ---------------------------------------------------------------------------
[[nodiscard]] std::optional<std::size_t> checked_add(std::size_t lhs, std::size_t rhs) noexcept;
[[nodiscard]] std::optional<std::size_t> checked_mul(std::size_t lhs, std::size_t rhs) noexcept;

// Requires value <= limit, returning std::nullopt otherwise. Used for every
// length or count field that arrives from persistence or the network.
[[nodiscard]] inline std::optional<std::size_t> checked_limit(std::uint64_t value, std::size_t limit) noexcept {
    if (value > static_cast<std::uint64_t>(limit)) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(value);
}

// ---------------------------------------------------------------------------
// Little-endian primitive helpers shared by persistence and the wire protocol.
// ---------------------------------------------------------------------------
void store_u16(ByteBuffer& out, std::uint16_t value);
void store_u32(ByteBuffer& out, std::uint32_t value);
void store_u64(ByteBuffer& out, std::uint64_t value);
void store_bytes(ByteBuffer& out, const std::uint8_t* data, std::size_t size);
void store_string(ByteBuffer& out, std::string_view text);

[[nodiscard]] std::uint16_t load_u16(const std::uint8_t* data) noexcept;
[[nodiscard]] std::uint32_t load_u32(const std::uint8_t* data) noexcept;
[[nodiscard]] std::uint64_t load_u64(const std::uint8_t* data) noexcept;

// ---------------------------------------------------------------------------
// Text validation
// ---------------------------------------------------------------------------
[[nodiscard]] bool is_valid_name(std::string_view text) noexcept;
[[nodiscard]] bool is_valid_text(std::string_view text) noexcept;

// Bounded, deterministic 64-bit hash used for canonical identity of text and
// for stable tie-breaking. This is a mixing function, not a security primitive.
[[nodiscard]] std::uint64_t fnv1a64(std::string_view text) noexcept;
[[nodiscard]] std::uint64_t fnv1a64(const std::uint8_t* data, std::size_t size) noexcept;

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_BYTES_HPP
