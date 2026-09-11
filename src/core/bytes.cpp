// Artifact Promotion - bounded byte views, hex encoding, and checked arithmetic.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/bytes.hpp"

namespace artifact_promotion {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

[[nodiscard]] int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return (c - 'a') + 10;
    }
    return -1;
}

}  // namespace

std::string to_hex(const std::uint8_t* data, std::size_t size) {
    std::string out;
    out.resize(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        const std::uint8_t byte = data[i];
        out[i * 2] = kHexDigits[byte >> 4];
        out[(i * 2) + 1] = kHexDigits[byte & 0x0FU];
    }
    return out;
}

std::string to_hex(const ByteBuffer& data) {
    return to_hex(data.data(), data.size());
}

std::optional<ByteBuffer> from_hex(std::string_view text) {
    if (text.size() % 2 != 0) {
        return std::nullopt;
    }
    ByteBuffer out;
    out.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const int high = hex_value(text[i]);
        const int low = hex_value(text[i + 1]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        out.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return out;
}

bool is_lower_hex(std::string_view text) noexcept {
    for (const char c : text) {
        const bool digit = c >= '0' && c <= '9';
        const bool alpha = c >= 'a' && c <= 'f';
        if (!digit && !alpha) {
            return false;
        }
    }
    return true;
}

std::optional<std::size_t> checked_add(std::size_t lhs, std::size_t rhs) noexcept {
    if (rhs > std::numeric_limits<std::size_t>::max() - lhs) {
        return std::nullopt;
    }
    return lhs + rhs;
}

std::optional<std::size_t> checked_mul(std::size_t lhs, std::size_t rhs) noexcept {
    if (lhs != 0 && rhs > std::numeric_limits<std::size_t>::max() / lhs) {
        return std::nullopt;
    }
    return lhs * rhs;
}

void store_u16(ByteBuffer& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
}

void store_u32(ByteBuffer& out, std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
    }
}

void store_u64(ByteBuffer& out, std::uint64_t value) {
    for (int shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
    }
}

void store_bytes(ByteBuffer& out, const std::uint8_t* data, std::size_t size) {
    out.insert(out.end(), data, data + size);
}

void store_string(ByteBuffer& out, std::string_view text) {
    store_u32(out, static_cast<std::uint32_t>(text.size()));
    out.insert(out.end(), text.begin(), text.end());
}

std::uint16_t load_u16(const std::uint8_t* data) noexcept {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[0]) |
                                      (static_cast<std::uint16_t>(data[1]) << 8));
}

std::uint32_t load_u32(const std::uint8_t* data) noexcept {
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(data[i]) << (8 * i);
    }
    return value;
}

std::uint64_t load_u64(const std::uint8_t* data) noexcept {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
    }
    return value;
}

bool is_valid_name(std::string_view text) noexcept {
    if (text.empty() || text.size() > kMaxNameLength) {
        return false;
    }
    for (const char c : text) {
        const bool alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        const bool digit = c >= '0' && c <= '9';
        if (!alpha && !digit && c != '_' && c != '-' && c != '.' && c != '/' && c != ':') {
            return false;
        }
    }
    return true;
}

bool is_valid_text(std::string_view text) noexcept {
    if (text.size() > kMaxTextLength) {
        return false;
    }
    for (const char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        if (byte < 0x20U || byte == 0x7FU) {
            return false;
        }
    }
    return true;
}

std::uint64_t fnv1a64(const std::uint8_t* data, std::size_t size) noexcept {
    std::uint64_t hash = 0xCBF29CE484222325ULL;
    for (std::size_t i = 0; i < size; ++i) {
        hash ^= static_cast<std::uint64_t>(data[i]);
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

std::uint64_t fnv1a64(std::string_view text) noexcept {
    return fnv1a64(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

}  // namespace artifact_promotion
