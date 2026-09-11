// Artifact Promotion - identity rendering and parsing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/identity.hpp"

#include "artifact_promotion/bytes.hpp"

namespace artifact_promotion::detail {
namespace {

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

std::string render_hex128(std::uint64_t high, std::uint64_t low) {
    std::uint8_t bytes[16];
    for (int i = 0; i < 8; ++i) {
        bytes[i] = static_cast<std::uint8_t>((high >> (8 * (7 - i))) & 0xFFU);
        bytes[8 + i] = static_cast<std::uint8_t>((low >> (8 * (7 - i))) & 0xFFU);
    }
    return to_hex(bytes, sizeof(bytes));
}

bool parse_hex128(std::string_view text, std::uint64_t& high, std::uint64_t& low) noexcept {
    if (text.size() != 32) {
        return false;
    }
    std::uint64_t values[2] = {0, 0};
    for (int half = 0; half < 2; ++half) {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 16; ++i) {
            const int digit = hex_value(text[(static_cast<std::size_t>(half) * 16) + i]);
            if (digit < 0) {
                return false;
            }
            value = (value << 4) | static_cast<std::uint64_t>(digit);
        }
        values[half] = value;
    }
    high = values[0];
    low = values[1];
    return true;
}

}  // namespace artifact_promotion::detail
