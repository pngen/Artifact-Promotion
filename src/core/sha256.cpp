// Artifact Promotion - SHA-256 content identity.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/sha256.hpp"

#include <cstring>

namespace artifact_promotion {
namespace {

constexpr std::uint32_t kRoundConstants[64] = {
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
    0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U, 0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
    0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
    0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U, 0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
    0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U, 0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
    0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U, 0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
    0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U, 0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U, 0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U};

[[nodiscard]] constexpr std::uint32_t rotr(std::uint32_t value, unsigned amount) noexcept {
    return (value >> amount) | (value << (32U - amount));
}

}  // namespace

void Sha256::reset() noexcept {
    state_[0] = 0x6A09E667U;
    state_[1] = 0xBB67AE85U;
    state_[2] = 0x3C6EF372U;
    state_[3] = 0xA54FF53AU;
    state_[4] = 0x510E527FU;
    state_[5] = 0x9B05688CU;
    state_[6] = 0x1F83D9ABU;
    state_[7] = 0x5BE0CD19U;
    bit_count_ = 0;
    buffer_size_ = 0;
    std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::compress(const std::uint8_t block[64]) noexcept {
    std::uint32_t schedule[64];
    for (int i = 0; i < 16; ++i) {
        schedule[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                      (static_cast<std::uint32_t>(block[(i * 4) + 1]) << 16) |
                      (static_cast<std::uint32_t>(block[(i * 4) + 2]) << 8) |
                      static_cast<std::uint32_t>(block[(i * 4) + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr(schedule[i - 15], 7) ^ rotr(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3);
        const std::uint32_t s1 = rotr(schedule[i - 2], 17) ^ rotr(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10);
        schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (int i = 0; i < 64; ++i) {
        const std::uint32_t sigma1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t choose = (e & f) ^ ((~e) & g);
        const std::uint32_t temp1 = h + sigma1 + choose + kRoundConstants[i] + schedule[i];
        const std::uint32_t sigma0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = sigma0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const std::uint8_t* data, std::size_t size) noexcept {
    if (size == 0) {
        return;
    }
    bit_count_ += static_cast<std::uint64_t>(size) * 8U;

    std::size_t offset = 0;
    if (buffer_size_ > 0) {
        while (offset < size && buffer_size_ < 64) {
            buffer_[buffer_size_] = data[offset];
            ++buffer_size_;
            ++offset;
        }
        if (buffer_size_ == 64) {
            compress(buffer_);
            buffer_size_ = 0;
        }
    }
    while (size - offset >= 64) {
        compress(data + offset);
        offset += 64;
    }
    while (offset < size) {
        buffer_[buffer_size_] = data[offset];
        ++buffer_size_;
        ++offset;
    }
}

Digest Sha256::finish() noexcept {
    const std::uint64_t total_bits = bit_count_;

    std::uint8_t padding[72];
    std::memset(padding, 0, sizeof(padding));
    padding[0] = 0x80U;
    const std::size_t pad_length = (buffer_size_ < 56) ? (56 - buffer_size_) : (120 - buffer_size_);
    update(padding, pad_length);

    std::uint8_t length_bytes[8];
    for (int i = 0; i < 8; ++i) {
        length_bytes[i] = static_cast<std::uint8_t>((total_bits >> (8 * (7 - i))) & 0xFFU);
    }
    update(length_bytes, sizeof(length_bytes));

    Digest result;
    std::uint8_t out[kSha256DigestSize];
    for (int i = 0; i < 8; ++i) {
        out[i * 4] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFFU);
        out[(i * 4) + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFFU);
        out[(i * 4) + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFFU);
        out[(i * 4) + 3] = static_cast<std::uint8_t>(state_[i] & 0xFFU);
    }
    result = Digest::from_raw(out);
    reset();
    return result;
}

Digest Digest::from_raw(const std::uint8_t raw[kSha256DigestSize]) noexcept {
    Digest digest;
    for (std::size_t i = 0; i < kSha256DigestSize; ++i) {
        digest.bytes_[i] = raw[i];
    }
    return digest;
}

Digest Digest::from_bytes(const std::uint8_t* data, std::size_t size) noexcept {
    Sha256 hasher;
    hasher.update(data, size);
    return hasher.finish();
}

std::optional<Digest> Digest::parse(std::string_view text) {
    if (text.size() != kSha256DigestSize * 2) {
        return std::nullopt;
    }
    const auto raw = from_hex(text);
    if (!raw.has_value() || raw->size() != kSha256DigestSize) {
        return std::nullopt;
    }
    Digest digest;
    for (std::size_t i = 0; i < kSha256DigestSize; ++i) {
        digest.bytes_[i] = (*raw)[i];
    }
    if (!digest.valid()) {
        return std::nullopt;
    }
    return digest;
}

std::string Digest::to_string() const {
    return to_hex(bytes_.data(), bytes_.size());
}

bool Digest::valid() const noexcept {
    for (const std::uint8_t byte : bytes_) {
        if (byte != 0) {
            return true;
        }
    }
    return false;
}

ArtifactDigest Digest::to_identity() const noexcept {
    std::uint64_t high = 0;
    std::uint64_t low = 0;
    for (int i = 0; i < 8; ++i) {
        high = (high << 8) | static_cast<std::uint64_t>(bytes_[static_cast<std::size_t>(i)]);
    }
    for (int i = 8; i < 16; ++i) {
        low = (low << 8) | static_cast<std::uint64_t>(bytes_[static_cast<std::size_t>(i)]);
    }
    if (high == 0 && low == 0) {
        // Fold the remaining bytes in so a truncated projection of a valid
        // digest is never the invalid sentinel.
        low = 1;
    }
    return ArtifactDigest::from_parts(high, low);
}

Digest sha256(const std::uint8_t* data, std::size_t size) noexcept {
    return Digest::from_bytes(data, size);
}

Digest sha256(std::string_view text) noexcept {
    return Digest::from_bytes(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

Digest sha256(const ByteBuffer& data) noexcept {
    return Digest::from_bytes(data.data(), data.size());
}

}  // namespace artifact_promotion
