// Artifact Promotion - canonical binary reader with hostile-input validation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_DETAIL_READER_HPP
#define ARTIFACT_PROMOTION_DETAIL_READER_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/error.hpp"
#include "artifact_promotion/identity.hpp"
#include "artifact_promotion/sha256.hpp"

namespace artifact_promotion::wire {

// ---------------------------------------------------------------------------
// Reader
//
// Decodes exactly what Writer produced. Every read is bounds checked against
// the exact remaining region; a declared length that exceeds the region is a
// ProtocolTruncated failure rather than an allocation. Trailing bytes are a
// failure unless the caller explicitly permits them.
// ---------------------------------------------------------------------------
class Reader {
public:
    Reader(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}
    explicit Reader(const ByteBuffer& buffer) noexcept : Reader(buffer.data(), buffer.size()) {}

    [[nodiscard]] std::size_t remaining() const noexcept { return size_ - offset_; }
    [[nodiscard]] bool finished() const noexcept { return offset_ == size_; }
    [[nodiscard]] std::size_t offset() const noexcept { return offset_; }
    [[nodiscard]] const std::uint8_t* cursor() const noexcept { return data_ + offset_; }

    [[nodiscard]] Result<std::uint8_t> u8();
    [[nodiscard]] Result<std::uint16_t> u16();
    [[nodiscard]] Result<std::uint32_t> u32();
    [[nodiscard]] Result<std::uint64_t> u64();
    [[nodiscard]] Result<bool> boolean();

    // Reads exactly size bytes into out. The region must exist.
    [[nodiscard]] Status raw(std::size_t size, ByteBuffer& out);
    [[nodiscard]] Status skip(std::size_t size);

    // Reads a length-prefixed string. The declared length is checked against
    // the remaining input and against the supplied limit before any allocation.
    [[nodiscard]] Result<std::string> text(std::size_t limit = kMaxTextLength);

    template <typename Tag>
    [[nodiscard]] Result<Identity<Tag>> identity() {
        auto high = u64();
        if (!high) {
            return high.status();
        }
        auto low = u64();
        if (!low) {
            return low.status();
        }
        return Identity<Tag>::from_parts(high.value(), low.value());
    }

    template <typename Tag>
    [[nodiscard]] Result<Counter<Tag>> counter() {
        auto value = u64();
        if (!value) {
            return value.status();
        }
        return Counter<Tag>(value.value());
    }

    [[nodiscard]] Result<Digest> digest();

    // Reads a length-prefixed blob and returns a bounded sub-reader over it.
    [[nodiscard]] Result<ByteBuffer> blob(std::size_t limit);
    [[nodiscard]] Result<Reader> sub_region(std::size_t limit);

    // Reads a count that is validated against an explicit bound. Counts are
    // never trusted: an absurd count fails deterministically before any
    // container reserves memory.
    [[nodiscard]] Result<std::size_t> count(std::size_t limit);

    // Rejects any unread trailing bytes.
    [[nodiscard]] Status require_finished() const;

    [[nodiscard]] Status fail(ErrorCode code, std::string_view message) const {
        return Status(code, message);
    }

private:
    [[nodiscard]] bool available(std::size_t size) const noexcept {
        return size <= size_ - offset_;
    }

    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t offset_ = 0;
};

// Raw 32-byte digest as stored in a container.
[[nodiscard]] inline Digest digest_from_raw(const std::uint8_t* raw) noexcept {
    return Digest::from_raw(raw);
}

}  // namespace artifact_promotion::wire

#endif  // ARTIFACT_PROMOTION_DETAIL_READER_HPP
