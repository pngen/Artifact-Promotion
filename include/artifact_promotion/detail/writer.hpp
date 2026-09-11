// Artifact Promotion - canonical binary writer.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_DETAIL_WRITER_HPP
#define ARTIFACT_PROMOTION_DETAIL_WRITER_HPP

#include <cstdint>
#include <string_view>

#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/identity.hpp"
#include "artifact_promotion/sha256.hpp"

namespace artifact_promotion::wire {

// ---------------------------------------------------------------------------
// Writer
//
// Canonical little-endian encoder shared by persistence snapshots and the wire
// protocol. Every composite value is written as length-prefixed bytes; the
// matching Reader always validates the declared length against the remaining
// input before allocating or copying.
//
// Text written through write_text() is truncated at a hard byte limit rather
// than rejected, so malformed producer text can never cause a write failure.
// The truncation is recorded in the value the caller encodes, not hidden.
// ---------------------------------------------------------------------------
class Writer {
public:
    Writer() = default;
    explicit Writer(std::size_t reserve) { buffer_.reserve(reserve); }

    void u8(std::uint8_t value) { buffer_.push_back(value); }
    void u16(std::uint16_t value) { store_u16(buffer_, value); }
    void u32(std::uint32_t value) { store_u32(buffer_, value); }
    void u64(std::uint64_t value) { store_u64(buffer_, value); }

    void boolean(bool value) { u8(value ? 1U : 0U); }

    void raw(const std::uint8_t* data, std::size_t size) { store_bytes(buffer_, data, size); }
    void bytes(const ByteBuffer& data) { raw(data.data(), data.size()); }

    void text(std::string_view value, std::size_t limit = kMaxTextLength) {
        const std::size_t size = value.size() < limit ? value.size() : limit;
        u32(static_cast<std::uint32_t>(size));
        raw(reinterpret_cast<const std::uint8_t*>(value.data()), size);
    }

    template <typename Tag>
    void identity(const Identity<Tag>& value) {
        u64(value.high());
        u64(value.low());
    }

    template <typename Tag>
    void counter(const Counter<Tag>& value) {
        u64(value.value());
    }

    void digest(const Digest& value) { raw(value.data(), kSha256DigestSize); }

    // Writes a length-prefixed blob produced by a nested encoder.
    void blob(const ByteBuffer& data) {
        u32(static_cast<std::uint32_t>(data.size()));
        bytes(data);
    }

    template <typename Fn>
    void list(std::size_t count, Fn&& encode_element) {
        u32(static_cast<std::uint32_t>(count));
        for (std::size_t i = 0; i < count; ++i) {
            encode_element(*this, i);
        }
    }

    [[nodiscard]] const ByteBuffer& buffer() const noexcept { return buffer_; }
    [[nodiscard]] ByteBuffer take() && { return std::move(buffer_); }
    [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
    void clear() { buffer_.clear(); }

    // Back-patches a previously reserved 32-bit slot. Used by SectionWriter to
    // declare a body length that is only known after the body is encoded.
    void patch_u32(std::size_t offset, std::uint32_t value) {
        buffer_[offset] = static_cast<std::uint8_t>(value & 0xFFU);
        buffer_[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFU);
        buffer_[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFFU);
        buffer_[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFFU);
    }

private:
    ByteBuffer buffer_;
};

// ---------------------------------------------------------------------------
// SectionWriter
//
// Emits a section whose byte length is unknown until it has been encoded. The
// declared length lets the Reader bound the section before decoding it, which
// is what keeps hostile persistence input from causing unbounded allocation.
// ---------------------------------------------------------------------------
class SectionWriter {
public:
    SectionWriter(Writer& writer, std::uint16_t kind) : outer_(writer) {
        outer_.u16(kind);
        length_offset_ = outer_.size();
        outer_.u32(0);
        header_offset_ = outer_.size();
    }

    // Encodes the section body directly into the outer buffer, then back-patches
    // the declared length so a Reader can bound the region before decoding it.
    template <typename Fn>
    void body(Fn&& encode) {
        encode(outer_);
        const std::size_t body_size = outer_.size() - header_offset_;
        outer_.patch_u32(length_offset_, static_cast<std::uint32_t>(body_size));
    }

private:
    Writer& outer_;
    std::size_t length_offset_ = 0;
    std::size_t header_offset_ = 0;
};

}  // namespace artifact_promotion::wire

#endif  // ARTIFACT_PROMOTION_DETAIL_WRITER_HPP
