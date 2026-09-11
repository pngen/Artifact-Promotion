// Artifact Promotion - canonical binary reader and section framing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/detail/reader.hpp"

#include "artifact_promotion/detail/writer.hpp"

namespace artifact_promotion::wire {

Result<std::uint8_t> Reader::u8() {
    if (!available(1)) {
        return Status(ErrorCode::ProtocolTruncated, "input ended while reading a byte");
    }
    const std::uint8_t value = data_[offset_];
    ++offset_;
    return value;
}

Result<std::uint16_t> Reader::u16() {
    if (!available(2)) {
        return Status(ErrorCode::ProtocolTruncated, "input ended while reading a 16-bit value");
    }
    const std::uint16_t value = load_u16(data_ + offset_);
    offset_ += 2;
    return value;
}

Result<std::uint32_t> Reader::u32() {
    if (!available(4)) {
        return Status(ErrorCode::ProtocolTruncated, "input ended while reading a 32-bit value");
    }
    const std::uint32_t value = load_u32(data_ + offset_);
    offset_ += 4;
    return value;
}

Result<std::uint64_t> Reader::u64() {
    if (!available(8)) {
        return Status(ErrorCode::ProtocolTruncated, "input ended while reading a 64-bit value");
    }
    const std::uint64_t value = load_u64(data_ + offset_);
    offset_ += 8;
    return value;
}

Result<bool> Reader::boolean() {
    auto value = u8();
    if (!value) {
        return value.status();
    }
    if (value.value() > 1) {
        return Status(ErrorCode::ProtocolMalformed, "boolean field holds a value other than 0 or 1");
    }
    return value.value() == 1;
}

Status Reader::raw(std::size_t size, ByteBuffer& out) {
    if (!available(size)) {
        return Status(ErrorCode::ProtocolTruncated, "input ended while reading a byte region");
    }
    out.assign(data_ + offset_, data_ + offset_ + size);
    offset_ += size;
    return Status::success();
}

Status Reader::skip(std::size_t size) {
    if (!available(size)) {
        return Status(ErrorCode::ProtocolTruncated, "input ended while skipping a byte region");
    }
    offset_ += size;
    return Status::success();
}

Result<std::string> Reader::text(std::size_t limit) {
    auto declared = u32();
    if (!declared) {
        return declared.status();
    }
    const std::size_t length = declared.value();
    if (length > limit) {
        return Status(ErrorCode::ProtocolOversized, "declared text length exceeds the configured bound");
    }
    if (!available(length)) {
        return Status(ErrorCode::ProtocolTruncated, "input ended while reading text");
    }
    std::string out(reinterpret_cast<const char*>(data_ + offset_), length);
    offset_ += length;
    return out;
}

Result<Digest> Reader::digest() {
    if (!available(kSha256DigestSize)) {
        return Status(ErrorCode::ProtocolTruncated, "input ended while reading a digest");
    }
    const Digest value = Digest::from_raw(data_ + offset_);
    offset_ += kSha256DigestSize;
    return value;
}

Result<ByteBuffer> Reader::blob(std::size_t limit) {
    auto declared = u32();
    if (!declared) {
        return declared.status();
    }
    const std::size_t length = declared.value();
    if (length > limit) {
        return Status(ErrorCode::ProtocolOversized, "declared blob length exceeds the configured bound");
    }
    ByteBuffer out;
    const Status status = raw(length, out);
    if (status.failed()) {
        return status;
    }
    return out;
}

Result<Reader> Reader::sub_region(std::size_t limit) {
    auto declared = u32();
    if (!declared) {
        return declared.status();
    }
    const std::size_t length = declared.value();
    if (length > limit) {
        return Status(ErrorCode::ProtocolOversized, "declared section length exceeds the configured bound");
    }
    if (!available(length)) {
        return Status(ErrorCode::ProtocolTruncated, "input ended while reading a section");
    }
    Reader sub(data_ + offset_, length);
    offset_ += length;
    return sub;
}

Result<std::size_t> Reader::count(std::size_t limit) {
    auto declared = u32();
    if (!declared) {
        return declared.status();
    }
    if (declared.value() > limit) {
        return Status(ErrorCode::ProtocolOversized, "declared element count exceeds the configured bound");
    }
    return static_cast<std::size_t>(declared.value());
}

Status Reader::require_finished() const {
    if (!finished()) {
        return Status(ErrorCode::ProtocolMalformed, "input contains trailing bytes");
    }
    return Status::success();
}

}  // namespace artifact_promotion::wire
