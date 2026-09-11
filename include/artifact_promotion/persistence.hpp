// Artifact Promotion - versioned durable state snapshots.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_PERSISTENCE_HPP
#define ARTIFACT_PROMOTION_PERSISTENCE_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/error.hpp"
#include "artifact_promotion/store.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// Snapshot format
//
//   "APSTATE\0"   8 bytes   magic
//   version        u16       format version
//   reserved       u16       must be zero
//   payload length u64       exact section byte count
//   sections       ...
//   footer digest  32 bytes  SHA-256 over magic..payload
//
// Every section is  u16 kind, u32 length, bytes. A reader bounds each section
// before decoding it, rejects unknown section kinds, rejects duplicate sections,
// rejects any truncation, rejects trailing bytes, and verifies the footer digest
// before a single record is accepted. A state file that fails any check is
// rejected outright; it is never silently replaced by an empty state.
// ---------------------------------------------------------------------------
class StatePersistence {
public:
    static constexpr std::uint16_t kFormatVersion = 1;
    static constexpr std::size_t kMaxSections = 32;

    // Encodes state into the durable format. Transient reservations are not
    // part of a snapshot.
    [[nodiscard]] static Result<ByteBuffer> encode(const CoordinatorState& state);

    // Decodes and fully validates a durable snapshot.
    [[nodiscard]] static Result<CoordinatorState> decode(const ByteBuffer& bytes);

    [[nodiscard]] static Result<CoordinatorState> load(const std::string& path);

    // Writes the snapshot through a temporary file and an atomic replacement.
    [[nodiscard]] static Status save(const std::string& path, const CoordinatorState& state);
};

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_PERSISTENCE_HPP
