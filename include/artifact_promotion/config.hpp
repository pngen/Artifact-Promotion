// Artifact Promotion - explicit resource bounds and coordinator configuration.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_CONFIG_HPP
#define ARTIFACT_PROMOTION_CONFIG_HPP

#include <cstddef>
#include <cstdint>

#include "artifact_promotion/bytes.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// EngineConfig
//
// Every bounded collection and every admission decision in the runtime is
// governed by an explicit limit. Nothing is sized from an untrusted field, and
// nothing grows without an admission check that can fail deterministically.
// ---------------------------------------------------------------------------
struct EngineConfig {
    // Metadata bounds
    std::size_t max_artifacts = 100000;
    std::size_t max_artifact_revisions_per_id = 64;
    std::size_t max_evidence_records = 500000;
    std::size_t max_evidence_per_artifact_revision = 256;
    std::size_t max_policies_retained = 16;
    std::size_t max_pending_promotions = 4096;
    std::size_t max_plans_retained = 4096;
    std::size_t max_decisions_retained = 65536;
    std::size_t max_records_retained = 65536;
    std::size_t max_history_events = 262144;
    std::size_t max_evidence_per_snapshot = 256;

    // Promotion semantics
    std::uint64_t plan_ttl_millis = 60000;
    std::uint64_t reservation_stale_millis = 30000;

    // Clock skew accepted when checking evidence freshness. A producer clock
    // running slightly ahead of the coordinator must not make fresh evidence
    // look like evidence from the future.
    std::uint64_t future_skew_tolerance_millis = 5000;

    // Determinism
    std::uint64_t identity_salt_seed = 0x5A17C0DEULL;

    [[nodiscard]] bool valid() const noexcept {
        return max_artifacts > 0 && max_evidence_records > 0 && max_pending_promotions > 0 &&
               max_plans_retained > 0 && max_history_events > 0 && max_evidence_per_snapshot > 0 &&
               max_policies_retained > 0 && plan_ttl_millis > 0 && max_decisions_retained > 0 &&
               max_records_retained > 0 && max_artifact_revisions_per_id > 0 &&
               max_evidence_per_artifact_revision > 0;
    }

    [[nodiscard]] static EngineConfig defaults() noexcept { return EngineConfig{}; }
};

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_CONFIG_HPP
