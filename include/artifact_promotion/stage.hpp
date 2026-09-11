// Artifact Promotion - lifecycle stages and the explicit transition graph.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_STAGE_HPP
#define ARTIFACT_PROMOTION_STAGE_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "artifact_promotion/error.hpp"
#include "artifact_promotion/identity.hpp"
#include "artifact_promotion/sha256.hpp"

namespace artifact_promotion {

// ---------------------------------------------------------------------------
// Stage
//
// The lifecycle state machine is a closed enumeration, not free-form strings.
// Free-form stage names are rejected everywhere: on the wire, in persistence,
// and in the public API.
// ---------------------------------------------------------------------------
enum class Stage : std::uint8_t {
    Invalid = 0,
    Candidate = 1,
    Verified = 2,
    Qualified = 3,
    Staged = 4,
    Approved = 5,
    Promoted = 6,
    Quarantined = 7,
    Revoked = 8,
    Superseded = 9,
    Retired = 10,
};

inline constexpr std::uint8_t kStageMin = static_cast<std::uint8_t>(Stage::Candidate);
inline constexpr std::uint8_t kStageMax = static_cast<std::uint8_t>(Stage::Retired);

[[nodiscard]] const char* to_string(Stage stage) noexcept;
[[nodiscard]] std::optional<Stage> stage_from_string(std::string_view text) noexcept;
[[nodiscard]] bool is_valid_stage_value(std::uint64_t raw) noexcept;
[[nodiscard]] bool is_terminal_failure_stage(Stage stage) noexcept;

// ---------------------------------------------------------------------------
// LifecycleGraph
//
// The authoritative, policy-selected topology of legal transitions. A graph is
// always validated: it must be acyclic, every node must be reachable from the
// candidate entry stage, and every edge must reference known stages.
//
// A jump from CANDIDATE straight to PROMOTED is illegal unless the active graph
// contains that exact edge.
// ---------------------------------------------------------------------------
class LifecycleGraph {
public:
    static constexpr std::size_t kMaxEdges = 64;

    struct Edge {
        Stage from = Stage::Invalid;
        Stage to = Stage::Invalid;

        [[nodiscard]] friend bool operator==(const Edge& lhs, const Edge& rhs) noexcept {
            return lhs.from == rhs.from && lhs.to == rhs.to;
        }
        [[nodiscard]] friend bool operator<(const Edge& lhs, const Edge& rhs) noexcept {
            if (lhs.from != rhs.from) {
                return lhs.from < rhs.from;
            }
            return lhs.to < rhs.to;
        }
    };

    LifecycleGraph() = default;

    // The reference lifecycle used when no graph is supplied by policy:
    // CANDIDATE -> VERIFIED -> QUALIFIED -> STAGED -> APPROVED -> PROMOTED,
    // plus quarantine, revocation, supersession, and retirement edges.
    [[nodiscard]] static LifecycleGraph reference();

    [[nodiscard]] bool add_edge(Stage from, Stage to);
    [[nodiscard]] bool has_edge(Stage from, Stage to) const noexcept;

    // Returns the empty vector when no transition is legal.
    [[nodiscard]] std::vector<Stage> successors(Stage from) const;

    [[nodiscard]] const std::vector<Edge>& edges() const noexcept { return edges_; }
    [[nodiscard]] std::size_t edge_count() const noexcept { return edges_.size(); }

    // Validates topology. Returns a Status describing the first violation.
    [[nodiscard]] Status validate(Stage entry) const;

    // Canonical form: sorted, de-duplicated edges. Two graphs that permit the
    // same transitions canonicalize identically.
    void canonicalize();
    [[nodiscard]] bool is_canonical() const noexcept;

    [[nodiscard]] Digest graph_digest() const;

    [[nodiscard]] friend bool operator==(const LifecycleGraph& lhs, const LifecycleGraph& rhs) noexcept {
        return lhs.edges_ == rhs.edges_;
    }

private:
    std::vector<Edge> edges_;
};

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_STAGE_HPP
