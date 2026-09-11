// Artifact Promotion - lifecycle stages and the explicit transition graph.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/stage.hpp"

#include <algorithm>
#include <array>

#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/sha256.hpp"

namespace artifact_promotion {
namespace {

struct StageName {
    Stage stage;
    const char* name;
};

constexpr std::array<StageName, 11> kStageNames = {{
    {Stage::Invalid, "INVALID"},
    {Stage::Candidate, "CANDIDATE"},
    {Stage::Verified, "VERIFIED"},
    {Stage::Qualified, "QUALIFIED"},
    {Stage::Staged, "STAGED"},
    {Stage::Approved, "APPROVED"},
    {Stage::Promoted, "PROMOTED"},
    {Stage::Quarantined, "QUARANTINED"},
    {Stage::Revoked, "REVOKED"},
    {Stage::Superseded, "SUPERSEDED"},
    {Stage::Retired, "RETIRED"},
}};

}  // namespace

const char* to_string(Stage stage) noexcept {
    for (const auto& entry : kStageNames) {
        if (entry.stage == stage) {
            return entry.name;
        }
    }
    return "INVALID";
}

std::optional<Stage> stage_from_string(std::string_view text) noexcept {
    for (const auto& entry : kStageNames) {
        if (text == entry.name) {
            return entry.stage;
        }
    }
    return std::nullopt;
}

bool is_valid_stage_value(std::uint64_t raw) noexcept {
    return raw >= kStageMin && raw <= kStageMax;
}

bool is_terminal_failure_stage(Stage stage) noexcept {
    return stage == Stage::Revoked || stage == Stage::Retired || stage == Stage::Superseded;
}

namespace {

// A holding stage withholds an artifact from promotion and hands it back to
// CANDIDATE only through an authorized release decision. QUARANTINED is the
// only such stage, so its release edge is a governed return rather than a
// promotion step.
[[nodiscard]] bool is_holding_stage(Stage stage) noexcept { return stage == Stage::Quarantined; }

}  // namespace

LifecycleGraph LifecycleGraph::reference() {
    LifecycleGraph graph;
    (void)graph.add_edge(Stage::Candidate, Stage::Verified);
    (void)graph.add_edge(Stage::Verified, Stage::Qualified);
    (void)graph.add_edge(Stage::Qualified, Stage::Staged);
    (void)graph.add_edge(Stage::Staged, Stage::Approved);
    (void)graph.add_edge(Stage::Approved, Stage::Promoted);
    // Quarantine is reachable from every stage, including CANDIDATE, because a
    // security finding can arrive at any point in an artifact's life.
    (void)graph.add_edge(Stage::Candidate, Stage::Quarantined);
    (void)graph.add_edge(Stage::Verified, Stage::Quarantined);
    (void)graph.add_edge(Stage::Qualified, Stage::Quarantined);
    (void)graph.add_edge(Stage::Staged, Stage::Quarantined);
    (void)graph.add_edge(Stage::Approved, Stage::Quarantined);
    (void)graph.add_edge(Stage::Promoted, Stage::Quarantined);
    // Quarantine holds the artifact until an authorized release decision
    // returns it to CANDIDATE for a full re-evaluation.
    (void)graph.add_edge(Stage::Quarantined, Stage::Candidate);
    // Revocation applies only to something that held authority.
    (void)graph.add_edge(Stage::Promoted, Stage::Revoked);
    (void)graph.add_edge(Stage::Staged, Stage::Revoked);
    (void)graph.add_edge(Stage::Approved, Stage::Revoked);
    // Supersession: a newer artifact replaces an older one. The older artifact
    // stays historically valid but is no longer current.
    (void)graph.add_edge(Stage::Promoted, Stage::Superseded);
    (void)graph.add_edge(Stage::Staged, Stage::Superseded);
    (void)graph.add_edge(Stage::Approved, Stage::Superseded);
    // Retirement is the orderly end of life.
    (void)graph.add_edge(Stage::Promoted, Stage::Retired);
    (void)graph.add_edge(Stage::Superseded, Stage::Retired);
    (void)graph.add_edge(Stage::Revoked, Stage::Retired);
    graph.canonicalize();
    return graph;
}

bool LifecycleGraph::add_edge(Stage from, Stage to) {
    if (from == Stage::Invalid || to == Stage::Invalid) {
        return false;
    }
    if (from == to) {
        return false;
    }
    for (const Edge& edge : edges_) {
        if (edge.from == from && edge.to == to) {
            return false;
        }
    }
    if (edges_.size() >= kMaxEdges) {
        return false;
    }
    edges_.push_back(Edge{from, to});
    return true;
}

bool LifecycleGraph::has_edge(Stage from, Stage to) const noexcept {
    for (const Edge& edge : edges_) {
        if (edge.from == from && edge.to == to) {
            return true;
        }
    }
    return false;
}

std::vector<Stage> LifecycleGraph::successors(Stage from) const {
    std::vector<Stage> out;
    for (const Edge& edge : edges_) {
        if (edge.from == from) {
            out.push_back(edge.to);
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

void LifecycleGraph::canonicalize() {
    std::sort(edges_.begin(), edges_.end());
    edges_.erase(std::unique(edges_.begin(), edges_.end()), edges_.end());
}

bool LifecycleGraph::is_canonical() const noexcept {
    return std::is_sorted(edges_.begin(), edges_.end()) &&
           std::adjacent_find(edges_.begin(), edges_.end()) == edges_.end();
}

Status LifecycleGraph::validate(Stage entry) const {
    if (entry == Stage::Invalid) {
        return Status(ErrorCode::InvalidStage, "entry stage is INVALID");
    }
    if (edges_.empty()) {
        return Status(ErrorCode::InvalidTransition, "lifecycle graph has no transitions");
    }
    if (edges_.size() > kMaxEdges) {
        return Status(ErrorCode::InvalidCount, "lifecycle graph exceeds the configured edge bound");
    }
    if (!is_canonical()) {
        return Status(ErrorCode::InvalidTransition, "lifecycle graph is not in canonical order");
    }
    for (const Edge& edge : edges_) {
        if (edge.from == Stage::Invalid || edge.to == Stage::Invalid || edge.from == edge.to) {
            return Status(ErrorCode::InvalidTransition, "lifecycle graph contains an invalid edge");
        }
        if (!is_valid_stage_value(static_cast<std::uint64_t>(edge.from)) ||
            !is_valid_stage_value(static_cast<std::uint64_t>(edge.to))) {
            return Status(ErrorCode::InvalidStage, "lifecycle graph references an unknown stage");
        }
    }

    constexpr std::size_t kStageCount = static_cast<std::size_t>(kStageMax) + 1;

    // Adjacency built once, in canonical edge order, so every traversal below is
    // deterministic: the answer never depends on the order edges were inserted.
    std::array<std::vector<Stage>, kStageCount> adjacency{};
    std::array<std::vector<Stage>, kStageCount> reverse{};
    for (const Edge& edge : edges_) {
        const auto from_index = static_cast<std::size_t>(edge.from);
        const auto to_index = static_cast<std::size_t>(edge.to);
        if (from_index >= kStageCount || to_index >= kStageCount) {
            return Status(ErrorCode::InvalidStage, "lifecycle graph references an unknown stage");
        }
        adjacency[from_index].push_back(edge.to);
        reverse[to_index].push_back(edge.from);
    }
    for (std::size_t index = 0; index < kStageCount; ++index) {
        std::sort(adjacency[index].begin(), adjacency[index].end());
        std::sort(reverse[index].begin(), reverse[index].end());
    }

    // Reachability from the entry stage, and reverse reachability from the exit
    // stages. Every stage of the graph must be reachable from the entry stage,
    // otherwise the graph declares a state no artifact can ever occupy.
    std::array<bool, kStageCount> forward{};
    std::array<bool, kStageCount> backward{};
    // The frontier is a plain queue with a head index. A node enters it exactly
    // once, because the visited flag is set at enqueue time, so the queue can
    // never hold more than kStageCount entries: an insertion that is only
    // guarded by "is there room left" silently drops nodes once the bound is
    // reached, which would make reachability depend on traversal order.
    std::array<Stage, kStageCount> frontier{};

    const auto traverse = [&](Stage start, const std::array<std::vector<Stage>, kStageCount>& links,
                              std::array<bool, kStageCount>& visited) {
        std::size_t head = 0;
        std::size_t tail = 0;
        visited[static_cast<std::size_t>(start)] = true;
        frontier[tail] = start;
        ++tail;
        while (head < tail) {
            const Stage current = frontier[head];
            ++head;
            for (const Stage next : links[static_cast<std::size_t>(current)]) {
                const auto index = static_cast<std::size_t>(next);
                if (!visited[index]) {
                    // The queue is exactly kStageCount long and a node is marked
                    // visited before it is enqueued, so this can only be reached
                    // if a stage value escapes the closed range. Stopping here
                    // keeps reachability a bounded computation instead of a
                    // buffer overrun.
                    if (tail >= frontier.size()) {
                        return;
                    }
                    visited[index] = true;
                    frontier[tail] = next;
                    ++tail;
                }
            }
        }
    };

    traverse(entry, adjacency, forward);
    // Every reachable stage must be able to reach a stage that has an exit, not
    // necessarily a terminal stage directly. An intermediate stage such as
    // QUARANTINED hands the artifact back to CANDIDATE, and CANDIDATE reaches
    // revocation and retirement; requiring QUARANTINED itself to be terminal
    // would reject a perfectly well formed lifecycle.
    for (std::uint8_t raw = kStageMin; raw <= kStageMax; ++raw) {
        const auto stage = static_cast<Stage>(raw);
        const auto index = static_cast<std::size_t>(stage);
        bool has_exit = false;
        for (const Stage next : adjacency[index]) {
            if (is_terminal_failure_stage(next) || next == Stage::Retired) {
                has_exit = true;
                break;
            }
        }
        if (has_exit) {
            traverse(stage, reverse, backward);
        }
    }

    for (std::uint8_t raw = kStageMin; raw <= kStageMax; ++raw) {
        const auto stage = static_cast<Stage>(raw);
        const auto index = static_cast<std::size_t>(stage);
        const bool appears = !adjacency[index].empty() || !reverse[index].empty();
        if (!appears) {
            continue;
        }
        if (!forward[index]) {
            return Status(ErrorCode::InvalidTransition,
                          std::string("lifecycle stage ") + to_string(stage) +
                              " is not reachable from the entry stage");
        }
        // A terminal stage is the exit, so it does not need a path to itself.
        // Every other reachable stage must be able to reach one, otherwise the
        // graph declares a state an artifact can enter and never leave.
        const bool terminal = is_terminal_failure_stage(stage) || stage == Stage::Retired;
        if (!backward[index] && !terminal) {
            return Status(ErrorCode::InvalidTransition,
                          std::string("lifecycle stage ") + to_string(stage) +
                              " cannot reach revocation, supersession, or retirement by any path");
        }
    }

    // Cycle detection over the subgraph induced by the reachable stages.
    //
    // A well formed lifecycle really does carry an edge back into the entry
    // stage: a quarantine is released by an authorized decision that returns the
    // artifact to CANDIDATE for full re-evaluation. Excluding exactly the edges
    // that leave a holding stage is what separates that governed return from a
    // promotion cycle. Forcing the entry in-degree to zero instead would discard
    // every edge back into CANDIDATE, so an ungoverned VERIFIED -> CANDIDATE
    // edge -- which lets an artifact re-enter promotion with no release decision
    // and no new evidence -- would validate as acyclic. The graph is small and
    // strictly bounded, so a Kahn-style topological count is exact and needs no
    // recursion.
    std::array<std::size_t, kStageCount> in_degree{};
    std::size_t reachable_nodes = 0;
    std::size_t reachable_edges = 0;
    for (std::size_t index = 0; index < kStageCount; ++index) {
        if (!forward[index]) {
            continue;
        }
        ++reachable_nodes;
        if (is_holding_stage(static_cast<Stage>(index))) {
            continue;
        }
        for (const Stage next : adjacency[index]) {
            ++in_degree[static_cast<std::size_t>(next)];
            ++reachable_edges;
        }
    }
    // The topological sort uses its own buffer. Reusing the reachability
    // frontier would leave stale entries in front of the freshly seeded roots,
    // and the sort would then count nodes that were never ordered.
    std::array<Stage, kStageCount> order_queue{};
    std::size_t queue_size = 0;
    for (std::size_t index = 0; index < kStageCount; ++index) {
        if (forward[index] && in_degree[index] == 0) {
            order_queue[queue_size] = static_cast<Stage>(index);
            ++queue_size;
        }
    }
    std::size_t topologically_ordered = 0;
    std::size_t head = 0;
    while (head < queue_size) {
        const Stage current = order_queue[head];
        ++head;
        ++topologically_ordered;
        for (const Stage next : adjacency[static_cast<std::size_t>(current)]) {
            const auto next_index = static_cast<std::size_t>(next);
            // A successor can only enter the ordering once, at the moment its
            // in-degree reaches zero, so the queue cannot exceed kStageCount
            // entries. The bound is still enforced explicitly: a wrong guess here
            // must not become an out-of-bounds write.
            if (in_degree[next_index] == 0 || !forward[next_index]) {
                continue;
            }
            --in_degree[next_index];
            if (in_degree[next_index] == 0 && queue_size < order_queue.size()) {
                order_queue[queue_size] = next;
                ++queue_size;
            }
        }
    }
    (void)reachable_edges;
    if (topologically_ordered != reachable_nodes) {
        return Status(ErrorCode::InvalidTransition, "lifecycle graph contains a cycle");
    }

    bool has_exit = false;
    for (const Edge& edge : edges_) {
        if (is_terminal_failure_stage(edge.to) || edge.to == Stage::Retired) {
            has_exit = true;
            break;
        }
    }
    if (!has_exit) {
        return Status(ErrorCode::InvalidTransition, "lifecycle graph has no quarantine, revocation, or retirement edge");
    }
    return Status::success();
}

Digest LifecycleGraph::graph_digest() const {
    std::string canonical;
    canonical.reserve(edges_.size() * 8);
    for (const Edge& edge : edges_) {
        canonical.push_back(static_cast<char>(static_cast<std::uint8_t>(edge.from)));
        canonical.push_back(static_cast<char>(static_cast<std::uint8_t>(edge.to)));
    }
    return Digest::from_string(canonical);
}

}  // namespace artifact_promotion
