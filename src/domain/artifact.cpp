// Artifact Promotion - governed artifact metadata and lifecycle state.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/artifact.hpp"

#include <algorithm>
#include <array>
#include <sstream>

namespace artifact_promotion {
namespace {

struct KindName {
    ArtifactKind kind;
    const char* name;
};

constexpr std::array<KindName, 12> kKindNames = {{
    {ArtifactKind::Invalid, "INVALID"},
    {ArtifactKind::Model, "MODEL"},
    {ArtifactKind::Kernel, "KERNEL"},
    {ArtifactKind::Executable, "EXECUTABLE"},
    {ArtifactKind::Library, "LIBRARY"},
    {ArtifactKind::Configuration, "CONFIGURATION"},
    {ArtifactKind::Dataset, "DATASET"},
    {ArtifactKind::ResearchResult, "RESEARCH_RESULT"},
    {ArtifactKind::BenchmarkBundle, "BENCHMARK_BUNDLE"},
    {ArtifactKind::GeneratedCode, "GENERATED_CODE"},
    {ArtifactKind::DeploymentManifest, "DEPLOYMENT_MANIFEST"},
    {ArtifactKind::Opaque, "OPAQUE"},
}};

}  // namespace

const char* to_string(ArtifactKind kind) noexcept {
    for (const auto& entry : kKindNames) {
        if (entry.kind == kind) {
            return entry.name;
        }
    }
    return "INVALID";
}

std::optional<ArtifactKind> artifact_kind_from_string(std::string_view text) noexcept {
    for (const auto& entry : kKindNames) {
        if (text == entry.name) {
            return entry.kind;
        }
    }
    return std::nullopt;
}

bool is_valid_artifact_kind(std::uint64_t raw) noexcept {
    return raw >= kArtifactKindMin && raw <= kArtifactKindMax;
}

const char* to_string(ProvenanceResolution resolution) noexcept {
    switch (resolution) {
        case ProvenanceResolution::Unknown:
            return "UNKNOWN";
        case ProvenanceResolution::Resolved:
            return "RESOLVED";
        case ProvenanceResolution::Superseded:
            return "SUPERSEDED";
        case ProvenanceResolution::Rejected:
            return "REJECTED";
    }
    return "UNKNOWN";
}

bool ArtifactRecord::has_provenance(ProvenanceRef reference) const noexcept {
    for (const ProvenanceRecord& record : provenance) {
        if (record.reference == reference) {
            return true;
        }
    }
    return false;
}

std::string render_artifact_summary(const ArtifactRecord& record) {
    std::ostringstream out;
    out << "artifact=" << record.id.to_string() << " revision=" << record.revision.to_string()
        << " generation=" << record.generation.to_string() << " kind=" << to_string(record.kind)
        << " digest=" << record.digest.to_string() << " stage=" << to_string(record.stage)
        << " stage_generation=" << record.stage_generation.to_string()
        << " promoted=" << (record.promoted ? "true" : "false");
    if (record.quarantine.active) {
        out << " quarantined=true";
    }
    if (record.revocation.active) {
        out << " revoked=true";
    }
    if (record.supersession.active) {
        out << " superseded=true";
    }
    return out.str();
}

Status ArtifactRegistration::validate() const {
    if (id.invalid()) {
        return Status(ErrorCode::InvalidIdentity, "artifact identity is the invalid sentinel");
    }
    if (!is_valid_artifact_kind(static_cast<std::uint64_t>(kind))) {
        return Status(ErrorCode::InvalidEnum, "artifact kind is not a known artifact class");
    }
    if (digest.invalid()) {
        return Status(ErrorCode::InvalidDigest, "artifact digest is the invalid sentinel");
    }
    if (!is_valid_name(name)) {
        return Status(ErrorCode::InvalidName, "artifact name is empty, too long, or contains rejected characters");
    }
    if (!producer.valid()) {
        return Status(ErrorCode::InvalidIdentity, "producer incarnation has a boot identity without a worker identity");
    }
    if (provenance.size() > ArtifactRecord::kMaxProvenanceRefs) {
        return Status(ErrorCode::InvalidCount, "artifact provenance reference count exceeds the configured bound");
    }
    if (dependencies.size() > ArtifactRecord::kMaxDependencies) {
        return Status(ErrorCode::InvalidCount, "artifact dependency count exceeds the configured bound");
    }
    for (const ProvenanceRecord& record : provenance) {
        if (record.reference.invalid()) {
            return Status(ErrorCode::InvalidIdentity, "provenance reference is the invalid sentinel");
        }
        if (record.source.empty() || record.source.size() > kMaxNameLength) {
            return Status(ErrorCode::InvalidName, "provenance source name is empty or too long");
        }
    }
    for (const std::string& dependency : dependencies) {
        if (!is_valid_name(dependency)) {
            return Status(ErrorCode::InvalidName, "artifact dependency name is empty, too long, or malformed");
        }
    }
    return Status::success();
}

}  // namespace artifact_promotion
