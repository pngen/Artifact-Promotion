// Artifact Promotion - state inspection and invariant checking.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Reads a durable snapshot directly, without a running coordinator, so an
// operator can determine exactly what the coordinator would consider
// authoritative after a restart.
//
//   artifact-promotion-inspect --state FILE --artifact HEX32
//   artifact-promotion-inspect --state FILE --list
//   artifact-promotion-inspect --state FILE --check

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "artifact_promotion/io.hpp"
#include "artifact_promotion/persistence.hpp"

namespace {

using namespace artifact_promotion;

struct Options {
    std::string state_path{};
    std::string artifact{};
    bool list = false;
    bool check = false;
    bool history = false;
};

void print_usage() {
    std::printf(
        "usage: artifact-promotion-inspect --state FILE [--artifact HEX32] [--list] [--check] [--history]\n"
        "\n"
        "  --state FILE       durable snapshot to read\n"
        "  --artifact HEX32   artifact identity to describe\n"
        "  --list             list every artifact identity with its current stage\n"
        "  --check            verify the whole snapshot against its internal invariants\n"
        "  --history          print the promotion history of the selected artifact\n");
}

[[nodiscard]] bool parse_options(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        const auto next = [&](std::string& target) -> bool {
            if (i + 1 >= argc) {
                return false;
            }
            target = argv[++i];
            return true;
        };
        if (argument == "--help" || argument == "-h") {
            print_usage();
            std::exit(0);
        }
        if (argument == "--list") {
            options.list = true;
            continue;
        }
        if (argument == "--check") {
            options.check = true;
            continue;
        }
        if (argument == "--history") {
            options.history = true;
            continue;
        }
        std::string value;
        if (argument == "--state") {
            if (!next(value)) {
                return false;
            }
            options.state_path = value;
            continue;
        }
        if (argument == "--artifact") {
            if (!next(value)) {
                return false;
            }
            options.artifact = value;
            continue;
        }
        std::printf("unknown argument: %s\n", argument.c_str());
        return false;
    }
    return !options.state_path.empty();
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!parse_options(argc, argv, options)) {
        print_usage();
        return 2;
    }

    auto loaded = StatePersistence::load(options.state_path);
    if (!loaded) {
        std::printf("SNAPSHOT REJECTED code=%s message=%s\n", to_string(loaded.status().code()),
                    loaded.status().message().c_str());
        return 1;
    }
    const CoordinatorState& state = loaded.value();

    std::printf("SNAPSHOT coordinator=%s epoch=%s commit_sequence=%s decision_sequence=%s\n",
                state.coordinator.to_string().c_str(), state.epoch.to_string().c_str(),
                state.commit_sequence.to_string().c_str(), state.decision_sequence.to_string().c_str());
    std::printf("SNAPSHOT policy=%s generation=%s digest=%s compatibility_generation=%s\n",
                state.active_policy.to_string().c_str(), state.active_policy_generation.to_string().c_str(),
                state.active_policy_digest.to_string().c_str(), state.compatibility_generation.to_string().c_str());
    std::printf("SNAPSHOT artifacts=%zu evidence=%zu plans=%zu decisions=%zu records=%zu history=%zu\n",
                state.artifacts.size(), state.evidence.size(), state.plans.size(), state.decisions.size(),
                state.records.size(), state.history.size());

    int exit_code = 0;

    if (options.check) {
        const Status consistency = state.verify_consistency();
        if (consistency.failed()) {
            std::printf("CHECK FAILED code=%s message=%s detail=%s\n", to_string(consistency.code()),
                        consistency.message().c_str(), consistency.render().c_str());
            exit_code = 1;
        } else {
            std::printf("CHECK OK the snapshot satisfies every internal invariant\n");
        }
    }

    if (options.list) {
        for (const auto& [id, revisions] : state.artifacts) {
            const ArtifactRecord& current = revisions.back();
            std::printf("ARTIFACT id=%s revisions=%zu stage=%s promoted=%s quarantined=%s revoked=%s "
                        "superseded=%s digest=%s\n",
                        id.to_string().c_str(), revisions.size(), to_string(current.stage),
                        current.promoted ? "true" : "false", current.quarantine.active ? "true" : "false",
                        current.revocation.active ? "true" : "false",
                        current.supersession.active ? "true" : "false", current.digest.to_string().c_str());
        }
    }

    if (!options.artifact.empty()) {
        auto id = ArtifactId::parse(options.artifact);
        if (!id.has_value()) {
            std::printf("--artifact must be 32 lower-case hex characters and non-zero\n");
            return 2;
        }
        const ArtifactRecord* current = state.find_current(id.value());
        if (current == nullptr) {
            std::printf("ARTIFACT NOT FOUND %s\n", options.artifact.c_str());
            return 1;
        }
        std::printf("DETAIL %s\n", render_artifact_summary(*current).c_str());
        std::printf("DETAIL authoritative=%s revision=%s generation=%s stage_generation=%s\n",
                    current->currently_authoritative() ? "true" : "false", current->revision.to_string().c_str(),
                    current->generation.to_string().c_str(), current->stage_generation.to_string().c_str());
        if (current->quarantine.active) {
            std::printf("DETAIL quarantine reason=%s detail=%s sequence=%s\n",
                        current->quarantine.reason_class.c_str(), current->quarantine.detail.c_str(),
                        current->quarantine.sequence.to_string().c_str());
        }
        if (current->revocation.active) {
            std::printf("DETAIL revocation decision=%s reason=%s detail=%s sequence=%s\n",
                        current->revocation.decision.to_string().c_str(),
                        current->revocation.reason_class.c_str(), current->revocation.detail.c_str(),
                        current->revocation.sequence.to_string().c_str());
        }
        if (current->supersession.active) {
            std::printf("DETAIL superseded_by=%s revision=%s reason=%s\n",
                        current->supersession.successor.to_string().c_str(),
                        current->supersession.successor_revision.to_string().c_str(),
                        current->supersession.reason.c_str());
        }
        for (const ProvenanceRecord& provenance : current->provenance) {
            std::printf("DETAIL provenance reference=%s source=%s subject=%s resolution=%s\n",
                        provenance.reference.to_string().c_str(), provenance.source.c_str(),
                        provenance.subject.c_str(), to_string(provenance.resolution));
        }

        std::size_t evidence_count = 0;
        for (const auto& [evidence_id, evidence] : state.evidence) {
            (void)evidence_id;
            if (evidence.subject != id.value() || evidence.subject_revision != current->revision) {
                continue;
            }
            ++evidence_count;
            std::printf("EVIDENCE id=%s class=%s result=%s environment=%s revoked=%s superseded=%s "
                        "produced=%llu\n",
                        evidence.id.to_string().c_str(), to_string(evidence.type),
                        to_string(evidence.result), evidence.environment.c_str(),
                        evidence.revoked ? "true" : "false", evidence.superseded ? "true" : "false",
                        static_cast<unsigned long long>(evidence.produced_unix_millis));
        }
        std::printf("EVIDENCE total=%zu\n", evidence_count);

        if (options.history) {
            for (const auto& [sequence, record] : state.records) {
                if (record.artifact != id.value()) {
                    continue;
                }
                std::printf("HISTORY sequence=%s %s->%s decision=%s note=%s\n", sequence.to_string().c_str(),
                            to_string(record.from), to_string(record.to),
                            record.decision.to_string().c_str(), record.note.c_str());
            }
            for (const auto& [sequence, event] : state.history) {
                if (event.artifact != id.value()) {
                    continue;
                }
                std::printf("HISTORY sequence=%s kind=%s %s->%s note=%s\n", sequence.to_string().c_str(),
                            to_string(event.kind), to_string(event.from), to_string(event.to),
                            event.note.c_str());
            }
        }
    }

    return exit_code;
}
