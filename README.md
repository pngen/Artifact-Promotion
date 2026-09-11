# Artifact Promotion

An open-source, vendor-neutral C++20 runtime for governing whether an autonomously
produced artifact is sufficiently evidenced, compatible, verified, authorized, and
trustworthy to advance from one lifecycle stage to another.

Core question:

> Given an artifact, its immutable identity, provenance, verification evidence,
> policy, compatibility requirements, current lifecycle stage, and promotion
> authority, may this exact artifact advance to the requested next stage now, and
> can that promotion remain authoritative after failures, restarts, concurrent
> evaluation, stale evidence, or replay?

Artifact Promotion does not build, test, scan, sign, or store artifacts. It owns the
decision boundary between "this artifact exists" and "this artifact may advance",
and it owns that decision durably.

## What the runtime owns

- **Immutable identity.** Every artifact, revision, digest, evidence record, plan,
  decision, transition, and reservation has a strongly typed 128-bit identity.
  Zero is the invalid sentinel and is never issued.
- **Evidence bound to exact content.** Evidence names the artifact, the revision, and
  the content digest it observed. Evidence for a different digest or an older
  revision never silently satisfies a gate.
- **Data-driven policy.** A promotion policy is a lifecycle graph plus per-class,
  per-transition gate rules. Gates are requirements (must be satisfied) or ordering
  preferences (used to order competing attempts).
- **Generation-bound authority.** Policy generation, coordinator epoch,
  compatibility generation, artifact generation, evidence generation, stage
  generation, and worker boot identity all participate in the decision. A plan
  derived under one generation does not commit under another.
- **Transactional promotion.** Promote evaluates, plans, reserves the transition in
  pending state, revalidates every gate plus the evidence snapshot digest and the
  stage generation, commits durably, and only then acknowledges. A crash between any
  two steps leaves a state the engine can reconcile.
- **Durable, self-verifying state.** Snapshots carry a magic, a format version, a
  section table, and a SHA-256 footer. Writes are atomic (temp file plus
  replace-existing, write-through). Corruption, truncation, trailing bytes, and
  over-large declarations are rejected before any field is interpreted.

## What the runtime does not own

- It is not a ledger, a content store, a scanner, or a signing service. Provenance
  and verification arrive as evidence from adjacent systems.
- It does not execute builds, tests, or model evaluations.
- It does not decide what policy should say; it decides what the published policy
  permits for this exact artifact now.

## Lifecycle

The reference policy implements a strict executable pipeline, a distinct model
pipeline, and a generic fallback:

    CANDIDATE -> VERIFIED -> QUALIFIED -> STAGED -> APPROVED -> PROMOTED
                                   \-> QUARANTINED -> CANDIDATE
    PROMOTED -> REVOKED | SUPERSEDED | RETIRED
    REVOKED | SUPERSEDED -> RETIRED

CANDIDATE to VERIFIED requires complete, fresh provenance. Executables additionally
require build, unit, integration, and environment-bound evidence to qualify; models
require model evaluation and data validation; every class requires its declared
dependencies to be promoted or absent. Staging adds reproducibility evidence and a
current coordinator epoch, approval adds machine critic approval, and promotion adds
signature validity and a current policy generation and epoch.

## Building

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build

Options: `ARTIFACT_PROMOTION_BUILD_TESTS`, `ARTIFACT_PROMOTION_BUILD_EXAMPLES`,
`ARTIFACT_PROMOTION_BUILD_BENCHMARKS`, `ARTIFACT_PROMOTION_BUILD_TOOLS`,
`ARTIFACT_PROMOTION_BUILD_DISTRIBUTED_LIB`, `ARTIFACT_PROMOTION_ENABLE_ASAN`.

Builds are strict: /W4 /permissive- /Zc:__cplusplus /Zc:preprocessor under MSVC, with
warnings as errors. Warnings are fixed, never suppressed.

## Using the installed package

    cmake --install build --prefix <prefix>

    find_package(ArtifactPromotion CONFIG REQUIRED)
    target_link_libraries(your_target PRIVATE Summon::ArtifactPromotion)

The distributed transport library installs as `Summon::ArtifactPromotionDistributed`.

## Command line tools

- `artifact-promotion-coordinator` serves the framed TCP protocol on loopback,
  optionally persisting to a state file and writing a readiness file.
- `artifact-promotion-worker` connects, registers an artifact, submits evidence,
  requests promotion, inspects state, and prints history.
- `artifact-promotion-inspect` reads a state file without starting a coordinator.

## Tests

Suites live in `tests/` and cover core types, lifecycle, authority and generations,
persistence and corruption, properties, adversarial framing, concurrency, and a
multi-process distributed proof over real loopback TCP with real process death.

    ctest --test-dir build --output-on-failure

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
