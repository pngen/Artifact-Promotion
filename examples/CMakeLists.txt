# Artifact Promotion examples
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0

set(ARTIFACT_PROMOTION_EXAMPLES
    promote_candidate
    reject_missing_evidence
    reject_mismatched_evidence
    policy_generation_invalidation
    duplicate_request_idempotency
    revocation_after_promotion
    supersession
    restart_recovery
    provenance_adapter)

foreach(example ${ARTIFACT_PROMOTION_EXAMPLES})
    add_executable(example_${example} ${example}.cpp)
    target_include_directories(example_${example} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
    target_link_libraries(example_${example} PRIVATE artifact_promotion artifact_promotion_distributed
        PRIVATE $<BUILD_INTERFACE:artifact_promotion_warnings>)
    set_target_properties(example_${example} PROPERTIES
        CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
endforeach()
