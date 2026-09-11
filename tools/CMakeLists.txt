# Artifact Promotion command line tools
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0

set(ARTIFACT_PROMOTION_TOOLS
    artifact-promotion-coordinator
    artifact-promotion-worker
    artifact-promotion-inspect)

foreach(tool ${ARTIFACT_PROMOTION_TOOLS})
    add_executable(${tool} ${tool}.cpp)
    target_include_directories(${tool} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${tool} PRIVATE artifact_promotion artifact_promotion_distributed
        PRIVATE $<BUILD_INTERFACE:artifact_promotion_warnings>)
    set_target_properties(${tool} PROPERTIES
        CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
endforeach()
