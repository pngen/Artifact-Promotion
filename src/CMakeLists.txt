# Artifact Promotion library
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0

set(ARTIFACT_PROMOTION_SOURCES
    core/bytes.cpp
    core/error.cpp
    core/identity.cpp
    core/io.cpp
    core/sha256.cpp
    core/wire.cpp
    domain/artifact.cpp
    domain/decision.cpp
    domain/evidence.cpp
    domain/policy.cpp
    domain/stage.cpp
    domain/store.cpp
    engine/engine.cpp
    engine/explain.cpp
    engine/evaluate.cpp
    engine/promotion.cpp
    engine/trust.cpp
    persist/codec.cpp
    persist/snapshot.cpp)

add_library(artifact_promotion ${ARTIFACT_PROMOTION_SOURCES})
add_library(Summon::ArtifactPromotion ALIAS artifact_promotion)

target_include_directories(artifact_promotion
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/../generated>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# The strict-warning interface target is a build-tree convenience; it is not an
# installed usage requirement, so it is applied only through BUILD_INTERFACE.
target_link_libraries(artifact_promotion PRIVATE $<BUILD_INTERFACE:artifact_promotion_warnings>)

# The installed package must offer the documented namespaced target
# Summon::ArtifactPromotion. An ALIAS alone does not survive install(EXPORT),
# which falls back to the internal target name, so the export names are declared
# explicitly here.
set_target_properties(artifact_promotion PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME ArtifactPromotion
    DEFINE_SYMBOL ARTIFACT_PROMOTION_BUILD_SHARED)

if(MSVC)
    target_compile_options(artifact_promotion PRIVATE /utf-8)
    target_compile_definitions(artifact_promotion PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(artifact_promotion PRIVATE -fPIC)
endif()

# ---------------------------------------------------------------------------
# Distributed reference deployment: framed TCP coordinator/worker transport
# ---------------------------------------------------------------------------
option(ARTIFACT_PROMOTION_BUILD_DISTRIBUTED_LIB "Build the framed TCP transport library" ON)
if(NOT ARTIFACT_PROMOTION_BUILD_DISTRIBUTED_LIB)
    return()
endif()

set(ARTIFACT_PROMOTION_DISTRIBUTED_SOURCES
    distributed/socket.cpp
    distributed/protocol.cpp
    distributed/coordinator_server.cpp
    distributed/worker_client.cpp)

add_library(artifact_promotion_distributed ${ARTIFACT_PROMOTION_DISTRIBUTED_SOURCES})
add_library(Summon::ArtifactPromotionDistributed ALIAS artifact_promotion_distributed)

target_include_directories(artifact_promotion_distributed
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/../generated>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(artifact_promotion_distributed
    PUBLIC artifact_promotion
    PRIVATE $<BUILD_INTERFACE:artifact_promotion_warnings>)

set_target_properties(artifact_promotion_distributed PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME ArtifactPromotionDistributed)

if(WIN32)
    target_link_libraries(artifact_promotion_distributed PRIVATE ws2_32)
endif()
