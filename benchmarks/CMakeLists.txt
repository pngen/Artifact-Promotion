# Artifact Promotion benchmarks
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0

add_executable(benchmark_promotion benchmark_promotion.cpp)
target_include_directories(benchmark_promotion PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(benchmark_promotion PRIVATE artifact_promotion
    PRIVATE $<BUILD_INTERFACE:artifact_promotion_warnings>)
set_target_properties(benchmark_promotion PROPERTIES
    CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
