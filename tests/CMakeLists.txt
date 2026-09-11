# Artifact Promotion test suite
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0

add_library(artifact_promotion_test_support STATIC
    support/test_context.cpp
    support/scenario.cpp)
target_include_directories(artifact_promotion_test_support
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(artifact_promotion_test_support
    PUBLIC artifact_promotion artifact_promotion_distributed
    PRIVATE $<BUILD_INTERFACE:artifact_promotion_warnings>)
set_target_properties(artifact_promotion_test_support PROPERTIES
    CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)

# Each test target runs to natural completion. No test carries a lifetime
# limit: a timeout would replace a product-behaviour verdict with a harness
# verdict, and a passing suite must pass because the runtime is correct.
function(artifact_promotion_add_test name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${name} PRIVATE artifact_promotion_test_support
        PRIVATE $<BUILD_INTERFACE:artifact_promotion_warnings>)
    target_compile_definitions(${name} PRIVATE
        AP_TOOLS_DIR="${CMAKE_BINARY_DIR}/tools"
        AP_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
    set_target_properties(${name} PROPERTIES
        CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# Every suite below is a first-class target. A suite whose source file is not
# present in the tree is skipped rather than failing configuration, so a partial
# checkout still builds.
set(ARTIFACT_PROMOTION_TEST_SUITES
    test_smoke:smoke.cpp
    test_unit_core:unit_core.cpp
    test_lifecycle:lifecycle.cpp
    test_authority:authority.cpp
    test_persistence:persistence.cpp
    test_property:property.cpp
    test_adversarial:adversarial.cpp
    test_concurrency:concurrency.cpp
    test_distributed:distributed.cpp)

foreach(entry IN LISTS ARTIFACT_PROMOTION_TEST_SUITES)
    string(REPLACE ":" ";" parts "${entry}")
    list(GET parts 0 suite_name)
    list(GET parts 1 suite_source)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${suite_source}")
        artifact_promotion_add_test(${suite_name} ${suite_source})
    endif()
endforeach()
