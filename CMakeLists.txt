cmake_minimum_required(VERSION 3.20)

project(ArtifactPromotion
    VERSION 1.0.0
    DESCRIPTION "Vendor-neutral C++20 runtime that governs whether an autonomously produced artifact may advance lifecycle stages"
    HOMEPAGE_URL "https://github.com/pngen/Artifact-Promotion"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(ARTIFACT_PROMOTION_BUILD_TESTS "Build the Artifact Promotion test suite" OFF)
option(ARTIFACT_PROMOTION_BUILD_EXAMPLES "Build the Artifact Promotion examples" OFF)
option(ARTIFACT_PROMOTION_BUILD_BENCHMARKS "Build the Artifact Promotion benchmarks" OFF)
option(ARTIFACT_PROMOTION_BUILD_TOOLS "Build the Artifact Promotion command line tools" OFF)
option(ARTIFACT_PROMOTION_BUILD_DISTRIBUTED "Build the framed TCP reference deployment" ON)
option(ARTIFACT_PROMOTION_ENABLE_ASAN "Enable AddressSanitizer for this build tree" OFF)
option(ARTIFACT_PROMOTION_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

if(ARTIFACT_PROMOTION_BUILD_TESTS OR ARTIFACT_PROMOTION_BUILD_EXAMPLES OR ARTIFACT_PROMOTION_BUILD_BENCHMARKS OR ARTIFACT_PROMOTION_BUILD_TOOLS)
    set(ARTIFACT_PROMOTION_BUILD_TOOLS ON)
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(ARTIFACT_PROMOTION_MASTER_PROJECT ON)
else()
    set(ARTIFACT_PROMOTION_MASTER_PROJECT OFF)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Warning configuration: strict, no suppressions
# ---------------------------------------------------------------------------
add_library(artifact_promotion_warnings INTERFACE)
if(MSVC)
    target_compile_options(artifact_promotion_warnings INTERFACE
        /W4
        /permissive-
        /utf-8
        /Zc:__cplusplus
        /Zc:preprocessor
        /EHsc
        /wd4996)
    if(ARTIFACT_PROMOTION_WARNINGS_AS_ERRORS)
        target_compile_options(artifact_promotion_warnings INTERFACE /WX)
    endif()
else()
    target_compile_options(artifact_promotion_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
        -Wold-style-cast -Wnon-virtual-dtor -Wcast-align -Wunused
        -Woverloaded-virtual -Wdouble-promotion -Wformat=2 -Wimplicit-fallthrough)
    if(ARTIFACT_PROMOTION_WARNINGS_AS_ERRORS)
        target_compile_options(artifact_promotion_warnings INTERFACE -Werror)
    endif()
endif()
add_library(Summon::ArtifactPromotionWarnings ALIAS artifact_promotion_warnings)

if(ARTIFACT_PROMOTION_ENABLE_ASAN)
    if(MSVC)
        add_compile_options(/fsanitize=address)
        add_link_options(/INCREMENTAL:NO)
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

# ---------------------------------------------------------------------------
# Version header
# ---------------------------------------------------------------------------
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/artifact_promotion/version.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/artifact_promotion/version.hpp"
    @ONLY)

# ---------------------------------------------------------------------------
# Libraries
# ---------------------------------------------------------------------------
add_subdirectory(src)

if(ARTIFACT_PROMOTION_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

if(ARTIFACT_PROMOTION_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(ARTIFACT_PROMOTION_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

if(ARTIFACT_PROMOTION_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
set(ARTIFACT_PROMOTION_INSTALL_TARGETS artifact_promotion)
if(TARGET artifact_promotion_distributed)
    list(APPEND ARTIFACT_PROMOTION_INSTALL_TARGETS artifact_promotion_distributed)
endif()

install(TARGETS ${ARTIFACT_PROMOTION_INSTALL_TARGETS}
    EXPORT ArtifactPromotionTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/artifact_promotion"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/generated/artifact_promotion/version.hpp"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/artifact_promotion)

install(EXPORT ArtifactPromotionTargets
    FILE ArtifactPromotionTargets.cmake
    NAMESPACE Summon::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ArtifactPromotion)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ArtifactPromotionConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/ArtifactPromotionConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ArtifactPromotion)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/ArtifactPromotionConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/ArtifactPromotionConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/ArtifactPromotionConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ArtifactPromotion)
