// Artifact Promotion test support.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "support/test_context.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <thread>

namespace artifact_promotion::test {
namespace {

std::string g_scratch_directory;

[[nodiscard]] std::string unique_scratch_name() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto thread_hash = std::hash<std::thread::id>{}(std::this_thread::get_id());
    return "artifact-promotion-tests-" + std::to_string(static_cast<unsigned long long>(now)) + "-" +
           std::to_string(static_cast<unsigned long long>(thread_hash));
}

}  // namespace

TestContext& TestContext::instance() {
    static TestContext context;
    return context;
}

void TestContext::add(std::string name, Body body) {
    cases_.push_back(Case{std::move(name), std::move(body)});
}

void TestContext::check(bool condition, std::string_view expression, std::string_view file, int line) {
    ++checks_;
    if (condition) {
        return;
    }
    ++failures_;
    std::printf("FAIL %s: %.*s\n  at %.*s:%d\n", current_test_.c_str(),
                static_cast<int>(expression.size()), expression.data(), static_cast<int>(file.size()),
                file.data(), line);
}

void TestContext::check_equal(std::string_view lhs_text, std::string_view rhs_text, const std::string& lhs,
                              const std::string& rhs, std::string_view file, int line) {
    ++checks_;
    if (lhs == rhs) {
        return;
    }
    ++failures_;
    std::printf("FAIL %s: %.*s == %.*s\n  left  = %s\n  right = %s\n  at %.*s:%d\n", current_test_.c_str(),
                static_cast<int>(lhs_text.size()), lhs_text.data(), static_cast<int>(rhs_text.size()),
                rhs_text.data(), lhs.c_str(), rhs.c_str(), static_cast<int>(file.size()), file.data(), line);
}

void TestContext::fail(const std::string& message, std::string_view file, int line) {
    ++checks_;
    ++failures_;
    std::printf("FAIL %s: %s\n  at %.*s:%d\n", current_test_.c_str(), message.c_str(),
                static_cast<int>(file.size()), file.data(), line);
}

void TestContext::record(std::string_view label, std::string_view value) {
    records_.emplace_back(std::string(label), std::string(value));
}

int TestContext::run_all(std::string_view suite_name) {
    if (g_scratch_directory.empty()) {
        const std::filesystem::path base = std::filesystem::temp_directory_path() / unique_scratch_name();
        std::error_code error;
        std::filesystem::create_directories(base, error);
        g_scratch_directory = base.string();
    }

    std::printf("suite %.*s: %zu test(s)\n", static_cast<int>(suite_name.size()), suite_name.data(),
                cases_.size());
    for (Case& item : cases_) {
        current_test_ = item.name;
        const std::size_t before = failures_;
        item.body(*this);
        const bool passed = failures_ == before;
        std::printf("  %-6s %s\n", passed ? "ok" : "FAILED", item.name.c_str());
    }

    for (const auto& [label, value] : records_) {
        std::printf("  proof  %s = %s\n", label.c_str(), value.c_str());
    }

    std::error_code error;
    if (!g_scratch_directory.empty()) {
        std::filesystem::remove_all(g_scratch_directory, error);
    }

    std::printf("suite %.*s: %zu check(s), %zu failure(s)\n", static_cast<int>(suite_name.size()),
                suite_name.data(), checks_, failures_);
    if (failures_ == 0) {
        std::printf("RESULT %.*s PASS\n", static_cast<int>(suite_name.size()), suite_name.data());
    } else {
        std::printf("RESULT %.*s FAIL\n", static_cast<int>(suite_name.size()), suite_name.data());
    }
    return failures_ == 0 ? 0 : 1;
}

void set_scratch_directory(std::string path) { g_scratch_directory = std::move(path); }

const std::string& scratch_directory() { return g_scratch_directory; }

std::string scratch_path(std::string_view name) {
    if (g_scratch_directory.empty()) {
        const std::filesystem::path base = std::filesystem::temp_directory_path() / unique_scratch_name();
        std::error_code error;
        std::filesystem::create_directories(base, error);
        g_scratch_directory = base.string();
    }
    return (std::filesystem::path(g_scratch_directory) / std::string(name)).string();
}

std::string render(bool value) { return value ? "true" : "false"; }
std::string render(int value) { return std::to_string(value); }
std::string render(unsigned value) { return std::to_string(value); }
std::string render(long value) { return std::to_string(value); }
std::string render(unsigned long value) { return std::to_string(value); }
std::string render(long long value) { return std::to_string(value); }
std::string render(unsigned long long value) { return std::to_string(value); }
std::string render(const std::string& value) { return value; }
std::string render(std::string_view value) { return std::string(value); }
std::string render(const char* value) { return value == nullptr ? "<null>" : std::string(value); }
std::string render(const Status& value) { return value.render(); }
std::string render(ErrorCode value) { return to_string(value); }
std::string render(Stage value) { return to_string(value); }
std::string render(ArtifactKind value) { return to_string(value); }
std::string render(EvidenceType value) { return to_string(value); }
std::string render(EvidenceResult value) { return to_string(value); }
std::string render(PromotionOutcome value) { return to_string(value); }
std::string render(GateStatus value) { return to_string(value); }
std::string render(HistoryEventKind value) { return to_string(value); }
std::string render(protocol::MessageType value) { return protocol::to_string(value); }
std::string render(const Digest& value) { return value.to_string(); }

}  // namespace artifact_promotion::test
