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

// A progress marker is never buffered: it is written and flushed as one line
// the instant it is produced, so a case that blocks still leaves behind the
// exact marker it stopped at.
void emit(const std::string& line) {
    std::fwrite(line.data(), 1, line.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

[[nodiscard]] std::string marker(std::string_view suite, std::string_view item) {
    std::string text(suite);
    text += "::";
    text += item;
    return text;
}

[[nodiscard]] std::string location(std::string_view file, int line) {
    std::string text(file);
    text += ':';
    text += std::to_string(line);
    return text;
}

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

void TestContext::record_failure(const std::string& reason) {
    if (first_failure_.empty()) {
        first_failure_ = reason;
    }
    emit("DETAIL " + marker(suite_, current_test_) + ": " + reason);
}

void TestContext::check(bool condition, std::string_view expression, std::string_view file, int line) {
    ++checks_;
    if (condition) {
        return;
    }
    ++failures_;
    record_failure(std::string(expression) + " at " + location(file, line));
}

void TestContext::check_equal(std::string_view lhs_text, std::string_view rhs_text, const std::string& lhs,
                              const std::string& rhs, std::string_view file, int line) {
    ++checks_;
    if (lhs == rhs) {
        return;
    }
    ++failures_;
    std::string reason(lhs_text);
    reason += " == ";
    reason += rhs_text;
    reason += " (left = ";
    reason += lhs;
    reason += ", right = ";
    reason += rhs;
    reason += ") at ";
    reason += location(file, line);
    record_failure(reason);
}

void TestContext::fail(const std::string& message, std::string_view file, int line) {
    ++checks_;
    ++failures_;
    record_failure(message + " at " + location(file, line));
}

void TestContext::record(std::string_view label, std::string_view value) {
    records_.emplace_back(std::string(label), std::string(value));
}

void TestContext::phase(std::string_view phase_name) {
    emit("PHASE " + marker(suite_, current_test_) + " " + std::string(phase_name));
}

int TestContext::run_all(std::string_view suite_name) { return run_all(suite_name, RunOptions{}); }

int TestContext::run_all(std::string_view suite_name, const RunOptions& options) {
    suite_.assign(suite_name);
    current_test_.clear();
    first_failure_.clear();

    // Progress has to survive a case that never returns, so stdout is unbuffered
    // for the whole run: every marker reaches its destination as it is produced
    // rather than at process exit.
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    if (options.list_only) {
        for (std::size_t index = 0; index < cases_.size(); ++index) {
            emit("CASE " + marker(suite_, cases_[index].name) + " index=" + std::to_string(index + 1));
        }
        emit("suite " + suite_ + ": " + std::to_string(cases_.size()) + " case(s)");
        return 0;
    }

    // Selection: every case, or exactly one case by stable name or 1-based
    // index. One case runs in its own process, so a case that blocks is
    // attributable to that case and to the phase it stopped in.
    std::vector<std::size_t> selected;
    if (options.select.empty()) {
        selected.reserve(cases_.size());
        for (std::size_t index = 0; index < cases_.size(); ++index) {
            selected.push_back(index);
        }
    } else {
        for (std::size_t index = 0; index < cases_.size(); ++index) {
            if (cases_[index].name == options.select) {
                selected.push_back(index);
                break;
            }
        }
        if (selected.empty()) {
            for (std::size_t index = 0; index < cases_.size(); ++index) {
                if (std::to_string(index + 1) == options.select) {
                    selected.push_back(index);
                    break;
                }
            }
        }
        if (selected.empty()) {
            emit("UNKNOWN CASE " + marker(suite_, options.select));
            for (std::size_t index = 0; index < cases_.size(); ++index) {
                emit("CASE " + marker(suite_, cases_[index].name) + " index=" + std::to_string(index + 1));
            }
            return 2;
        }
    }

    if (g_scratch_directory.empty()) {
        const std::filesystem::path scratch = std::filesystem::temp_directory_path() / unique_scratch_name();
        std::error_code error;
        std::filesystem::create_directories(scratch, error);
        g_scratch_directory = scratch.string();
    }

    emit("suite " + suite_ + ": " + std::to_string(selected.size()) + " case(s)");
    for (const std::size_t index : selected) {
        Case& item = cases_[index];
        current_test_ = item.name;
        first_failure_.clear();
        emit("BEGIN " + marker(suite_, current_test_));
        const std::size_t failures_before = failures_;
        item.body(*this);
        if (failures_ == failures_before) {
            emit("PASS " + marker(suite_, current_test_));
        } else {
            emit("FAIL " + marker(suite_, current_test_) + ": " + first_failure_);
        }
    }

    for (const auto& [label, value] : records_) {
        emit("  proof  " + label + " = " + value);
    }

    std::error_code error;
    if (!g_scratch_directory.empty()) {
        std::filesystem::remove_all(g_scratch_directory, error);
    }

    emit("suite " + suite_ + ": " + std::to_string(checks_) + " check(s), " + std::to_string(failures_) +
         " failure(s)");
    if (failures_ == 0) {
        emit("RESULT " + suite_ + " PASS");
    } else {
        emit("RESULT " + suite_ + " FAIL");
    }
    return failures_ == 0 ? 0 : 1;
}

int run_suite_from_command_line(std::string_view suite_name, int argc, char** argv) {
    RunOptions options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index] == nullptr ? std::string() : std::string(argv[index]);
        if (argument == "--list") {
            options.list_only = true;
            continue;
        }
        if (argument == "--case") {
            if (index + 1 >= argc || argv[index + 1] == nullptr) {
                emit("usage: --case <name|index>");
                return 2;
            }
            options.select = argv[++index];
            continue;
        }
        emit("unknown argument: " + argument);
        emit("usage: [--list] [--case <name|index>]");
        return 2;
    }
    return TestContext::instance().run_all(suite_name, options);
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
