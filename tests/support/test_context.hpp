// Artifact Promotion test support.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_TEST_CONTEXT_HPP
#define ARTIFACT_PROMOTION_TEST_CONTEXT_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "artifact_promotion/engine.hpp"
#include "artifact_promotion/io.hpp"
#include "artifact_promotion/persistence.hpp"
#include "artifact_promotion/protocol.hpp"

namespace artifact_promotion::test {

// ---------------------------------------------------------------------------
// Run selection
//
// Every suite is a set of independently addressable cases with stable names.
// The runner can enumerate the cases, run all of them, or run exactly one, so a
// case that blocks is identified by the progress markers it produced instead of
// degrading an entire suite into an undetermined verdict.
// ---------------------------------------------------------------------------
struct RunOptions {
    bool list_only = false;
    std::string select;  // empty selects every case; otherwise a case name or 1-based index
};

// ---------------------------------------------------------------------------
// TestContext
//
// A minimal deterministic test runner. There are no time limits anywhere: a
// test either reaches its assertions or it does not. A failure prints the test
// name, the file, the line, and the rendered values, and the process exits
// non-zero so the harness observes the failure.
//
// Progress is written and flushed one line at a time, and stdout is unbuffered
// for the whole run, so the last marker a process produced is on disk even when
// the case that produced it never returns:
//
//   BEGIN <suite>::<case>             emitted before the case body runs
//   PHASE <suite>::<case> <PHASE>     emitted on every explicit phase change
//   DETAIL <suite>::<case>: <reason>  emitted for each failing check
//   PASS <suite>::<case>              emitted when the case body returns clean
//   FAIL <suite>::<case>: <reason>    emitted with the first failure reason
// ---------------------------------------------------------------------------
class TestContext {
public:
    using Body = std::function<void(TestContext&)>;

    struct Case {
        std::string name;
        Body body;
    };

    static TestContext& instance();

    void add(std::string name, Body body);

    // Runs every case of the suite.
    int run_all(std::string_view suite_name);

    // Runs the cases the options select: all of them, or exactly one by stable
    // name or 1-based index.
    int run_all(std::string_view suite_name, const RunOptions& options);

    // Emits a phase transition for the case currently executing. A case with
    // blocking or concurrent phases calls this so the last marker a process
    // produced names the phase it stopped in, not merely the case.
    void phase(std::string_view phase_name);

    void check(bool condition, std::string_view expression, std::string_view file, int line);
    void check_equal(std::string_view lhs_text, std::string_view rhs_text, const std::string& lhs,
                     const std::string& rhs, std::string_view file, int line);
    void fail(const std::string& message, std::string_view file, int line);

    // Records a measurement or proof fact that the suite prints at the end.
    void record(std::string_view label, std::string_view value);

    [[nodiscard]] std::size_t checks() const noexcept { return checks_; }
    [[nodiscard]] std::size_t failures() const noexcept { return failures_; }
    [[nodiscard]] const std::string& current_test() const noexcept { return current_test_; }
    [[nodiscard]] const std::string& suite_name() const noexcept { return suite_; }

private:
    friend void set_scratch_directory(std::string path);
    friend const std::string& scratch_directory();
    void record_failure(const std::string& reason);

    std::vector<Case> cases_;
    std::string suite_;
    std::string current_test_;
    std::string first_failure_;
    std::size_t checks_ = 0;
    std::size_t failures_ = 0;
    std::vector<std::pair<std::string, std::string>> records_;
};

// Runs one suite from a command line: no arguments runs every case, --list
// enumerates the cases, and --case <name|index> runs exactly one of them.
int run_suite_from_command_line(std::string_view suite_name, int argc, char** argv);

// Installs and returns the per-process scratch directory. It lives under the
// system temporary directory and is removed when the suite finishes.
void set_scratch_directory(std::string path);
[[nodiscard]] const std::string& scratch_directory();
[[nodiscard]] std::string scratch_path(std::string_view name);

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
struct Registrar {
    Registrar(std::string name, TestContext::Body body) {
        TestContext::instance().add(std::move(name), std::move(body));
    }
};

#define AP_TEST(name)                                                                          \
    static void ap_test_body_##name(::artifact_promotion::test::TestContext& context);          \
    static const ::artifact_promotion::test::Registrar ap_test_registrar_##name(                \
        #name, [](::artifact_promotion::test::TestContext& ctx) { ap_test_body_##name(ctx); }); \
    static void ap_test_body_##name(::artifact_promotion::test::TestContext& context)

#define AP_CHECK(expression) context.check((expression), #expression, __FILE__, __LINE__)

#define AP_CHECK_EQ(lhs, rhs)                                                                    \
    do {                                                                                         \
        const auto ap_lhs_value = (lhs);                                                         \
        const auto ap_rhs_value = (rhs);                                                         \
        context.check_equal(#lhs, #rhs, ::artifact_promotion::test::render(ap_lhs_value),         \
                            ::artifact_promotion::test::render(ap_rhs_value), __FILE__, __LINE__); \
    } while (false)

// AP_REQUIRE evaluates its expression exactly once. A macro that evaluates the
// operand twice would let a side-effecting condition pass the check on the first
// evaluation and return early on the second, silently truncating the test body
// with no failure recorded. The statement-expression form below is the whole
// reason this macro is not written as AP_CHECK(expression) followed by
// if (!(expression)).
#if defined(_MSC_VER)
#define AP_REQUIRE(expression)                                          \
    do {                                                                \
        const bool ap_require_result = !!(expression);                   \
        context.check(ap_require_result, #expression, __FILE__, __LINE__); \
        if (!ap_require_result) {                                       \
            return;                                                     \
        }                                                               \
    } while (false)
#else
#define AP_REQUIRE(expression)                                              \
    do {                                                                    \
        const bool ap_require_result = ({ !!(expression); });                \
        context.check(ap_require_result, #expression, __FILE__, __LINE__);   \
        if (!ap_require_result) {                                           \
            return;                                                         \
        }                                                                   \
    } while (false)
#endif

// ---------------------------------------------------------------------------
// Rendering helpers used by AP_CHECK_EQ
// ---------------------------------------------------------------------------
[[nodiscard]] std::string render(bool value);
[[nodiscard]] std::string render(int value);
[[nodiscard]] std::string render(unsigned value);
[[nodiscard]] std::string render(long value);
[[nodiscard]] std::string render(unsigned long value);
[[nodiscard]] std::string render(long long value);
[[nodiscard]] std::string render(unsigned long long value);
[[nodiscard]] std::string render(const std::string& value);
[[nodiscard]] std::string render(std::string_view value);
[[nodiscard]] std::string render(const char* value);
[[nodiscard]] std::string render(const Status& value);
[[nodiscard]] std::string render(ErrorCode value);
[[nodiscard]] std::string render(Stage value);
[[nodiscard]] std::string render(ArtifactKind value);
[[nodiscard]] std::string render(EvidenceType value);
[[nodiscard]] std::string render(EvidenceResult value);
[[nodiscard]] std::string render(PromotionOutcome value);
[[nodiscard]] std::string render(GateStatus value);
[[nodiscard]] std::string render(HistoryEventKind value);
[[nodiscard]] std::string render(protocol::MessageType value);
[[nodiscard]] std::string render(const Digest& value);

template <typename Tag>
[[nodiscard]] std::string render(const Identity<Tag>& value) {
    return value.to_string();
}

template <typename Tag>
[[nodiscard]] std::string render(const Counter<Tag>& value) {
    return value.to_string();
}

// ---------------------------------------------------------------------------
// Scenario
//
// Drives the engine through realistic promotion scenarios using the publisher
// supplied evidence classes. Every call goes through the public engine API; no
// implementation detail is duplicated here.
// ---------------------------------------------------------------------------
struct ScenarioOptions {
    EngineConfig engine{};
    CoordinatorEpoch epoch{CoordinatorEpoch(1)};
};

class Scenario {
public:
    explicit Scenario(ScenarioOptions options = {});

    [[nodiscard]] PromotionEngine& engine() noexcept { return *engine_; }
    [[nodiscard]] const PromotionEngine& engine() const noexcept { return *engine_; }
    [[nodiscard]] CoordinatorAuthority authority() const { return engine_->authority(); }

    [[nodiscard]] ArtifactId make_artifact_id() noexcept;
    [[nodiscard]] Digest make_digest(std::string_view seed) noexcept;
    [[nodiscard]] PromotionRequestId make_request_id() noexcept;
    [[nodiscard]] PromotionAttemptId make_attempt_id() noexcept;
    [[nodiscard]] WorkerBootId make_boot_id() noexcept;

    // Registers a fresh artifact and returns its first revision record.
    [[nodiscard]] ArtifactRecord register_artifact(ArtifactId id, ArtifactKind kind, std::string_view name,
                                                   std::string_view digest_seed,
                                                   std::vector<std::string> dependencies = {});

    struct EvidenceSpec {
        EvidenceType type = EvidenceType::Invalid;
        EvidenceResult result = EvidenceResult::Pass;
        std::string custom_type{};
        bool use_current_digest = true;
        Digest override_digest{};
        bool use_current_revision = true;
        ArtifactRevision override_revision{};
        std::uint64_t produced_unix_millis = 0;  // 0 means "now"
        bool has_validity_window = false;
        std::uint64_t valid_from_unix_millis = 0;
        std::uint64_t valid_until_unix_millis = 0;
        std::string environment{};
        std::string measurement{};
        std::string detail{};
        WorkerBootId boot{};
    };

    [[nodiscard]] EvidenceRecord submit_spec(ArtifactId id, const EvidenceSpec& spec);

    // Submits one evidence record of a class with the default PASS result.
    [[nodiscard]] EvidenceRecord submit(ArtifactId id, EvidenceType type, EvidenceResult result,
                                        std::string_view digest_seed);

    // Runs one governed transition and returns the resulting outcome.
    [[nodiscard]] PromotionOutcome step(ArtifactId id, Stage destination);

    // Grants every evidence class the reference policy needs for one artifact
    // class and advances the artifact to PROMOTED one transition at a time.
    [[nodiscard]] Status drive_to_promoted(ArtifactId id);

    [[nodiscard]] ArtifactRecord current(ArtifactId id) const;

private:
    std::unique_ptr<PromotionEngine> engine_;
    IdentityGenerator<ArtifactIdTag> artifact_generator_;
    IdentityGenerator<PromotionRequestIdTag> request_generator_;
    IdentityGenerator<PromotionAttemptIdTag> attempt_generator_;
    IdentityGenerator<WorkerBootIdTag> boot_generator_;
    IdentityGenerator<ProvenanceRefTag> provenance_generator_;
};

}  // namespace artifact_promotion::test

#endif  // ARTIFACT_PROMOTION_TEST_CONTEXT_HPP
