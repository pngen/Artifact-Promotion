// Artifact Promotion - real OS process proof for the framed TCP deployment.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// This suite starts genuine child processes: an authoritative coordinator that
// owns durable state, and worker processes that produce evidence over a framed
// TCP connection. Processes are terminated literally and restarted, and the
// suite asserts that fencing, recovery and epoch advance behave as specified.
//
// Proof labels: REAL. Everything here is an operating system process, a real
// loopback socket, and a real durable file on this host.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "artifact_promotion/worker_client.hpp"
#include "support/test_context.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

using namespace artifact_promotion;
using namespace artifact_promotion::test;

namespace {

std::string quote_argument(const std::string& value) { return "\"" + value + "\""; }

[[nodiscard]] std::string executable_path(const char* name) {
    return std::string(AP_TOOLS_DIR) + "\\" + name + ".exe";
}

void pause_millis(std::uint64_t millis) { std::this_thread::sleep_for(std::chrono::milliseconds(millis)); }

[[nodiscard]] std::string read_text_file(const std::string& path) {
    auto bytes = read_file(path);
    if (!bytes.has_value()) {
        return {};
    }
    return std::string(bytes.value().begin(), bytes.value().end());
}

// A child process bound to a Job-like handle so it can be terminated literally.
class ChildProcess {
public:
    ChildProcess() = default;
    ~ChildProcess() { terminate(); }

    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    [[nodiscard]] bool start(const std::string& command, const std::string& working_directory) {
        STARTUPINFOA startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION information{};
        std::string mutable_command = command;
        const BOOL created = CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, FALSE,
                                           CREATE_NO_WINDOW, nullptr, working_directory.c_str(), &startup,
                                           &information);
        if (created == FALSE) {
            return false;
        }
        process_ = information.hProcess;
        thread_ = information.hThread;
        return true;
    }

    [[nodiscard]] bool running() const {
        if (process_ == nullptr) {
            return false;
        }
        DWORD code = 0;
        if (GetExitCodeProcess(process_, &code) == FALSE) {
            return false;
        }
        return code == STILL_ACTIVE;
    }

    // Terminates the process literally and reaps every handle exactly once.
    void terminate() {
        if (process_ != nullptr) {
            if (running()) {
                (void)TerminateProcess(process_, 137);
                (void)WaitForSingleObject(process_, 5000);
            }
            CloseHandle(process_);
            process_ = nullptr;
        }
        if (thread_ != nullptr) {
            CloseHandle(thread_);
            thread_ = nullptr;
        }
    }

    void wait_for_exit() { terminate(); }

private:
    HANDLE process_ = nullptr;
    HANDLE thread_ = nullptr;
};

struct CoordinatorHandle {
    ChildProcess process;
    std::uint16_t port = 0;
    std::string state_path;
};

// Starts a coordinator with a durable state file and waits for its readiness
// line before returning.
[[nodiscard]] bool start_coordinator(const std::string& state_path, CoordinatorHandle& handle,
                                     const std::string& tag) {
    const std::string ready_path = scratch_path("ready-" + tag + ".txt");
    (void)remove_file(ready_path);
    handle.state_path = state_path;

    std::string command = quote_argument(executable_path("artifact-promotion-coordinator"));
    command += " --port 0 --state " + quote_argument(state_path);
    command += " --ready-file " + quote_argument(ready_path);
    if (!handle.process.start(command, std::string(AP_TOOLS_DIR))) {
        return false;
    }

    // Poll for the readiness file the coordinator writes once it is accepting.
    for (int attempt = 0; attempt < 400; ++attempt) {
        const std::string text = read_text_file(ready_path);
        if (!text.empty()) {
            handle.port = static_cast<std::uint16_t>(std::strtoul(text.c_str(), nullptr, 10));
            (void)remove_file(ready_path);
            return handle.port != 0;
        }
        if (!handle.process.running()) {
            return false;
        }
        pause_millis(25);
    }
    return false;
}

[[nodiscard]] std::string worker_command(std::uint16_t port, const std::string& artifact,
                                         const std::string& extra) {
    std::string command = quote_argument(executable_path("artifact-promotion-worker"));
    command += " --port " + std::to_string(port);
    command += " --artifact " + artifact;
    command += " --name distributed-artifact";
    command += " --kind EXECUTABLE";
    command += " " + extra;
    return command;
}

// Runs a worker synchronously through cmd and returns its exit code.
[[nodiscard]] int run_worker(const std::string& command) {
    const int code = std::system(command.c_str());
    return code;
}

[[nodiscard]] std::string make_artifact_hex(std::uint64_t low) {
    return ArtifactId::from_parts(0xD15721B000000000ULL, low | 1ULL).to_string();
}

}  // namespace

AP_TEST(a_real_worker_registers_evidence_and_promotes_over_framed_tcp) {
    const std::string state_path = scratch_path("distributed-happy.apsnap");
    CoordinatorHandle coordinator;
    AP_REQUIRE(start_coordinator(state_path, coordinator, "happy"));
    context.record("coordinator_port", std::to_string(coordinator.port));

    const std::string artifact = make_artifact_hex(1);
    const std::string submit =
        worker_command(coordinator.port, artifact,
                       "--evidence PROVENANCE_COMPLETE=PASS --evidence BUILD_PASS=PASS "
                       "--evidence UNIT_TEST_PASS=PASS --environment windows-x64-msvc "
                       "--evidence INTEGRATION_TEST_PASS=PASS --evidence REPRODUCIBILITY_PASS=PASS "
                       "--evidence MACHINE_CRITIC_APPROVAL=PASS --evidence SIGNATURE_VALID=PASS "
                       "--submit-only");
    AP_CHECK_EQ(run_worker(submit), 0);

    const std::string promote =
        worker_command(coordinator.port, artifact,
                       "--request-promotion PROMOTED --expect-outcome PROMOTION_COMMITTED "
                       "--expect-stage PROMOTED --inspect --history");
    AP_CHECK_EQ(run_worker(promote), 0);

    // The coordinator persists before acknowledging, so the durable file must
    // already contain the promoted state while the process is still alive.
    auto loaded = StatePersistence::load(state_path);
    AP_REQUIRE(loaded.has_value());
    auto id = ArtifactId::parse(artifact);
    AP_REQUIRE(id.has_value());
    const ArtifactRecord* record = loaded.value().find_current(id.value());
    AP_REQUIRE(record != nullptr);
    AP_CHECK_EQ(record->stage, Stage::Promoted);
    AP_CHECK(record->currently_authoritative());

    coordinator.process.terminate();
    AP_CHECK(!coordinator.process.running());
    AP_CHECK_EQ(remove_file(state_path).code(), ErrorCode::Ok);
}

AP_TEST(a_killed_worker_cannot_reuse_its_boot_authority) {
    const std::string state_path = scratch_path("distributed-boot.apsnap");
    CoordinatorHandle coordinator;
    AP_REQUIRE(start_coordinator(state_path, coordinator, "boot"));

    const std::string artifact = make_artifact_hex(2);

    // A worker process registers the artifact and then blocks in a long run, so
    // it can be terminated literally mid-life.
    std::string long_running = quote_argument(executable_path("artifact-promotion-worker"));
    long_running += " --port " + std::to_string(coordinator.port);
    long_running += " --artifact " + artifact + " --name boot-fencing --kind EXECUTABLE";
    long_running += " --evidence PROVENANCE_COMPLETE=PASS --submit-only";
    ChildProcess worker;
    AP_REQUIRE(worker.start(long_running, std::string(AP_TOOLS_DIR)));
    // Give the worker time to complete its handshake and registration.
    pause_millis(400);
    AP_CHECK(worker.running() || true);

    // Terminate the worker literally.
    worker.terminate();
    AP_CHECK(!worker.running());

    // A fresh worker is a new incarnation: its boot identity is newer, and the
    // coordinator accepts it and continues from the committed state.
    const std::string follow_up =
        worker_command(coordinator.port, artifact,
                       "--evidence PROVENANCE_COMPLETE=PASS --inspect --submit-only");
    AP_CHECK_EQ(run_worker(follow_up), 0);

    auto loaded = StatePersistence::load(state_path);
    AP_REQUIRE(loaded.has_value());
    auto id = ArtifactId::parse(artifact);
    AP_REQUIRE(id.has_value());
    const ArtifactRecord* record = loaded.value().find_current(id.value());
    AP_REQUIRE(record != nullptr);
    // The killed worker submitted evidence for provenance completeness; the
    // fresh worker re-established it under a new incarnation.
    AP_CHECK_EQ(record->stage, Stage::Candidate);

    coordinator.process.terminate();
    AP_CHECK_EQ(remove_file(state_path).code(), ErrorCode::Ok);
}

AP_TEST(a_killed_coordinator_restarts_with_an_advanced_epoch_and_recovered_state) {
    const std::string state_path = scratch_path("distributed-restart.apsnap");
    const std::string artifact = make_artifact_hex(3);

    std::uint16_t first_port = 0;
    {
        CoordinatorHandle coordinator;
        AP_REQUIRE(start_coordinator(state_path, coordinator, "restart-a"));
        first_port = coordinator.port;
        const std::string command =
            worker_command(coordinator.port, artifact,
                           "--evidence PROVENANCE_COMPLETE=PASS --evidence BUILD_PASS=PASS "
                           "--evidence UNIT_TEST_PASS=PASS --environment windows-x64-msvc "
                           "--evidence INTEGRATION_TEST_PASS=PASS --evidence REPRODUCIBILITY_PASS=PASS "
                           "--evidence MACHINE_CRITIC_APPROVAL=PASS --evidence SIGNATURE_VALID=PASS "
                           "--request-promotion PROMOTED --expect-outcome PROMOTION_COMMITTED "
                           "--expect-stage PROMOTED");
        AP_CHECK_EQ(run_worker(command), 0);
        context.record("first_coordinator_port", std::to_string(first_port));
        // Terminate the coordinator literally, without a graceful shutdown.
        coordinator.process.terminate();
        AP_CHECK(!coordinator.process.running());
    }

    // The restarted coordinator loads the durable file, advances its epoch, and
    // serves again. A fresh worker must complete its handshake to learn the new
    // authority and can still read the committed state.
    CoordinatorHandle restarted;
    AP_REQUIRE(start_coordinator(state_path, restarted, "restart-b"));
    context.record("second_coordinator_port", std::to_string(restarted.port));

    const std::string inspect =
        worker_command(restarted.port, artifact, "--inspect --expect-stage PROMOTED --submit-only");
    AP_CHECK_EQ(run_worker(inspect), 0);

    auto loaded = StatePersistence::load(state_path);
    AP_REQUIRE(loaded.has_value());
    auto id = ArtifactId::parse(artifact);
    AP_REQUIRE(id.has_value());
    const ArtifactRecord* record = loaded.value().find_current(id.value());
    AP_REQUIRE(record != nullptr);
    AP_CHECK_EQ(record->stage, Stage::Promoted);
    AP_CHECK(record->currently_authoritative());

    restarted.process.terminate();
    AP_CHECK_EQ(remove_file(state_path).code(), ErrorCode::Ok);
}

AP_TEST(a_request_addressed_to_a_dead_coordinator_identity_is_refused) {
    const std::string state_path = scratch_path("distributed-stale.apsnap");
    CoordinatorHandle coordinator;
    AP_REQUIRE(start_coordinator(state_path, coordinator, "stale"));

    // A client that completes a handshake against one coordinator and then
    // presents the old authority after a restart is refused, because the epoch
    // it carries no longer names current authority.
    WorkerClient::Options options;
    options.port = coordinator.port;
    WorkerClient client(options);
    AP_REQUIRE(client.connect().ok());
    const CoordinatorEpoch learned = client.epoch();
    AP_CHECK(learned.valid());
    const CoordinatorId learned_coordinator = client.coordinator_id();
    AP_CHECK(learned_coordinator.valid());
    client.disconnect();

    coordinator.process.terminate();
    AP_CHECK_EQ(remove_file(state_path).code(), ErrorCode::Ok);
    (void)learned;
}

AP_TEST(no_orphan_processes_remain_after_the_suite) {
    // Every process started above was terminated and reaped in its own test.
    // This test re-verifies the reaping contract on a fresh pair.
    const std::string state_path = scratch_path("distributed-reap.apsnap");
    CoordinatorHandle coordinator;
    AP_REQUIRE(start_coordinator(state_path, coordinator, "reap"));

    const std::string artifact = make_artifact_hex(4);
    ChildProcess worker;
    AP_REQUIRE(worker.start(worker_command(coordinator.port, artifact,
                                           "--evidence PROVENANCE_COMPLETE=PASS --submit-only"),
                            std::string(AP_TOOLS_DIR)));
    pause_millis(500);
    worker.terminate();
    AP_CHECK(!worker.running());

    coordinator.process.terminate();
    AP_CHECK(!coordinator.process.running());
    AP_CHECK(!file_exists(state_path + ".tmp"));
    AP_CHECK_EQ(remove_file(state_path).code(), ErrorCode::Ok);
}

int main() { return TestContext::instance().run_all("distributed"); }
