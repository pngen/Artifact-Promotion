// Artifact Promotion - coordinator process.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Runs the authoritative coordinator: it owns promotion identity, lifecycle
// state, evidence applicability, policy generation, reservations, and the
// durable commit, and it serves the framed protocol on the loopback interface.
//
//   artifact-promotion-coordinator [--port N] [--state FILE] [--ready-file FILE]
//                                  [--run-millis N] [--once]
//
// --once exits immediately after printing the readiness line, which is how the
// process lifecycle tests start a coordinator and then terminate it literally.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include "artifact_promotion/coordinator_server.hpp"
#include "artifact_promotion/io.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace {

std::atomic<bool> g_stop_requested{false};

#if defined(_WIN32)
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
        g_stop_requested.store(true);
        return TRUE;
    }
    return FALSE;
}
#else
extern "C" void posix_handler(int) { g_stop_requested.store(true); }
#endif

struct Options {
    std::uint16_t port = 0;
    std::string state_path{};
    std::string ready_file{};
    std::uint64_t run_millis = 0;
    bool run_once = false;
};

void print_usage() {
    std::printf(
        "usage: artifact-promotion-coordinator [--port N] [--state FILE] [--ready-file FILE]\n"
        "                                      [--run-millis N] [--once]\n"
        "\n"
        "  --port N          loopback port to bind; 0 selects an ephemeral port and prints it\n"
        "  --state FILE      durable snapshot path; every committed mutation is written there\n"
        "  --ready-file FILE write the bound port to this file once the listener is accepting\n"
        "  --run-millis N    stop after this long; 0 means run until interrupted\n"
        "  --once            exit immediately after reporting readiness\n");
}

[[nodiscard]] bool parse_options(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        const auto next = [&](std::string& target) -> bool {
            if (i + 1 >= argc) {
                return false;
            }
            target = argv[++i];
            return true;
        };
        if (argument == "--help" || argument == "-h") {
            print_usage();
            std::exit(0);
        }
        if (argument == "--once") {
            options.run_once = true;
            continue;
        }
        std::string value;
        if (argument == "--port") {
            if (!next(value)) {
                return false;
            }
            const long parsed = std::strtol(value.c_str(), nullptr, 10);
            if (parsed < 0 || parsed > 65535) {
                return false;
            }
            options.port = static_cast<std::uint16_t>(parsed);
            continue;
        }
        if (argument == "--state") {
            if (!next(value)) {
                return false;
            }
            options.state_path = value;
            continue;
        }
        if (argument == "--ready-file") {
            if (!next(value)) {
                return false;
            }
            options.ready_file = value;
            continue;
        }
        if (argument == "--run-millis") {
            if (!next(value)) {
                return false;
            }
            options.run_millis = static_cast<std::uint64_t>(std::strtoull(value.c_str(), nullptr, 10));
            continue;
        }
        std::printf("unknown argument: %s\n", argument.c_str());
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!parse_options(argc, argv, options)) {
        print_usage();
        return 2;
    }

#if defined(_WIN32)
    (void)SetConsoleCtrlHandler(console_handler, TRUE);
#else
    (void)std::signal(SIGINT, posix_handler);
    (void)std::signal(SIGTERM, posix_handler);
#endif

    artifact_promotion::CoordinatorServer::Options server_options;
    server_options.port = options.port;
    server_options.state_path = options.state_path;
    artifact_promotion::CoordinatorServer server(server_options);

    const artifact_promotion::Status started = server.start();
    if (started.failed()) {
        std::printf("coordinator failed to start: %s\n", started.render().c_str());
        return 1;
    }

    const artifact_promotion::CoordinatorAuthority authority = server.engine().authority();
    std::printf("READY port=%u coordinator=%s epoch=%s policy=%s state=%s\n",
                static_cast<unsigned>(server.port()), authority.coordinator.to_string().c_str(),
                authority.epoch.to_string().c_str(),
                server.engine().snapshot().active_policy_digest.to_string().c_str(),
                options.state_path.empty() ? "<memory>" : options.state_path.c_str());
    std::fflush(stdout);

    if (!options.ready_file.empty()) {
        const std::string text = std::to_string(server.port());
        const artifact_promotion::ByteBuffer bytes(text.begin(), text.end());
        const artifact_promotion::Status written = artifact_promotion::atomic_write_file(options.ready_file, bytes);
        if (written.failed()) {
            std::printf("cannot write the readiness file: %s\n", written.render().c_str());
            server.stop();
            return 1;
        }
    }

    if (options.run_once) {
        server.stop();
        std::printf("STOPPED graceful\n");
        return 0;
    }

    const std::uint64_t started_at = artifact_promotion::PromotionEngine::now_millis();
    while (!g_stop_requested.load()) {
        if (options.run_millis > 0) {
            const std::uint64_t now = artifact_promotion::PromotionEngine::now_millis();
            if (now >= started_at && now - started_at >= options.run_millis) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    server.stop();
    std::printf("STOPPED graceful artifacts=%zu evidence=%zu pending=%zu\n", server.engine().count_artifacts(),
                server.engine().count_evidence(), server.engine().count_pending_transitions());
    return 0;
}
