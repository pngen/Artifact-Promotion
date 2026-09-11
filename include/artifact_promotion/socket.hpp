// Artifact Promotion - bounded TCP sockets for the reference deployment.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_SOCKET_HPP
#define ARTIFACT_PROMOTION_SOCKET_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/error.hpp"

namespace artifact_promotion::net {

// Initializes the platform networking subsystem. Idempotent and thread safe.
[[nodiscard]] Status initialize_networking();

[[nodiscard]] std::string last_socket_error();

// ---------------------------------------------------------------------------
// Socket
//
// A move-only RAII owner of one operating system socket. Destruction closes the
// handle exactly once, and every early-return path releases it.
// ---------------------------------------------------------------------------
class Socket {
public:
    Socket() = default;
    explicit Socket(std::uintptr_t handle) noexcept : handle_(handle) {}
    ~Socket();

    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] std::uintptr_t handle() const noexcept { return handle_; }

    void close() noexcept;

    // Sends every byte or reports a transport failure. A short write is
    // completed on the next iteration rather than silently truncating a frame.
    [[nodiscard]] Status send_all(const std::uint8_t* data, std::size_t size);
    [[nodiscard]] Status send_all(const ByteBuffer& data);

    // Reads exactly size bytes. A clean end of stream before size bytes is
    // reported as ConnectionClosed; a partial frame is never returned.
    [[nodiscard]] Status receive_exactly(std::uint8_t* data, std::size_t size);

    [[nodiscard]] Status set_nodelay(bool enabled);

    // A receive timeout makes a worker thread that is blocked on a dead peer
    // observably interruptible, which is what allows a bounded shutdown.
    [[nodiscard]] Status set_receive_timeout_millis(std::uint32_t millis);
    [[nodiscard]] Status set_send_timeout_millis(std::uint32_t millis);

    [[nodiscard]] std::string peer_address() const;

private:
    std::uintptr_t handle_ = kInvalidHandle;

public:
    static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(~static_cast<std::uintptr_t>(0));
};

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------
class Listener {
public:
    Listener() = default;
    ~Listener();

    Listener(Listener&& other) noexcept;
    Listener& operator=(Listener&& other) noexcept;
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;

    // Binds to the loopback interface only. The reference deployment never
    // accepts a connection from outside the host.
    [[nodiscard]] Status bind_loopback(std::uint16_t port);
    [[nodiscard]] Status listen(int backlog);

    // Blocks until a connection arrives or the listener is shut down.
    [[nodiscard]] Result<Socket> accept_one();

    // Unblocks a thread blocked in accept_one and refuses further connections.
    void shutdown() noexcept;

    [[nodiscard]] std::uint16_t bound_port() const noexcept { return bound_port_; }
    [[nodiscard]] bool valid() const noexcept { return handle_ != Socket::kInvalidHandle; }

    void close() noexcept;

private:
    std::uintptr_t handle_ = Socket::kInvalidHandle;
    std::uint16_t bound_port_ = 0;
};

// Connects to a loopback TCP endpoint with bounded retry while the peer starts.
[[nodiscard]] Result<Socket> connect_loopback(std::uint16_t port, int attempts, std::uint32_t delay_millis);

}  // namespace artifact_promotion::net

#endif  // ARTIFACT_PROMOTION_SOCKET_HPP
