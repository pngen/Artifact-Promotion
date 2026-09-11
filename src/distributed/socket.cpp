// Artifact Promotion - bounded TCP sockets for the reference deployment.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/socket.hpp"

#include <chrono>
#include <mutex>
#include <thread>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace artifact_promotion::net {
namespace {

#if defined(_WIN32)
using native_socket = SOCKET;
constexpr native_socket kInvalidNative = INVALID_SOCKET;

native_socket to_native(std::uintptr_t handle) noexcept { return static_cast<native_socket>(handle); }
std::uintptr_t from_native(native_socket handle) noexcept { return static_cast<std::uintptr_t>(handle); }
#else
using native_socket = int;
constexpr native_socket kInvalidNative = -1;

native_socket to_native(std::uintptr_t handle) noexcept { return static_cast<native_socket>(handle); }
std::uintptr_t from_native(native_socket handle) noexcept { return static_cast<std::uintptr_t>(handle); }
#endif

std::once_flag g_init_once;
Status g_init_status = Status::success();

Status perform_init() {
#if defined(_WIN32)
    WSADATA data{};
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        return Status(ErrorCode::TransportError, "WSAStartup failed with error " + std::to_string(result));
    }
#endif
    return Status::success();
}

}  // namespace

Status initialize_networking() {
    std::call_once(g_init_once, [] { g_init_status = perform_init(); });
    return g_init_status;
}

std::string last_socket_error() {
#if defined(_WIN32)
    return "winsock error " + std::to_string(WSAGetLastError());
#else
    return std::string(std::strerror(errno));
#endif
}

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) { other.handle_ = kInvalidHandle; }

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        other.handle_ = kInvalidHandle;
    }
    return *this;
}

bool Socket::valid() const noexcept { return handle_ != kInvalidHandle; }

void Socket::close() noexcept {
    if (handle_ == kInvalidHandle) {
        return;
    }
    const native_socket native = to_native(handle_);
#if defined(_WIN32)
    ::shutdown(native, SD_BOTH);
    ::closesocket(native);
#else
    ::shutdown(native, SHUT_RDWR);
    ::close(native);
#endif
    handle_ = kInvalidHandle;
}

Status Socket::send_all(const std::uint8_t* data, std::size_t size) {
    if (!valid()) {
        return Status(ErrorCode::TransportError, "send attempted on a closed socket");
    }
    std::size_t offset = 0;
    while (offset < size) {
        const std::size_t remaining = size - offset;
        const int chunk = remaining > static_cast<std::size_t>(0x7FFFFFFF) ? 0x7FFFFFFF
                                                                            : static_cast<int>(remaining);
        const int sent = ::send(to_native(handle_), reinterpret_cast<const char*>(data + offset), chunk, 0);
        if (sent <= 0) {
            return Status(ErrorCode::TransportError, "send failed: " + last_socket_error());
        }
        offset += static_cast<std::size_t>(sent);
    }
    return Status::success();
}

Status Socket::send_all(const ByteBuffer& data) { return send_all(data.data(), data.size()); }

Status Socket::receive_exactly(std::uint8_t* data, std::size_t size) {
    if (!valid()) {
        return Status(ErrorCode::TransportError, "receive attempted on a closed socket");
    }
    std::size_t offset = 0;
    while (offset < size) {
        const std::size_t remaining = size - offset;
        const int chunk = remaining > static_cast<std::size_t>(0x7FFFFFFF) ? 0x7FFFFFFF
                                                                            : static_cast<int>(remaining);
        const int received = ::recv(to_native(handle_), reinterpret_cast<char*>(data + offset), chunk, 0);
        if (received == 0) {
            return Status(ErrorCode::ConnectionClosed, "peer closed the connection mid-frame");
        }
        if (received < 0) {
            return Status(ErrorCode::TransportError, "receive failed: " + last_socket_error());
        }
        offset += static_cast<std::size_t>(received);
    }
    return Status::success();
}

Status Socket::set_nodelay(bool enabled) {
    if (!valid()) {
        return Status(ErrorCode::TransportError, "option set attempted on a closed socket");
    }
    const int value = enabled ? 1 : 0;
    const int result = ::setsockopt(to_native(handle_), IPPROTO_TCP, TCP_NODELAY,
                                    reinterpret_cast<const char*>(&value), sizeof(value));
    if (result != 0) {
        return Status(ErrorCode::TransportError, "cannot set TCP_NODELAY: " + last_socket_error());
    }
    return Status::success();
}

Status Socket::set_receive_timeout_millis(std::uint32_t millis) {
    if (!valid()) {
        return Status(ErrorCode::TransportError, "option set attempted on a closed socket");
    }
#if defined(_WIN32)
    const DWORD value = static_cast<DWORD>(millis);
    const int result = ::setsockopt(to_native(handle_), SOL_SOCKET, SO_RCVTIMEO,
                                    reinterpret_cast<const char*>(&value), sizeof(value));
#else
    struct timeval value {};
    value.tv_sec = static_cast<long>(millis / 1000U);
    value.tv_usec = static_cast<long>((millis % 1000U) * 1000U);
    const int result = ::setsockopt(to_native(handle_), SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value));
#endif
    if (result != 0) {
        return Status(ErrorCode::TransportError, "cannot set the receive timeout: " + last_socket_error());
    }
    return Status::success();
}

Status Socket::set_send_timeout_millis(std::uint32_t millis) {
    if (!valid()) {
        return Status(ErrorCode::TransportError, "option set attempted on a closed socket");
    }
#if defined(_WIN32)
    const DWORD value = static_cast<DWORD>(millis);
    const int result = ::setsockopt(to_native(handle_), SOL_SOCKET, SO_SNDTIMEO,
                                    reinterpret_cast<const char*>(&value), sizeof(value));
#else
    struct timeval value {};
    value.tv_sec = static_cast<long>(millis / 1000U);
    value.tv_usec = static_cast<long>((millis % 1000U) * 1000U);
    const int result = ::setsockopt(to_native(handle_), SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value));
#endif
    if (result != 0) {
        return Status(ErrorCode::TransportError, "cannot set the send timeout: " + last_socket_error());
    }
    return Status::success();
}

std::string Socket::peer_address() const {
    if (!valid()) {
        return "<closed>";
    }
    sockaddr_storage address{};
#if defined(_WIN32)
    int length = sizeof(address);
#else
    socklen_t length = sizeof(address);
#endif
    if (::getpeername(to_native(handle_), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        return "<unknown>";
    }
    char text[64] = {};
    if (address.ss_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
        const std::uint32_t host = ntohl(ipv4->sin_addr.s_addr);
        std::snprintf(text, sizeof(text), "%u.%u.%u.%u:%u", (host >> 24) & 0xFFU, (host >> 16) & 0xFFU,
                      (host >> 8) & 0xFFU, host & 0xFFU, static_cast<unsigned>(ntohs(ipv4->sin_port)));
    } else {
        std::snprintf(text, sizeof(text), "<non-ipv4>");
    }
    return std::string(text);
}

Listener::~Listener() { close(); }

Listener::Listener(Listener&& other) noexcept : handle_(other.handle_), bound_port_(other.bound_port_) {
    other.handle_ = Socket::kInvalidHandle;
    other.bound_port_ = 0;
}

Listener& Listener::operator=(Listener&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        bound_port_ = other.bound_port_;
        other.handle_ = Socket::kInvalidHandle;
        other.bound_port_ = 0;
    }
    return *this;
}

void Listener::close() noexcept {
    if (handle_ == Socket::kInvalidHandle) {
        return;
    }
    const native_socket native = to_native(handle_);
#if defined(_WIN32)
    ::closesocket(native);
#else
    ::close(native);
#endif
    handle_ = Socket::kInvalidHandle;
}

Status Listener::bind_loopback(std::uint16_t port) {
    const Status init = initialize_networking();
    if (init.failed()) {
        return init;
    }
    const native_socket native = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (native == kInvalidNative) {
        return Status(ErrorCode::TransportError, "cannot create a listening socket: " + last_socket_error());
    }
    handle_ = from_native(native);

    const int reuse = 1;
    ::setsockopt(native, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (::bind(native, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        const std::string error = last_socket_error();
        close();
        return Status(ErrorCode::TransportError, "cannot bind the loopback listener: " + error);
    }

    sockaddr_in bound{};
#if defined(_WIN32)
    int length = sizeof(bound);
#else
    socklen_t length = sizeof(bound);
#endif
    if (::getsockname(native, reinterpret_cast<sockaddr*>(&bound), &length) == 0) {
        bound_port_ = ntohs(bound.sin_port);
    } else {
        bound_port_ = port;
    }
    return Status::success();
}

Status Listener::listen(int backlog) {
    if (!valid()) {
        return Status(ErrorCode::TransportError, "listen attempted on an unbound listener");
    }
    if (::listen(to_native(handle_), backlog) != 0) {
        return Status(ErrorCode::TransportError, "cannot listen on the loopback socket: " + last_socket_error());
    }
    return Status::success();
}

Result<Socket> Listener::accept_one() {
    if (!valid()) {
        return Status(ErrorCode::ConnectionClosed, "listener is closed");
    }
    const native_socket accepted = ::accept(to_native(handle_), nullptr, nullptr);
    if (accepted == kInvalidNative) {
        return Status(ErrorCode::ConnectionClosed, "accept failed: " + last_socket_error());
    }
    return Socket(from_native(accepted));
}

void Listener::shutdown() noexcept {
    if (!valid()) {
        return;
    }
#if defined(_WIN32)
    ::shutdown(to_native(handle_), SD_BOTH);
#else
    ::shutdown(to_native(handle_), SHUT_RDWR);
#endif
}

Result<Socket> connect_loopback(std::uint16_t port, int attempts, std::uint32_t delay_millis) {
    const Status init = initialize_networking();
    if (init.failed()) {
        return init;
    }
    Status last = Status(ErrorCode::TransportError, "no connection attempt was made");
    for (int attempt = 0; attempt < attempts; ++attempt) {
        const native_socket native = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (native == kInvalidNative) {
            last = Status(ErrorCode::TransportError, "cannot create a client socket: " + last_socket_error());
        } else {
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = htons(port);
            if (::connect(native, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0) {
                Socket socket(from_native(native));
                (void)socket.set_nodelay(true);
                return socket;
            }
            last = Status(ErrorCode::TransportError, "connect failed: " + last_socket_error());
#if defined(_WIN32)
            ::closesocket(native);
#else
            ::close(native);
#endif
        }
        if (attempt + 1 < attempts) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_millis));
        }
    }
    return last;
}

}  // namespace artifact_promotion::net
