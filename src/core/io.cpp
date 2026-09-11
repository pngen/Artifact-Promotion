// Artifact Promotion - durable file primitives.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "artifact_promotion/io.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <system_error>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace artifact_promotion {
namespace fs = std::filesystem;

Result<ByteBuffer> read_file(const std::string& path) {
    std::error_code error;
    const auto size = fs::file_size(path, error);
    if (error) {
        return Status(ErrorCode::PersistenceIoError, "cannot determine the size of the state file", path);
    }
    if (size > static_cast<std::uintmax_t>(kMaxSnapshotBytes)) {
        return Status(ErrorCode::PayloadTooLarge, "state file is larger than the supported snapshot bound", path);
    }
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return Status(ErrorCode::PersistenceIoError, "cannot open the state file for reading", path);
    }
    ByteBuffer buffer(static_cast<std::size_t>(size));
    if (size > 0) {
        stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size));
        if (stream.gcount() != static_cast<std::streamsize>(size)) {
            return Status(ErrorCode::PersistenceIoError, "state file was shorter than its reported size", path);
        }
    }
    if (stream.bad()) {
        return Status(ErrorCode::PersistenceIoError, "read error while loading the state file", path);
    }
    return buffer;
}

Status atomic_write_file(const std::string& path, const ByteBuffer& data) {
    const fs::path target(path);
    const fs::path directory = target.has_parent_path() ? target.parent_path() : fs::path(".");
    std::error_code error;
    if (!fs::exists(directory, error)) {
        fs::create_directories(directory, error);
        if (error) {
            return Status(ErrorCode::PersistenceIoError, "cannot create the state directory", directory.string());
        }
    }

    // A unique temporary name in the same directory keeps the replacement on
    // one volume, which is what makes the rename atomic.
    const fs::path temporary = directory / (target.filename().string() + ".tmp");

    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream) {
            return Status(ErrorCode::PersistenceIoError, "cannot open the temporary state file for writing",
                          temporary.string());
        }
        if (!data.empty()) {
            stream.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        }
        stream.flush();
        if (!stream) {
            stream.close();
            std::error_code cleanup;
            fs::remove(temporary, cleanup);
            return Status(ErrorCode::PersistenceIoError, "cannot flush the temporary state file",
                          temporary.string());
        }
    }

    // Verify the temporary file before it replaces anything authoritative.
    std::error_code verify_error;
    const auto written = fs::file_size(temporary, verify_error);
    if (verify_error || written != static_cast<std::uintmax_t>(data.size())) {
        std::error_code cleanup;
        fs::remove(temporary, cleanup);
        return Status(ErrorCode::PersistenceIoError, "temporary state file did not verify after writing",
                      temporary.string());
    }

#if defined(_WIN32)
    if (!MoveFileExW(temporary.wstring().c_str(), target.wstring().c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD last_error = GetLastError();
        std::error_code cleanup;
        fs::remove(temporary, cleanup);
        return Status(ErrorCode::PersistenceIoError,
                      "atomic replacement of the authoritative state file failed with error " +
                          std::to_string(static_cast<unsigned long>(last_error)),
                      target.string());
    }
#else
    fs::rename(temporary, target, error);
    if (error) {
        std::error_code cleanup;
        fs::remove(temporary, cleanup);
        return Status(ErrorCode::PersistenceIoError, "atomic replacement of the state file failed: " + error.message(),
                      target.string());
    }
#endif
    return Status::success();
}

Status remove_file(const std::string& path) {
    std::error_code error;
    fs::remove(path, error);
    if (error && error != std::errc::no_such_file_or_directory) {
        return Status(ErrorCode::PersistenceIoError, "cannot remove file: " + error.message(), path);
    }
    return Status::success();
}

bool file_exists(const std::string& path) {
    std::error_code error;
    return fs::exists(path, error);
}

std::string parent_directory(std::string_view path) {
    const fs::path value(path);
    if (!value.has_parent_path()) {
        return ".";
    }
    return value.parent_path().string();
}

Status create_directories(const std::string& path) {
    std::error_code error;
    fs::create_directories(path, error);
    if (error) {
        return Status(ErrorCode::PersistenceIoError, "cannot create directory: " + error.message(), path);
    }
    return Status::success();
}

void write_stdout(std::string_view text) {
    std::cout << text;
    std::cout.flush();
}

void write_stderr(std::string_view text) { std::cerr << text; }

}  // namespace artifact_promotion
