// Artifact Promotion - durable file primitives.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef ARTIFACT_PROMOTION_IO_HPP
#define ARTIFACT_PROMOTION_IO_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "artifact_promotion/bytes.hpp"
#include "artifact_promotion/error.hpp"

namespace artifact_promotion {

// Reads an entire file into memory. Fails rather than truncating.
[[nodiscard]] Result<ByteBuffer> read_file(const std::string& path);

// Writes bytes to a temporary file in the same directory, flushes it to the
// platform, verifies the byte count, and then atomically replaces the
// destination. The previous authoritative file is never overwritten with a
// partially written one: until the replacement succeeds, the original file
// remains untouched.
[[nodiscard]] Status atomic_write_file(const std::string& path, const ByteBuffer& data);

// Removes a file if it exists. Reports success when the file is already gone.
[[nodiscard]] Status remove_file(const std::string& path);

[[nodiscard]] bool file_exists(const std::string& path);

// Returns the directory portion of a path, or "." when there is none.
[[nodiscard]] std::string parent_directory(std::string_view path);

// Creates every missing directory in the path. Reports success when the
// directory already exists.
[[nodiscard]] Status create_directories(const std::string& path);

// Writes advisory status text to standard error. Used by the command line
// tools; the library itself never writes to stdout.
void write_stdout(std::string_view text);
void write_stderr(std::string_view text);

}  // namespace artifact_promotion

#endif  // ARTIFACT_PROMOTION_IO_HPP
