// SPDX-License-Identifier: MIT
#pragma once
#include <FEXCore/fextl/allocator.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/Utils/File.h>

#include <fmt/format.h>
#include <fmt/ranges.h>
// fmt moved formatter<std::byte> out of format.h into std.h between 12.1.0 and
// 12.2.0. FEX formats std::span<std::byte> (CodeCache's cache-validation
// message uses fmt::join over one), so without this include the tree stops
// compiling against any system fmt >= 12.2 with an unformattable-type error.
// CMake's find_package(fmt QUIET) prefers the system copy over the bundled
// submodule, so which one you get depends on the host -- hence a build that
// works here and fails on a newer distro. fmt/std.h has existed for years, so
// including it unconditionally is safe against both.
#include <fmt/std.h>
#include <unistd.h>

namespace fextl::fmt {
template<typename T, size_t SIZE = ::fmt::inline_buffer_size, typename Allocator = fextl::FEXAlloc<T>>
using basic_memory_buffer = ::fmt::basic_memory_buffer<T, SIZE, Allocator>;
using memory_buffer = fextl::fmt::basic_memory_buffer<char>;

template<class OutputIt, class... Args>
OutputIt format_to(OutputIt out, ::fmt::format_string<Args...> fmt, Args&&... args) {
  return ::fmt::vformat_to(out, fmt.str, ::fmt::make_format_args(args...));
}

template<typename Char, size_t SIZE>
FMT_NODISCARD auto to_string(const fextl::fmt::basic_memory_buffer<Char, SIZE>& buf) -> fextl::basic_string<Char> {
  auto size = buf.size();
  ::fmt::detail::assume(size < std::basic_string<Char>().max_size());
  return fextl::basic_string<Char>(buf.data(), size);
}

FMT_INLINE fextl::string vformat(::fmt::string_view fmt, ::fmt::format_args args) {
  // Don't optimize the "{}" case to keep the binary size small and because it
  // can be better optimized in fmt::format anyway.
  auto buffer = memory_buffer();
  ::fmt::detail::vformat_to(buffer, fmt, args);
  return fextl::fmt::to_string(buffer);
}

template<typename... T>
FMT_NODISCARD FMT_INLINE auto format(::fmt::format_string<T...> fmt, T&&... args) -> fextl::string {
  return fextl::fmt::vformat(fmt, ::fmt::make_format_args(args...));
}

#ifndef _WIN32
template<typename... T>
FMT_INLINE auto print(::fmt::format_string<T...> fmt, T&&... args) -> void {
  auto String = fextl::fmt::vformat(fmt, ::fmt::make_format_args(args...));
  write(STDOUT_FILENO, String.c_str(), String.size());
}

template<typename... T>
FMT_INLINE auto print(int FD, ::fmt::format_string<T...> fmt, T&&... args) -> void {
  auto String = fextl::fmt::vformat(fmt, ::fmt::make_format_args(args...));
  write(FD, String.c_str(), String.size());
}
#else
template<typename... T>
FMT_INLINE auto print(::fmt::format_string<T...> fmt, T&&... args) -> void {
  auto String = fextl::fmt::vformat(fmt, ::fmt::make_format_args(args...));
  auto f = FEXCore::File::File::GetStdOUT();
  f.Write(String.c_str(), String.size());
}

template<typename... T>
FMT_INLINE auto print(HANDLE File, ::fmt::format_string<T...> fmt, T&&... args) -> void {
  auto String = fextl::fmt::vformat(fmt, ::fmt::make_format_args(args...));
  WriteFile(File, String.c_str(), String.size(), nullptr, nullptr);
}
#endif
template<typename... T>
FMT_INLINE auto print(FEXCore::File::File& f, ::fmt::format_string<T...> fmt, T&&... args) -> void {
  auto String = fextl::fmt::vformat(fmt, ::fmt::make_format_args(args...));
  f.Write(String.c_str(), String.size());
}

template<typename... T>
FMT_INLINE auto print(std::FILE* f, ::fmt::format_string<T...> fmt, T&&... args) -> void {
  auto String = fextl::fmt::vformat(fmt, ::fmt::make_format_args(args...));
  write(fileno(f), String.c_str(), String.size());
}
} // namespace fextl::fmt
