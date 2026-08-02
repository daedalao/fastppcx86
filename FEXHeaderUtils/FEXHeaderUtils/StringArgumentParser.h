// SPDX-License-Identifier: MIT
#pragma once
#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/fmt.h>

#include <algorithm>
#include <string_view>

namespace FHU {

/**
 * @brief Parses a string of arguments, returning a vector of string_views.
 *
 * Split by ASCII space OR tab, matching Linux `fs/binfmt_script.c`'s
 * shebang tokeniser. Trailing '\r' on the last token is stripped so
 * CRLF-authored scripts (Windows line endings) parse as if they were LF.
 *
 * @param ArgumentString The string of arguments to parse
 *
 * @return The array of parsed arguments
 */
static inline fextl::vector<std::string_view> ParseArgumentsFromString(const std::string_view ArgumentString) {
  fextl::vector<std::string_view> Arguments;

  auto Begin = ArgumentString.begin();
  auto ArgEnd = Begin;
  const auto End = ArgumentString.end();
  auto IsSep = [](char c) { return c == ' ' || c == '\t'; };
  while (ArgEnd != End && Begin != End) {
    // Argument ends at a space, tab, or the end of the interpreter line.
    ArgEnd = std::find_if(Begin, End, IsSep);

    if (Begin != ArgEnd) {
      // Strip a trailing '\r' — CRLF-authored scripts (Windows) put the
      // '\r' at the end of the interpreter line's final token; without this
      // the last argument is e.g. "-x\r" and Exists() fails downstream.
      auto ViewEnd = ArgEnd;
      if (ViewEnd != Begin && *(ViewEnd - 1) == '\r') {
        --ViewEnd;
      }
      const auto View = std::string_view(Begin, ViewEnd - Begin);
      if (!View.empty()) {
        Arguments.emplace_back(View);
      }
    }

    // Advance past the separator, but never past End. Prior code did
    // `Begin = ArgEnd + 1` even when ArgEnd == End, which is a one-past-the-
    // end iterator — inert only because the loop guard catches it before any
    // dereference, but still undefined behaviour on the increment itself.
    Begin = (ArgEnd == End) ? End : ArgEnd + 1;
  }

  return Arguments;
}
} // namespace FHU
