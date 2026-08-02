// SPDX-License-Identifier: MIT
#pragma once
#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/fmt.h>

#include <algorithm>
#include <string_view>

namespace FHU {

/**
 * @brief Parses a shebang interpreter line, returning a vector of string_views.
 *
 * Matches Linux `fs/binfmt_script.c` exactly:
 *   1. Skip leading ASCII whitespace (space or tab).
 *   2. Interpreter = the first token, up to the next whitespace or end.
 *   3. Skip whitespace after the interpreter.
 *   4. **All remaining content becomes ONE argument, unsplit**, with any
 *      trailing whitespace / '\r' stripped.
 *
 * So `#!/usr/bin/env python3 -u` yields two tokens — `"/usr/bin/env"` and
 * `"python3 -u"` — not three. Internal whitespace inside the second token
 * is preserved. `\r` from CRLF-authored scripts is stripped at the end of
 * whichever token is last (the interpreter, if no arg; the argument, if
 * present).
 *
 * @param ArgumentString The string of arguments to parse
 *
 * @return The array of parsed arguments (0, 1, or 2 elements)
 */
static inline fextl::vector<std::string_view> ParseArgumentsFromString(const std::string_view ArgumentString) {
  fextl::vector<std::string_view> Arguments;
  auto IsSep = [](char c) { return c == ' ' || c == '\t'; };

  const auto End = ArgumentString.end();
  auto It = ArgumentString.begin();

  // Skip leading whitespace.
  while (It != End && IsSep(*It)) {
    ++It;
  }
  if (It == End) {
    return Arguments;
  }

  // Interpreter: chars up to next whitespace or end.
  auto InterpBegin = It;
  while (It != End && !IsSep(*It)) {
    ++It;
  }
  auto InterpEnd = It;
  // Strip trailing '\r' from interpreter (CRLF residue when there is no arg).
  if (InterpEnd != InterpBegin && *(InterpEnd - 1) == '\r') {
    --InterpEnd;
  }
  Arguments.emplace_back(std::string_view(InterpBegin, InterpEnd - InterpBegin));

  // Skip whitespace after interpreter.
  while (It != End && IsSep(*It)) {
    ++It;
  }
  if (It == End) {
    return Arguments;
  }

  // Kernel argument cap: the remainder is ONE argument with internal
  // whitespace preserved. Strip trailing whitespace and any '\r'.
  auto ArgBegin = It;
  auto ArgEnd = End;
  while (ArgEnd != ArgBegin && (IsSep(*(ArgEnd - 1)) || *(ArgEnd - 1) == '\r')) {
    --ArgEnd;
  }
  if (ArgEnd != ArgBegin) {
    Arguments.emplace_back(std::string_view(ArgBegin, ArgEnd - ArgBegin));
  }
  return Arguments;
}
} // namespace FHU
