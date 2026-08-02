#include <catch2/catch_test_macros.hpp>

#include <FEXHeaderUtils/StringArgumentParser.h>

// The parser matches Linux fs/binfmt_script.c: at most 2 tokens per line —
// interpreter + a single unsplit arg. Tests updated by S4b to reflect this
// (multi-arg input strings are now collected into one "everything after
// interpreter" arg with internal whitespace preserved).

TEST_CASE("Basic") {
  const auto ArgString = "Test a b c";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "Test");
  CHECK(Args.at(1) == "a b c");
}

TEST_CASE("Basic - Empty") {
  const auto ArgString = "";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 0);
}

TEST_CASE("Basic - Empty spaces") {
  const auto ArgString = "                       ";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 0);
}

TEST_CASE("Basic - Space at start") {
  const auto ArgString = "      Test a b c";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "Test");
  CHECK(Args.at(1) == "a b c");
}

TEST_CASE("Basic - Bonus spaces between args") {
  const auto ArgString = "Test       a      b      c";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "Test");
  // Internal whitespace between "a" and later tokens is preserved as-is.
  CHECK(Args.at(1) == "a      b      c");
}

TEST_CASE("Basic - non printable") {
  const auto ArgString = "Test a b \x01c";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "Test");
  CHECK(Args.at(1) == "a b \x01c");
}

TEST_CASE("Basic - Emoji") {
  const auto ArgString = "Test a b 🐸";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "Test");
  CHECK(Args.at(1) == "a b 🐸");
}

TEST_CASE("Basic - space at the end") {
  const auto ArgString = "Test a b 🐸        ";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "Test");
  // Trailing whitespace stripped, internal whitespace preserved.
  CHECK(Args.at(1) == "a b 🐸");
}

// S4a: tab separator (Linux fs/binfmt_script.c splits on space and tab).
TEST_CASE("S4a - tab separator") {
  const auto ArgString = "/bin/sh\t-x";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "/bin/sh");
  CHECK(Args.at(1) == "-x");
}

// S4a: interpreter followed by whitespace of mixed types. Post-S4b the arg
// is a single unsplit token; internal whitespace stays as-is, only leading
// whitespace after the interpreter is trimmed. Trailing whitespace stripped.
TEST_CASE("S4a - mixed space and tab") {
  const auto ArgString = "/usr/bin/env\t python3 \t -u";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "/usr/bin/env");
  CHECK(Args.at(1) == "python3 \t -u");
}

// S4a: CRLF residue — a Windows-authored script's shebang line ends with
// '\r\n'. Callers cut at '\n' only, so the final token would be "-x\r"
// pre-fix; after S4a the trailing '\r' is stripped.
TEST_CASE("S4a - CRLF residue on last token") {
  const auto ArgString = "/bin/sh -x\r";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "/bin/sh");
  CHECK(Args.at(1) == "-x");
}

// S4a: leading tabs are stripped like leading spaces.
TEST_CASE("S4a - leading tabs") {
  const auto ArgString = "\t\t\t/bin/sh -x";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "/bin/sh");
  CHECK(Args.at(1) == "-x");
}

// S4a: input that is only tabs parses to zero tokens (same as spaces-only).
TEST_CASE("S4a - tabs only") {
  const auto ArgString = "\t\t\t\t";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 0);
}

// S4a: interpreter only, no args.
TEST_CASE("S4a - interpreter only") {
  const auto ArgString = "/bin/sh";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 1);
  CHECK(Args.at(0) == "/bin/sh");
}

// S4a: bare CR at the end of the interpreter (no arg) — trailing '\r'
// on the single token should be stripped.
TEST_CASE("S4a - CR after interpreter only") {
  const auto ArgString = "/bin/sh\r";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 1);
  CHECK(Args.at(0) == "/bin/sh");
}

// S4b: Linux fs/binfmt_script.c passes at most ONE arg after the interpreter,
// unsplit. This is the canonical `#!/usr/bin/env python3 -u` case — three
// tokens under space-splitting, two under kernel semantics.
TEST_CASE("S4b - kernel argument cap: env style") {
  const auto ArgString = "/usr/bin/env python3 -u";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "/usr/bin/env");
  CHECK(Args.at(1) == "python3 -u");
}

// S4b: internal whitespace inside the single argument is preserved verbatim
// (both space and tab).
TEST_CASE("S4b - kernel argument cap: mixed internal whitespace") {
  const auto ArgString = "/bin/sh\t-x -y\tfoo bar";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "/bin/sh");
  CHECK(Args.at(1) == "-x -y\tfoo bar");
}

// S4b: trailing '\r' at end of the arg (CRLF authored script) is stripped
// after the arg is collected. Trailing whitespace is also stripped.
TEST_CASE("S4b - kernel argument cap: CRLF and trailing whitespace") {
  const auto ArgString = "/bin/sh -x -y  \t\r";
  auto Args = FHU::ParseArgumentsFromString(ArgString);
  REQUIRE(Args.size() == 2);
  CHECK(Args.at(0) == "/bin/sh");
  CHECK(Args.at(1) == "-x -y");
}
