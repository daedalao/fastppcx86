// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// tiny-json declares this as `typedef struct json_s { ... } json_t;`, so the
// forward declaration has to name the struct and alias it, not declare a
// `struct json_t` -- that would be a different type and clash on include.
struct json_s;
using json_t = struct json_s;

/**
 * JSON for the launcher's own files.
 *
 * Reading goes through tiny-json, the same parser the rest of the tree uses.
 * Writing does not: tiny-json's writer targets a caller-provided fixed buffer
 * (Source/Common/Config.cpp gets away with 4 KiB because a Config layer is
 * small), and a registry holding many titles plus eight runtime lists will
 * outgrow any such buffer. The writer below streams into a std::string instead,
 * so there is no size ceiling to overrun.
 */
namespace FastPPCx86::Launcher::Json {

class Writer final {
public:
  Writer();

  void BeginObject(std::string_view Key = {});
  void EndObject();
  void BeginArray(std::string_view Key = {});
  void EndArray();

  void Str(std::string_view Key, std::string_view Value);
  void Int(std::string_view Key, int64_t Value);
  void Bool(std::string_view Key, bool Value);

  /// Bare values, for use between BeginArray/EndArray.
  void StrValue(std::string_view Value);

  /// Closes any still-open containers and returns the document.
  std::string Finish();

private:
  void Punctuate();
  void Indent();
  void Key(std::string_view Key);

  std::string Out;
  std::vector<bool> Stack; ///< true = array, false = object
  bool NeedComma {false};
};

/// Escapes per RFC 8259, including the control characters below 0x20.
void EscapeInto(std::string& Out, std::string_view Value);

// -- Reading -----------------------------------------------------------------

/// Reads a whole file. Returns false when it does not exist or cannot be read.
bool ReadFile(const std::string& Path, std::string& Out);

/**
 * Writes via a sibling temporary plus rename(2), so an interrupted save cannot
 * leave a half-written registry behind. Creates parent directories as needed.
 */
bool WriteFileAtomic(const std::string& Path, std::string_view Contents);

std::string GetString(const json_t* Obj, const char* Name, std::string_view Default = {});
int64_t GetInt(const json_t* Obj, const char* Name, int64_t Default = 0);
/// Accepts a real JSON bool, and also "1"/"0"/"true"/"false" as text.
bool GetBool(const json_t* Obj, const char* Name, bool Default = false);
std::vector<std::string> GetStringArray(const json_t* Obj, const char* Name);

} // namespace FastPPCx86::Launcher::Json
