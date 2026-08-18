// SPDX-License-Identifier: MIT
#include "Json.h"

#include <FEXHeaderUtils/Filesystem.h>

#include <tiny-json.h>

#include <fmt/format.h>

#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <fcntl.h>
#include <unistd.h>

namespace FastPPCx86::Launcher::Json {

Writer::Writer() {
  Out.reserve(4096);
}

void Writer::Punctuate() {
  if (NeedComma) {
    Out += ',';
  }
  if (!Stack.empty()) {
    Out += '\n';
    Indent();
  }
  NeedComma = true;
}

void Writer::Indent() {
  Out.append(Stack.size() * 2, ' ');
}

void Writer::Key(std::string_view K) {
  if (K.empty()) {
    return;
  }
  Out += '"';
  EscapeInto(Out, K);
  Out += "\": ";
}

void Writer::BeginObject(std::string_view K) {
  Punctuate();
  Key(K);
  Out += '{';
  Stack.push_back(false);
  NeedComma = false;
}

void Writer::BeginArray(std::string_view K) {
  Punctuate();
  Key(K);
  Out += '[';
  Stack.push_back(true);
  NeedComma = false;
}

void Writer::EndObject() {
  const bool Empty = !NeedComma;
  Stack.pop_back();
  if (!Empty) {
    Out += '\n';
    Indent();
  }
  Out += '}';
  NeedComma = true;
}

void Writer::EndArray() {
  const bool Empty = !NeedComma;
  Stack.pop_back();
  if (!Empty) {
    Out += '\n';
    Indent();
  }
  Out += ']';
  NeedComma = true;
}

void Writer::Str(std::string_view K, std::string_view Value) {
  Punctuate();
  Key(K);
  Out += '"';
  EscapeInto(Out, Value);
  Out += '"';
}

void Writer::StrValue(std::string_view Value) {
  Str({}, Value);
}

void Writer::Int(std::string_view K, int64_t Value) {
  Punctuate();
  Key(K);
  fmt::format_to(std::back_inserter(Out), "{}", Value);
}

void Writer::Bool(std::string_view K, bool Value) {
  Punctuate();
  Key(K);
  Out += Value ? "true" : "false";
}

std::string Writer::Finish() {
  while (!Stack.empty()) {
    if (Stack.back()) {
      EndArray();
    } else {
      EndObject();
    }
  }
  Out += '\n';
  return std::move(Out);
}

void EscapeInto(std::string& Out, std::string_view Value) {
  for (const char C : Value) {
    switch (C) {
    case '"': Out += "\\\""; break;
    case '\\': Out += "\\\\"; break;
    case '\n': Out += "\\n"; break;
    case '\r': Out += "\\r"; break;
    case '\t': Out += "\\t"; break;
    case '\b': Out += "\\b"; break;
    case '\f': Out += "\\f"; break;
    default:
      // Everything below 0x20 must be escaped; the \u form is the only one that
      // covers the codes without a short escape. Bytes >= 0x80 are passed
      // through untouched so UTF-8 in a title name survives a save/load cycle.
      if (static_cast<unsigned char>(C) < 0x20) {
        fmt::format_to(std::back_inserter(Out), "\\u{:04x}", static_cast<unsigned>(static_cast<unsigned char>(C)));
      } else {
        Out += C;
      }
      break;
    }
  }
}

bool ReadFile(const std::string& Path, std::string& Out) {
  const int FD = ::open(Path.c_str(), O_RDONLY | O_CLOEXEC);
  if (FD < 0) {
    return false;
  }

  Out.clear();
  char Buffer[8192];
  ssize_t Read {};
  while ((Read = ::read(FD, Buffer, sizeof(Buffer))) > 0) {
    Out.append(Buffer, static_cast<size_t>(Read));
  }
  const bool Failed = Read < 0;
  ::close(FD);
  return !Failed;
}

bool WriteFileAtomic(const std::string& Path, std::string_view Contents) {
  const auto Parent = FHU::Filesystem::ParentPath(Path.c_str());
  if (!Parent.empty() && !FHU::Filesystem::Exists(Parent) && !FHU::Filesystem::CreateDirectories(Parent)) {
    return false;
  }

  // Same directory as the target, so the rename below stays within one
  // filesystem and is therefore atomic.
  std::string Temp = Path + ".tmp";
  const int FD = ::open(Temp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (FD < 0) {
    return false;
  }

  size_t Offset {};
  bool Ok = true;
  while (Offset < Contents.size()) {
    const ssize_t Written = ::write(FD, Contents.data() + Offset, Contents.size() - Offset);
    if (Written <= 0) {
      if (errno == EINTR) {
        continue;
      }
      Ok = false;
      break;
    }
    Offset += static_cast<size_t>(Written);
  }

  // Durability before the rename: a rename over a target whose data has not
  // reached disk can survive a crash as an empty file.
  if (Ok && ::fsync(FD) != 0) {
    Ok = false;
  }
  ::close(FD);

  if (!Ok || ::rename(Temp.c_str(), Path.c_str()) != 0) {
    ::unlink(Temp.c_str());
    return false;
  }
  return true;
}

std::string GetString(const json_t* Obj, const char* Name, std::string_view Default) {
  if (!Obj) {
    return std::string {Default};
  }
  const json_t* Property = json_getProperty(Obj, Name);
  if (!Property) {
    return std::string {Default};
  }
  const jsonType_t Type = json_getType(Property);
  if (Type != JSON_TEXT && Type != JSON_INTEGER && Type != JSON_REAL && Type != JSON_BOOLEAN) {
    return std::string {Default};
  }
  const char* Value = json_getValue(Property);
  return Value ? std::string {Value} : std::string {Default};
}

int64_t GetInt(const json_t* Obj, const char* Name, int64_t Default) {
  if (!Obj) {
    return Default;
  }
  const json_t* Property = json_getProperty(Obj, Name);
  if (!Property) {
    return Default;
  }
  if (json_getType(Property) == JSON_INTEGER) {
    return json_getInteger(Property);
  }
  // Accept a quoted number too: FEX config files habitually write "1" rather
  // than 1, and hand-edited registries will copy that habit.
  const char* Value = json_getValue(Property);
  if (!Value) {
    return Default;
  }
  int64_t Parsed {};
  const auto* End = Value + std::strlen(Value);
  if (std::from_chars(Value, End, Parsed).ec != std::errc {}) {
    return Default;
  }
  return Parsed;
}

bool GetBool(const json_t* Obj, const char* Name, bool Default) {
  if (!Obj) {
    return Default;
  }
  const json_t* Property = json_getProperty(Obj, Name);
  if (!Property) {
    return Default;
  }
  if (json_getType(Property) == JSON_BOOLEAN) {
    return json_getBoolean(Property);
  }
  const char* Value = json_getValue(Property);
  if (!Value) {
    return Default;
  }
  const std::string_view View {Value};
  if (View == "1" || View == "true" || View == "True") {
    return true;
  }
  if (View == "0" || View == "false" || View == "False") {
    return false;
  }
  return Default;
}

std::vector<std::string> GetStringArray(const json_t* Obj, const char* Name) {
  std::vector<std::string> Result;
  if (!Obj) {
    return Result;
  }
  const json_t* Array = json_getProperty(Obj, Name);
  if (!Array || json_getType(Array) != JSON_ARRAY) {
    return Result;
  }
  for (const json_t* Element = json_getChild(Array); Element; Element = json_getSibling(Element)) {
    if (const char* Value = json_getValue(Element)) {
      Result.emplace_back(Value);
    }
  }
  return Result;
}

} // namespace FastPPCx86::Launcher::Json
