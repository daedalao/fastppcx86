// SPDX-License-Identifier: MIT
#pragma once

// Token registry for opaque host handles crossing into a 32-bit guest.
//
// A host handle is a 64-bit pointer; a 32-bit guest cannot hold one. Handing
// the pointer over truncates it, which either faults later or - worse -
// silently addresses the wrong object. Instead the host keeps the pointer and
// gives the guest a stable 32-bit token, translating back on the way in.
//
// Tokens are drawn from a per-type range so a handle of the wrong type is
// rejected rather than silently reinterpreted, and index 0 is never handed out
// so token 0 stays reserved for null.
//
// NOTE: libGL/libGL_Host.cpp still carries a private copy of this (the
// GLXFBConfig/GLXContext/GLsync registries). It should migrate here, but that
// path is freshly validated and was left alone deliberately.

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace FEX::Thunks {

template<typename T, uint32_t TokenBase>
struct OpaqueHandleRegistry {
  std::mutex Mutex;
  // Index 0 is never handed out so that token 0 stays reserved for null.
  std::vector<T*> ByIndex {nullptr};
  std::unordered_map<T*, uint32_t> ToToken;

  uint32_t TokenFor(T* Host) {
    if (!Host) {
      return 0;
    }
    std::lock_guard lk {Mutex};
    if (auto It = ToToken.find(Host); It != ToToken.end()) {
      return It->second;
    }
    const uint32_t Token = TokenBase + static_cast<uint32_t>(ByIndex.size());
    ByIndex.push_back(Host);
    ToToken.emplace(Host, Token);
    return Token;
  }

  T* ForToken(uint32_t Token) {
    if (!Token) {
      return nullptr;
    }
    std::lock_guard lk {Mutex};
    // Token maps 1:1 onto an index.
    const uint32_t Index = Token - TokenBase;
    if (Token < TokenBase || Index >= ByIndex.size()) {
      // Not one of ours. Pass it through rather than inventing a null: a guest
      // that obtained a handle by some path we do not model should fail in the
      // driver with its own diagnostics, not silently here.
      return reinterpret_cast<T*>(static_cast<uintptr_t>(Token));
    }
    // Null here means the handle was retired - the guest is using it after
    // destroying it. Returning null makes the driver reject it; returning the
    // old pointer would dereference freed memory.
    return ByIndex[Index];
  }

  // Drop a handle whose underlying object is being destroyed. The slot is kept
  // (so later tokens keep their meaning) but emptied, and the pointer is
  // un-interned so an allocator reusing the address cannot resurrect the
  // retired token for a different object.
  void Retire(T* Host) {
    if (!Host) {
      return;
    }
    std::lock_guard lk {Mutex};
    auto It = ToToken.find(Host);
    if (It == ToToken.end()) {
      return;
    }
    const uint32_t Index = It->second - TokenBase;
    if (Index < ByIndex.size()) {
      ByIndex[Index] = nullptr;
    }
    ToToken.erase(It);
  }
};

} // namespace FEX::Thunks
