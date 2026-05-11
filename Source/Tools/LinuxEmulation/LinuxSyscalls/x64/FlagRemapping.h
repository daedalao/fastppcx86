// SPDX-License-Identifier: MIT
// x86-64 host open(2) flag remapping — identity, no translation needed.
// Included by Syscalls.h inside namespace FEX::HLE.

inline static int RemapFromX86Flags(int flags) {
  return flags;
}

inline static int RemapToX86Flags(int flags) {
  return flags;
}
