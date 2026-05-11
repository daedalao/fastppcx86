// SPDX-License-Identifier: MIT
// PPC64LE host open(2) flag remapping.
// Translates x86-64 O_* flag values to/from the ppc64le kernel values.
// Included by Syscalls.h inside namespace FEX::HLE.
//
// Flag         x86-64    ppc64le
// O_DIRECT    040000    0400000
// O_LARGEFILE 0100000   0200000
// O_DIRECTORY 0200000   040000
// O_NOFOLLOW  0400000   0100000

inline static int RemapFromX86Flags(int flags) {
  constexpr int X86_O_DIRECT    = 040000;
  constexpr int X86_O_LARGEFILE = 0100000;
  constexpr int X86_O_DIRECTORY = 0200000;
  constexpr int X86_O_NOFOLLOW  = 0400000;

  constexpr int PPC_O_DIRECTORY = 040000;
  constexpr int PPC_O_NOFOLLOW  = 0100000;
  constexpr int PPC_O_LARGEFILE = 0200000;
  constexpr int PPC_O_DIRECT    = 0400000;

  int new_flags = 0;
  if (flags & X86_O_DIRECT)    { flags &= ~X86_O_DIRECT;    new_flags |= PPC_O_DIRECT;    }
  if (flags & X86_O_LARGEFILE) { flags &= ~X86_O_LARGEFILE; new_flags |= PPC_O_LARGEFILE; }
  if (flags & X86_O_DIRECTORY) { flags &= ~X86_O_DIRECTORY; new_flags |= PPC_O_DIRECTORY; }
  if (flags & X86_O_NOFOLLOW)  { flags &= ~X86_O_NOFOLLOW;  new_flags |= PPC_O_NOFOLLOW;  }
  return flags | new_flags;
}

inline static int RemapToX86Flags(int flags) {
  constexpr int X86_O_DIRECT    = 040000;
  constexpr int X86_O_LARGEFILE = 0100000;
  constexpr int X86_O_DIRECTORY = 0200000;
  constexpr int X86_O_NOFOLLOW  = 0400000;

  constexpr int PPC_O_DIRECTORY = 040000;
  constexpr int PPC_O_NOFOLLOW  = 0100000;
  constexpr int PPC_O_LARGEFILE = 0200000;
  constexpr int PPC_O_DIRECT    = 0400000;

  int new_flags = 0;
  if (flags & PPC_O_DIRECT)    { flags &= ~PPC_O_DIRECT;    new_flags |= X86_O_DIRECT;    }
  if (flags & PPC_O_LARGEFILE) { flags &= ~PPC_O_LARGEFILE; new_flags |= X86_O_LARGEFILE; }
  if (flags & PPC_O_DIRECTORY) { flags &= ~PPC_O_DIRECTORY; new_flags |= X86_O_DIRECTORY; }
  if (flags & PPC_O_NOFOLLOW)  { flags &= ~PPC_O_NOFOLLOW;  new_flags |= X86_O_NOFOLLOW;  }
  return flags | new_flags;
}
