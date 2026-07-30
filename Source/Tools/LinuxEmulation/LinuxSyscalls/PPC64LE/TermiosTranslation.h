// SPDX-License-Identifier: MIT
#pragma once

// x86 <-> PowerPC termios translation.
//
// PowerPC's termios ABI differs from x86's in three independent ways, and all
// three have to be handled or a guest gets nonsense back from tcgetattr():
//
//   1. SIZE. The guest x86 kernel `struct termios` is 36 bytes. The host
//      buffer we pass to `::ioctl(TCGETS, …)` must match what glibc writes,
//      which on PowerPC is `struct termios` from `<termios.h>` — 60 bytes.
//      That is a **userspace** translation: glibc's PowerPC ioctl wrapper
//      calls the kernel with the 44-byte `__kernel_termios`, then converts
//      into the 60-byte layout at the caller's pointer regardless of the
//      caller's declared buffer size. Handing that wrapper a 44-byte struct
//      overruns by 16 bytes and trips the stack canary — observed as
//      "*** stack smashing detected ***" running apt on a pty.
//   2. LAYOUT. x86 orders {flags, c_line, c_cc[19]}. PowerPC glibc also puts
//      c_line before c_cc, but with NCCS=32 and c_ispeed/c_ospeed at 52/56.
//      Not the same as the kernel's internal layout, which is
//      {flags, c_cc[19], c_line, c_ispeed@36, c_ospeed@40} — see
//      `build-probes/probe_termios_layout.c` for the raw evidence.
//   3. FLAG BIT VALUES. Every one of the four flag words disagrees. The two
//      that bite hardest: ONLCR is 0x4 on x86 and 0x2 on PowerPC, while OLCUC
//      is 0x2 on x86 and 0x4 on PowerPC — exactly swapped. A guest setting
//      the entirely ordinary ONLCR ("map NL to CR-NL") lands on PowerPC's
//      OLCUC ("map lowercase to UPPERCASE on output"). c_lflag is worse: x86's
//      is System V derived, PowerPC's is BSD derived, and almost nothing lines
//      up.
//
// Everything below is expressed as explicit {guest_bit, host_bit} pairs rather
// than arithmetic, so each line can be checked against asm-generic/termbits.h
// and arch/powerpc/include/uapi/asm/termbits.h by eye.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <termios.h>

namespace FEX::HLE::PPC64 {

// The x86 kernel's struct termios, as the guest sees it. 36 bytes.
struct GuestTermios {
  uint32_t c_iflag;
  uint32_t c_oflag;
  uint32_t c_cflag;
  uint32_t c_lflag;
  uint8_t c_line;
  uint8_t c_cc[19];
};
static_assert(sizeof(GuestTermios) == 36, "x86 kernel struct termios is 36 bytes");

// The host buffer type is glibc's own `struct termios` from `<termios.h>`.
// That is *by definition* the layout its ioctl wrapper writes for TCGETS on
// this arch. Pinning the assumptions here so a future glibc change breaks
// the build instead of silently corrupting a terminal.
static_assert(sizeof(struct termios) == 60, "PowerPC glibc struct termios must be 60 bytes");
static_assert(offsetof(struct termios, c_iflag) == 0, "");
static_assert(offsetof(struct termios, c_oflag) == 4, "");
static_assert(offsetof(struct termios, c_cflag) == 8, "");
static_assert(offsetof(struct termios, c_lflag) == 12, "");
static_assert(offsetof(struct termios, c_line) == 16, "c_line must precede c_cc in glibc layout");
static_assert(offsetof(struct termios, c_cc) == 17, "c_cc must follow c_line in glibc layout");
static_assert(offsetof(struct termios, c_ispeed) == 52, "");
static_assert(offsetof(struct termios, c_ospeed) == 56, "");
static_assert(NCCS >= 17, "glibc NCCS must cover PowerPC's 17 defined V* slots");

struct BitPair {
  uint32_t Guest;
  uint32_t Host;
};

// c_iflag — only IXON/IXOFF/IUCLC move.
constexpr BitPair IFlagMap[] = {
  {0x0001, 0x0001}, // IGNBRK
  {0x0002, 0x0002}, // BRKINT
  {0x0004, 0x0004}, // IGNPAR
  {0x0008, 0x0008}, // PARMRK
  {0x0010, 0x0010}, // INPCK
  {0x0020, 0x0020}, // ISTRIP
  {0x0040, 0x0040}, // INLCR
  {0x0080, 0x0080}, // IGNCR
  {0x0100, 0x0100}, // ICRNL
  {0x0200, 0x1000}, // IUCLC   x86 0x200 -> ppc 0x1000
  {0x0400, 0x0200}, // IXON    x86 0x400 -> ppc 0x200
  {0x0800, 0x0800}, // IXANY
  {0x1000, 0x0400}, // IXOFF   x86 0x1000 -> ppc 0x400
  {0x2000, 0x2000}, // IMAXBEL
  {0x4000, 0x4000}, // IUTF8
};

// c_oflag — OLCUC and ONLCR are swapped. This pair is the uppercase bug.
constexpr BitPair OFlagMap[] = {
  {0x01, 0x01}, // OPOST
  {0x02, 0x04}, // OLCUC  x86 0x02 -> ppc 0x04
  {0x04, 0x02}, // ONLCR  x86 0x04 -> ppc 0x02
  {0x08, 0x08}, // OCRNL
  {0x10, 0x10}, // ONOCR
  {0x20, 0x20}, // ONLRET
  {0x40, 0x40}, // OFILL
  {0x80, 0x80}, // OFDEL
};

// c_lflag — x86 System V ordering vs PowerPC BSD ordering. Only ECHO matches.
constexpr BitPair LFlagMap[] = {
  {0x00001, 0x00000080}, // ISIG
  {0x00002, 0x00000100}, // ICANON
  {0x00004, 0x00004000}, // XCASE
  {0x00008, 0x00000008}, // ECHO
  {0x00010, 0x00000002}, // ECHOE
  {0x00020, 0x00000004}, // ECHOK
  {0x00040, 0x00000010}, // ECHONL
  {0x00080, 0x80000000}, // NOFLSH
  {0x00100, 0x00400000}, // TOSTOP
  {0x00200, 0x00000040}, // ECHOCTL
  {0x00400, 0x00000020}, // ECHOPRT
  {0x00800, 0x00000001}, // ECHOKE
  {0x01000, 0x00800000}, // FLUSHO
  {0x04000, 0x20000000}, // PENDIN
  {0x08000, 0x00000400}, // IEXTEN
  {0x10000, 0x10000000}, // EXTPROC
};

// c_cflag structural bits. Baud lives in CBAUD/CIBAUD and is a *value*, not a
// bitmask, so it is handled separately below.
constexpr BitPair CFlagMap[] = {
  {0x00000040, 0x00000400}, // CSTOPB
  {0x00000080, 0x00000800}, // CREAD
  {0x00000100, 0x00001000}, // PARENB
  {0x00000200, 0x00002000}, // PARODD
  {0x00000400, 0x00004000}, // HUPCL
  {0x00000800, 0x00008000}, // CLOCAL
  {0x40000000, 0x40000000}, // CMSPAR
  {0x80000000, 0x80000000}, // CRTSCTS
};

// Every entry above is a single bit, so a plain test-and-set is correct here.
// The multi-bit fields (CSIZE, CBAUD, CIBAUD) are NOT in these tables -- a
// bit-pair map would silently drop CS6 and CS7, whose masks are proper subsets
// of CSIZE. They are shifted as fields below.
template<size_t N>
constexpr uint32_t MapBits(uint32_t Src, const BitPair (&Map)[N], bool GuestToHost) {
  uint32_t Dst = 0;
  for (const auto& P : Map) {
    const uint32_t From = GuestToHost ? P.Guest : P.Host;
    if (Src & From) {
      Dst |= GuestToHost ? P.Host : P.Guest;
    }
  }
  return Dst;
}

// CSIZE: bits 4-5 on x86, bits 8-9 on PowerPC. CS5/6/7/8 are values 0-3 in that
// field on both, so it moves as a unit.
constexpr uint32_t GuestCSIZE = 0x00000030, GuestCSIZEShift = 4;
constexpr uint32_t HostCSIZE = 0x00000300, HostCSIZEShift = 8;

constexpr uint32_t TranslateCSize(uint32_t Src, bool GuestToHost) {
  if (GuestToHost) {
    return ((Src & GuestCSIZE) >> GuestCSIZEShift) << HostCSIZEShift;
  }
  return ((Src & HostCSIZE) >> HostCSIZEShift) << GuestCSIZEShift;
}

// Baud is an enumerated index, not a bitfield, and the two architectures encode
// it differently above B38400. x86 has a 4-bit CBAUD plus a CBAUDEX escape bit,
// so B57600 is 0x1001 (escape | 1). PowerPC has a flat 8-bit CBAUD and no
// CBAUDEX, so the indices simply continue: B57600 is 16, B115200 is 17. Below
// B38400 both use the same 0..15, which is the only range a pty ever reports.
constexpr uint32_t GuestCBAUD = 0x0000100f, GuestCBAUDEX = 0x00001000;
constexpr uint32_t HostCBAUD = 0x000000ff;
constexpr uint32_t GuestCIBAUD = 0x100f0000, GuestCIBAUDEX = 0x10000000;
constexpr uint32_t HostCIBAUD = 0x00ff0000;

// Index <-> encoded form, for one baud field.
constexpr uint32_t BaudToIndex(uint32_t Encoded, bool GuestToHost) {
  if (GuestToHost) {
    // x86: escape bit means 16 + low nibble.
    return (Encoded & 0x1000) ? (16u + (Encoded & 0xfu)) : (Encoded & 0xfu);
  }
  return Encoded & 0xffu; // PowerPC: already a flat index.
}

constexpr uint32_t IndexToBaud(uint32_t Index, bool ToHost) {
  if (ToHost) {
    return Index & 0xffu;
  }
  return Index >= 16u ? (0x1000u | ((Index - 16u) & 0xfu)) : (Index & 0xfu);
}

constexpr uint32_t TranslateBaud(uint32_t Src, bool GuestToHost) {
  uint32_t Out = 0;
  if (GuestToHost) {
    Out |= IndexToBaud(BaudToIndex(Src & GuestCBAUD, true), true);
    const uint32_t In = (Src & GuestCIBAUD) >> 16;
    Out |= IndexToBaud(BaudToIndex(In, true), true) << 16;
  } else {
    Out |= IndexToBaud(BaudToIndex(Src & HostCBAUD, false), false);
    const uint32_t In = (Src & HostCIBAUD) >> 16;
    Out |= IndexToBaud(BaudToIndex(In, false), false) << 16;
  }
  return Out;
}

// c_cc index permutation. Only VINTR/VQUIT/VERASE/VKILL/VEOF share an index
// (0..4); every other V* macro sits in a different slot on the two arches, so
// a raw memcpy puts, e.g., VMIN's value at what x86 calls VTIME. GuestCCFromHost
// is indexed by x86's V* number and yields the corresponding PowerPC V* number.
constexpr uint8_t GuestCCFromHost[17] = {
  /* x86 VINTR    = 0  */ 0,  // PPC VINTR
  /* x86 VQUIT    = 1  */ 1,  // PPC VQUIT
  /* x86 VERASE   = 2  */ 2,  // PPC VERASE
  /* x86 VKILL    = 3  */ 3,  // PPC VKILL
  /* x86 VEOF     = 4  */ 4,  // PPC VEOF
  /* x86 VTIME    = 5  */ 7,  // PPC VTIME
  /* x86 VMIN     = 6  */ 5,  // PPC VMIN
  /* x86 VSWTC    = 7  */ 9,  // PPC VSWTC
  /* x86 VSTART   = 8  */ 13, // PPC VSTART
  /* x86 VSTOP    = 9  */ 14, // PPC VSTOP
  /* x86 VSUSP    = 10 */ 12, // PPC VSUSP
  /* x86 VEOL     = 11 */ 6,  // PPC VEOL
  /* x86 VREPRINT = 12 */ 11, // PPC VREPRINT
  /* x86 VDISCARD = 13 */ 16, // PPC VDISCARD
  /* x86 VWERASE  = 14 */ 10, // PPC VWERASE
  /* x86 VLNEXT   = 15 */ 15, // PPC VLNEXT
  /* x86 VEOL2    = 16 */ 8,  // PPC VEOL2
};

inline void HostToGuest(const struct termios& Host, GuestTermios& Guest) {
  Guest.c_iflag = MapBits(Host.c_iflag, IFlagMap, false);
  Guest.c_oflag = MapBits(Host.c_oflag, OFlagMap, false);
  Guest.c_lflag = MapBits(Host.c_lflag, LFlagMap, false);
  Guest.c_cflag = MapBits(Host.c_cflag, CFlagMap, false) | TranslateCSize(Host.c_cflag, false) | TranslateBaud(Host.c_cflag, false);
  Guest.c_line = Host.c_line;
  std::memset(Guest.c_cc, 0, sizeof(Guest.c_cc));
  for (size_t i = 0; i < 17; ++i) {
    Guest.c_cc[i] = Host.c_cc[GuestCCFromHost[i]];
  }
  // Slots 17,18 are padding on both — kernel doesn't populate them.
}

inline void GuestToHost(const GuestTermios& Guest, struct termios& Host) {
  std::memset(&Host, 0, sizeof(Host));
  Host.c_iflag = MapBits(Guest.c_iflag, IFlagMap, true);
  Host.c_oflag = MapBits(Guest.c_oflag, OFlagMap, true);
  Host.c_lflag = MapBits(Guest.c_lflag, LFlagMap, true);
  Host.c_cflag = MapBits(Guest.c_cflag, CFlagMap, true) | TranslateCSize(Guest.c_cflag, true) | TranslateBaud(Guest.c_cflag, true);
  Host.c_line = Guest.c_line;
  for (size_t i = 0; i < 17; ++i) {
    Host.c_cc[GuestCCFromHost[i]] = Guest.c_cc[i];
  }
}

} // namespace FEX::HLE::PPC64
