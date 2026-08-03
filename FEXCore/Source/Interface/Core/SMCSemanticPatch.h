// SPDX-License-Identifier: MIT
#pragma once

// ===========================================================================
// SMC Idea 4: semantic patch recognition   (FEX_SMCSEMANTICPATCH=1)
// ===========================================================================
//
// PROBLEM
// -------
// v3 (soft-invalidate + validate-relink, SMCSoftInvalidate.h) removes the
// recompile cost only when the guest bytes did NOT change.  The smcstorm
// `patchloop` scenario is 100% relink-MISS: the guest genuinely rewrites the
// rel32 of a `call`/`jmp` every iteration, so every cycle pays fault +
// invalidate + full recompile (~22us measured on POWER8, 41K iters/s).  No
// amount of hashing helps -- the code really is different.
//
// But the *difference* is trivial.  Runtime code generators (Mono's callsite
// backpatcher, .NET, CP2077's scripting VM) overwhelmingly patch one field:
// the rel32 target of a direct branch.  Everything else about the block is
// unchanged.  Recompiling the whole block to learn a new branch destination is
// four orders of magnitude more work than the change deserves.
//
// DESIGN
// ------
//  1. COMPILE TIME.  While the frontend decodes a block, record every direct
//     rel32 control-flow instruction it contains (call rel32 E8, jmp rel32 E9,
//     jcc rel32 0F 8x) as a BranchImmSite: the guest address range of the rel32
//     field and the guest address one past the instruction (from which the
//     target is `InstEnd + (int32_t)rel32`).  Separately, the PPC64LE backend
//     records every ExitFunction that materialises a compile-time-constant
//     destination RIP as an ExitRIPSite: the host address of the fixed-width
//     5-instruction LoadImm64Fixed sequence that bakes that RIP into the block.
//     Both tables live in GuestToHostMap::BlockEntry next to the v3 hash, are
//     capped at kMaxSitesPerBlock entries, and default to empty -- so a
//     code-cache-loaded block, a custom-IR block, or any block compiled with
//     the flag off is simply ineligible.
//
//  2. FAULT TIME.  On an SMC write fault the handler decodes the faulting host
//     store (DecodePPCStore) and, before any invalidation, asks whether the
//     guest write range lies ENTIRELY inside one recorded BranchImmSite of
//     every block that covers it.  If so, the new branch target is computed
//     from (current guest bytes overlaid with the store's value), the affected
//     blocks' baked host constants are patched, the store is performed via
//     pwrite(/proc/self/mem) exactly as SMCStoreEmulation v1 does, and the page
//     is LEFT WRITE-PROTECTED.  Nothing is invalidated, delinked or recompiled.
//     Each subsequent patch faults again but takes this path instead.
//
//  3. Anything unusual -- write crosses the field boundary, no recorded site,
//     block ineligible, ambiguous or missing host constant, non-atomically
//     patchable constant -- falls through to the existing soft-invalidate /
//     legacy path unchanged, with a reason tag in the FEX_SMC_AUDIT trace.
//
// WHICH TRANSLATED-EXIT CASE IS PPC64LE?  CASE (ii): BAKED CONSTANT.
// ------------------------------------------------------------------
// The design sketch offered two possibilities: (i) the exit jumps through a
// patchable link slot that a delinker can reset, or (ii) the exit embeds the
// destination guest RIP as a literal.  PPC64LE is unambiguously (ii), and it
// has no (i) at all:
//
//   * JIT/PPC64LE/BranchOps.cpp DEF_OP(ExitFunction) states it outright --
//     "NOT block linking. There is no backpatching, no jump thunk, no
//     ExitFunctionLinkData and no shadow stack here -- every exit still goes
//     through the L1 table."  It materialises the destination RIP into TMP1
//     (via InsertGuestRIPMove when the destination is an inline constant or an
//     entrypoint offset), probes the L1 lookup table inline, and bctr's.
//   * PPC64JITCore::ExitFunctionLink has signature (Frame, uint64_t GuestRIP)
//     -- it takes a RIP, not an ExitFunctionLinkData* Record.  It never calls
//     LookupCache::AddBlockLink; the only AddBlockLink callers in the tree are
//     in the arm64 backend (JIT/JIT.cpp).  GuestToHostMap::BlockLinks is
//     therefore permanently EMPTY on this port, and SeverBlockLinks() -- the
//     delinker path the design suggested reusing -- is a guaranteed no-op.
//
//   STALENESS WARNING (2026-08-03): the above was true until FEX_BLOCKLINKING
//   (f28ba8721, default-on since 01a21b4e6) added real constant-target jump
//   linking to this port.  A LINKED exit branches directly and never reloads
//   the patched window, which would make rel32 patches silently ineffective.
//   The interlock in PPC64JITCore (JIT.cpp, BlockLinkingEnabled) therefore
//   force-disables block linking whenever FEX_SMCSEMANTICPATCH (or
//   FEX_SMCLAZYINVAL, whose scrub needs every exit to re-probe) is enabled,
//   restoring the invariant this file's soundness argument rests on.  If a
//   linking-compatible semantic patch is ever wanted, the patch path must
//   also sever inbound links to the OLD destination (SeverBlockLinks is no
//   longer a no-op) and suppress re-linking of claimed exits.
//
// Consequences:
//   * "Sever the outbound direct link" is not merely insufficient here, it is
//     a nop.  Delinking alone would leave the block jumping to the OLD target
//     forever.  Patching the baked literal is mandatory, not optional.
//   * Conversely, once the literal is patched there is nothing else to do: the
//     block re-resolves the (new) RIP through the L1 table / dispatcher on
//     every execution, so a stale cached host pointer cannot survive.
//
// InsertGuestRIPMove emits LoadConstantFixed -> LoadImm64Fixed, which is always
// exactly five instructions (lis, ori, sldi, oris, ori) regardless of value --
// a fixed-width window that CodeCache::ApplyCodeRelocations already re-emits in
// place for RELOC_GUEST_RIP_MOVE.  We reuse that same fixed window.
//
// IDENTIFYING THE RIGHT LITERAL, AND THE INVARIANT THAT MAKES IT SOUND
// --------------------------------------------------------------------
// The backend cannot tell us which x86 instruction an ExitFunction came from
// (the PPC64LE emission loop tracks guest RIPs only per entry-point block --
// DebugData->GuestOpcodes -- not per IR op).  So the match is made on VALUE,
// under this invariant:
//
//     For every recorded ExitRIPSite, the RIP currently baked into its host
//     window equals the target computed from the CURRENT guest bytes of
//     whichever branch produced it.
//
// True at compile time by construction, and preserved by this code because a
// guest write to a rel32 field and the corresponding host repatch happen
// together, inside the fault handler, before the store retires.
//
// So at fault time we compute OldTarget from the un-modified guest bytes,
// synthesize the exact 5-word LoadImm64Fixed encoding for OldTarget, and look
// for the site whose five host words match it byte-for-byte.  That is a
// 20-byte exact match against a value derived from guest memory: it cannot
// collide with the block's other guest-RIP constants (a `call`'s pushed return
// address is InstEnd, not the target), and if it somehow matches twice we
// decline rather than guess.  Only ExitFunction sites are recorded, so a
// coincidentally-equal guest immediate elsewhere in the block is not a
// candidate at all.
//
// ATOMICITY / CROSS-MODIFYING HOST CODE
// -------------------------------------
// Another thread may be executing the block while we patch it.  A five-word
// sequence cannot be rewritten atomically, and a thread that fetched a mixed
// old/new pair would compute a garbage RIP and dispatch to it.  So the patch is
// accepted ONLY when OldTarget and NewTarget differ in exactly one of the five
// instruction words (or in none, in which case nothing is written).  A single
// naturally-aligned 4-byte store is single-copy-atomic on POWER, so every
// observer sees either the old word or the new word, never a mixture, and the
// resulting RIP is therefore either the old or the new target -- both of which
// are RIPs the guest itself published.  Multi-word deltas (target crossing a
// 64KiB boundary relative to the old one, or a change in the upper 32 bits) are
// declined and take the fallback path.  This is expected to be the common case
// for a patched callsite, whose targets cluster; it is measured by the
// `multiword` audit tag.
//
// SYNCHRONISATION PROTOCOL (copied, not invented)
// -----------------------------------------------
// After the store, the exact sequence the PPC64LE dispatcher already uses when
// it publishes freshly-emitted host code (JIT/PPC64LE/PPC64Dispatcher.cpp:941)
// is issued for the patched word's cache block:
//
//     dcbst 0,p ; sync ; icbi 0,p ; isync
//
// (which is also what __builtin___clear_cache lowers to on PPC64, i.e. what
// PPC64JITCore::CompileCode does for a whole block at JIT.cpp:2893).  POWER8
// has split, non-coherent I/D caches; dcbst pushes the store out of the
// D-cache, sync orders it before the icbi, icbi (a broadcast operation)
// invalidates the I-cache block on all processors, and isync flushes this
// thread's fetch pipeline.
//
// Residual, and unchanged from x86 semantics: a thread ALREADY executing the
// patched block does not itself execute an isync, so it may still fetch the old
// word and take the old target.  x86 says exactly the same thing --
// cross-modifying code without a serialising instruction on the executing
// processor is architecturally undefined -- and FEX's existing code-publication
// paths (block compile, code-cache relocation patching) have the identical
// property.  Nothing new is introduced here.
//
// SOUNDNESS NOTES
// ---------------
// (a) Guest visibility.  The guest bytes are updated by pwrite before the
//     handler returns, so any later decode/hash of that memory sees the new
//     value.  The block's stored v3 GuestHash is deliberately NOT refreshed: it
//     goes stale in the conservative direction, so a later soft-invalidation of
//     the page relink-MISSES and recompiles the block from the new bytes.  A
//     stale hash can never falsely match changed bytes.
//
// (b) Multiple code buffers.  A guest branch can be compiled into more than one
//     CodeBuffer (per-thread lookup caches).  The patch walks CodeBufferList,
//     exactly as InvalidateCodeBuffersCodeRange does, and is TWO-PHASE: every
//     affected block in every buffer must yield an unambiguous, single-word
//     patch, or nothing is written at all and the caller falls back.  There is
//     no partial state.
//
//     "Affected" means TRANSLATED THESE BYTES, not "claimed them": a block that
//     covers the written range but carries no metadata (code-cache-loaded, site
//     table overflowed) or decoded it at different instruction boundaries would
//     otherwise be left behind, stuck on the old value forever because the page
//     deliberately stays protected.  PlanSemanticPatch tests every non-claiming
//     block's guest extent (BlockTranslatedRange, the same JITCodeTail read
//     RangeOverlapsCompiledCode uses) and declines with `unclaimed-cover` if it
//     overlaps.  Conservative in the right direction: an unknown extent counts
//     as an overlap.
//
// AUDIT TAGS (FEX_SMC_AUDIT)
// --------------------------
// A serviced fault logs `SEMANTIC-PATCH kind=<rel32|movimm|mixed>`; a refusal
// logs `SEMPATCH-DECLINE reason=<tag>` and then takes the fallback path.  Tags:
//   flag-off, width, page-cross, no-claiming-block  -- gate refusals
//   no-exit-sites, no-matching-exit, ambiguous-exit, multiword   -- rel32 half
//   movimm-no-window, movimm-multi-window, movimm-duplicate-site,
//   movimm-stale-window, movimm-multiword                     -- mov-imm half
//   unclaimed-cover                                    -- note (b), both halves
//
// (c) Locking.  The patch runs from ThreadManager::SemanticPatchGuestCodeRange,
//     a byte-for-byte copy of the SoftInvalidateGuestCodeRange lock protocol
//     (ReleaseAllPendingSharedLocks -> ThreadCreationMutex -> steal-capable
//     exclusive CodeInvalidationMutex -> per-buffer LookupCache lock).  Holding
//     the exclusive CodeInvalidationMutex is what makes it safe to write into a
//     CodeBuffer from a signal handler: it excludes ClearCodeCache and every
//     concurrent compile.  No new lock and no new lock order is introduced.
//
// (d) Same-thread patch-then-execute, including patching the block you are
//     standing in.  The legacy handler covers that case by re-running the
//     faulting guest instruction as a single-instruction block
//     (IsAddressInCurrentBlock at the tail of HandleSegfault); the semantic
//     path returns before that and does not need it.  The destination RIP is
//     loaded out of host code at exit time, so a block that has already been
//     entered still exits to the new target, and the patching thread is the
//     executing thread -- it runs the isync itself.  DetectMonoBackpatcherBlock
//     is likewise skipped: it exists to spot a backpatcher through repeated
//     invalidations, and on this path there are none to spot.
//
// (e) Not handled, on purpose.  rel8 branches, indirect branches and rel16 are
//     out (the size check rejects them), as are mov-immediate forms with a
//     memory destination or a 16-bit immediate.
//
// MOV-IMMEDIATE PATCHING  (second recognised shape)
// -------------------------------------------------
// The rel32 recognizer is blind to the other thing runtime code generators
// patch constantly: the immediate of a `mov r32, imm32` / `mov r64, imm64`
// trampoline slot.  smcstorm's `patchloop` scenario is exactly that shape --
// `b8 <imm32> c3` invoked through `call *r13` -- and it reported 100%
// `no-claiming-block`, because such a block records NO metadata at all: it
// contains no rel32 branch (so BranchImmSites is empty) and its `ret` is an
// indirect exit (so ExitRIPSites is empty), and CompileBlock clears both tables
// unless both are non-empty.
//
// The rel32 half can locate its host patch site because the backend emits every
// constant destination RIP through InsertGuestRIPMove, a fixed-width 20-byte
// window, and records it.  A guest immediate has no such anchor: DEF_OP(Constant)
// emits a *variable-width* LoadConstant (1..5 instructions, value dependent), the
// IR emitter POOLS constants (IREmitter.h::Constant keeps a 32-entry pool, so one
// IR node can serve the guest mov AND an unrelated use of the same value), and
// the register allocator may rematerialise or delete it.  Matching a window to a
// guest immediate BY VALUE -- the trick the rel32 half uses for exits -- is
// therefore unsound here: patching a pooled constant would silently corrupt the
// unrelated user, which is exactly the class of bug this option must never have.
//
// So mov-immediates carry explicit provenance instead of being guessed at:
//
//   1. The frontend loop in ContextImpl::GenerateIR decodes each instruction
//      with DecodeMovImmSite below and records a MovImmSite (guest address and
//      width of the immediate field).  It hands the site's index (+1, so 0 means
//      "none") to the OpDispatcher for the duration of that one instruction.
//   2. OpDispatchBuilder::LoadSource_WithOpSize, when it is about to materialise
//      exactly that literal, emits an UNPOOLED `_Constant` tagged with the site
//      index (IROp_Constant::PatchSite).  Unpooled is load bearing: the node has
//      no other user by construction, so patching it cannot disturb anything but
//      the guest mov it came from.
//   3. PPC64JITCore::DEF_OP(Constant) sees a non-zero PatchSite and materialises
//      the value through LoadConstantFixed -- the same fixed 20-byte window the
//      RIP path uses -- recording {HostAddr, SiteIndex} in CodeData.MovImmWindows.
//      Cost is paid only with the flag on, and only for tagged constants.
//   4. At fault time the claim is resolved by INDEX, not by value: the site the
//      guest write lands in selects its window directly.  The window is then
//      verified to currently materialise the value the guest bytes still hold
//      (the same invariant the RIP path checks), and the same single-word,
//      single-copy-atomic publication rule applies -- a 5-word sequence cannot be
//      rewritten atomically under concurrent execution, so a new immediate that
//      differs in two or more of the five words is DECLINED (`movimm-multiword`)
//      rather than published in pieces.  In practice the low 16-bit half moves
//      and the rest stands, which is one word.
//
// Anything that breaks the 1:1 site<->window correspondence (a rematerialised or
// deleted constant, an immediate the dispatcher transformed before materialising
// it, a cache-loaded block) leaves zero or two windows for the site and declines.
//
// Accepted guest forms: B8+r (mov r32, imm32 / REX.W mov r64, imm64) and C7 /0
// with mod == 11 (mov r32, imm32, register destination).  A memory destination
// would need full ModRM/SIB/displacement decoding to find the immediate, and a
// 0x66 operand-size prefix makes the immediate 16-bit; both are refused.
//
// The overlap rule is the rel32 rule plus one widening: the guest store may lie
// wholly INSIDE the immediate field (partial patch, combined with the bytes
// already there), or it may COVER the field completely -- an 8-byte store over
// `b8 imm32 c3` is how a real patcher publishes atomically -- provided every byte
// it writes outside the field is byte-identical to what is already there.  A
// store that changes a byte outside the field is changing instructions, not
// immediates, and is not claimed at all.
//
// POWER8: no new codegen.  The one host instruction ever written is a copy of a
// word the emitter itself produced via LoadImm64Fixed.
// ===========================================================================

#include <FEXCore/fextl/vector.h>

#include <cstdint>
#include <cstring>

namespace FEXCore::SMC {

// Per-block cap on either metadata table. A block with more direct branches (or
// more constant exits) than this is simply not eligible for semantic patching;
// both tables are cleared and the block takes the fallback path. Chosen to
// cover any realistic runtime-codegen stub while bounding the fault-time scan.
constexpr size_t kMaxSitesPerBlock = 32;

// A rel32 field of a direct control-flow instruction inside a block's guest
// source bytes. Length is always 4 (rel8/rel16 are not recorded).
struct BranchImmSite {
  uint64_t ImmStart; // guest address of the first rel32 byte
  uint64_t InstEnd;  // guest address one past the whole instruction
};

// A guest RIP baked into the block's translated code by InsertGuestRIPMove at
// an ExitFunction. HostAddr points at the first of the five instruction words
// of the LoadImm64Fixed window.
struct ExitRIPSite {
  uint64_t HostAddr;
};

// The immediate field of a `mov reg, imm` inside a block's guest source bytes.
// ImmSize is 4 (imm32) or 8 (REX.W imm64).
struct MovImmSite {
  uint64_t ImmStart; // guest address of the first immediate byte
  uint32_t ImmSize;  // 4 or 8
};

// The host window a tagged guest immediate was materialised into. SiteIndex is
// the index into the block's MovImmSites of the guest immediate it came from --
// carried through the IR in IROp_Constant::PatchSite, so no value guessing is
// involved. HostAddr points at the first of the five instruction words of the
// LoadImm64Fixed window.
struct MovImmWindow {
  uint64_t HostAddr;
  uint32_t SiteIndex;
};

using BranchImmSites = fextl::vector<BranchImmSite>;
using ExitRIPSites = fextl::vector<ExitRIPSite>;
using MovImmSites = fextl::vector<MovImmSite>;
using MovImmWindows = fextl::vector<MovImmWindow>;

// Target of a rel32 branch given the field's little-endian bytes.
inline uint64_t Rel32Target(uint64_t InstEnd, uint32_t Rel32) {
  return InstEnd + static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(Rel32)));
}

/**
 * @brief Recognise a direct rel32 branch and locate its immediate field.
 *
 * Walks the legacy prefixes (and REX in 64-bit mode) at the front of the
 * instruction, then accepts exactly:
 *    E8 rel32      call
 *    E9 rel32      jmp
 *    0F 80..8F rel32   jcc
 * The decoded field must end exactly at the instruction's last byte; that check
 * is what rejects operand-size-prefixed rel16 forms, rel8 forms, and any case
 * where the prefix walk mis-identified the opcode byte.
 *
 * @param Bytes     the instruction's guest bytes
 * @param InstSize  its length as the frontend decoded it
 * @param InstAddr  its guest address
 * @param Is64Bit   guest mode (controls REX-prefix skipping)
 */
inline bool DecodeRel32BranchSite(const uint8_t* Bytes, size_t InstSize, uint64_t InstAddr, bool Is64Bit, BranchImmSite* Out) {
  if (InstSize < 5 || InstSize > 15) {
    return false;
  }

  size_t p = 0;
  while (p < InstSize) {
    const uint8_t B = Bytes[p];
    const bool IsLegacyPrefix = B == 0x26 || B == 0x2E || B == 0x36 || B == 0x3E || B == 0x64 || B == 0x65 || B == 0x66 || B == 0x67 ||
                                B == 0xF0 || B == 0xF2 || B == 0xF3;
    const bool IsREX = Is64Bit && (B & 0xF0) == 0x40;
    if (!IsLegacyPrefix && !IsREX) {
      break;
    }
    ++p;
  }

  size_t ImmOffset;
  if (p < InstSize && (Bytes[p] == 0xE8 || Bytes[p] == 0xE9)) {
    ImmOffset = p + 1;
  } else if (p + 1 < InstSize && Bytes[p] == 0x0F && (Bytes[p + 1] & 0xF0) == 0x80) {
    ImmOffset = p + 2;
  } else {
    return false;
  }

  if (ImmOffset + 4 != InstSize) {
    // rel8/rel16, or the prefix walk landed on the wrong byte. Either way this
    // is not a field we can reason about.
    return false;
  }

  Out->ImmStart = InstAddr + ImmOffset;
  Out->InstEnd = InstAddr + InstSize;
  return true;
}

/**
 * @brief Recognise a mov-immediate and locate its immediate field.
 *
 * Accepts exactly:
 *    B8+r imm32          mov r32, imm32
 *    REX.W B8+r imm64    mov r64, imm64
 *    C7 /0 imm32, mod==11    mov r32, imm32 (register destination)
 *
 * REX prefixes are skipped in 64-bit mode; ANY legacy prefix disqualifies the
 * instruction (0x66 would make the immediate 16-bit, and no runtime patcher
 * emits its patchable mov with a segment/lock/rep/address-size prefix -- there
 * is nothing to gain by decoding them and a mis-parse is unrecoverable). The
 * "immediate ends exactly at the last byte" check is what rejects a mis-parse.
 *
 * *Value receives the 64-bit constant the guest instruction materialises: the
 * little-endian immediate ZERO-extended, which is what x86 does for both
 * `mov r32, imm32` (writing r32 clears the upper half) and, trivially, for
 * `mov r64, imm64`. Callers must compute the post-store value the same way.
 *
 * @param Bytes     the instruction's guest bytes
 * @param InstSize  its length as the frontend decoded it
 * @param InstAddr  its guest address
 * @param Is64Bit   guest mode (controls REX-prefix skipping)
 */
inline bool DecodeMovImmSite(const uint8_t* Bytes, size_t InstSize, uint64_t InstAddr, bool Is64Bit, MovImmSite* Out, uint64_t* Value) {
  if (InstSize < 5 || InstSize > 15) {
    return false;
  }

  size_t p = 0;
  bool RexW = false;
  while (p < InstSize && Is64Bit && (Bytes[p] & 0xF0) == 0x40) {
    RexW = (Bytes[p] & 0x08) != 0;
    ++p;
  }

  size_t ImmOffset;
  size_t ImmSize;
  if (p < InstSize && (Bytes[p] & 0xF8) == 0xB8) {
    ImmOffset = p + 1;
    ImmSize = RexW ? 8 : 4;
  } else if (p + 1 < InstSize && Bytes[p] == 0xC7 && !RexW && (Bytes[p + 1] & 0xC0) == 0xC0 && (Bytes[p + 1] & 0x38) == 0) {
    // mod == 11 (register destination) and reg field == 0 (the /0 extension).
    // With mod != 11 there is a ModRM memory operand whose SIB/displacement
    // length would have to be decoded to find the immediate.
    ImmOffset = p + 2;
    ImmSize = 4;
  } else {
    return false;
  }

  if (ImmOffset + ImmSize != InstSize) {
    // A 16-bit immediate, a legacy prefix we refused to walk, or a mis-parse.
    return false;
  }

  uint64_t V = 0;
  ::memcpy(&V, Bytes + ImmOffset, ImmSize);

  Out->ImmStart = InstAddr + ImmOffset;
  Out->ImmSize = static_cast<uint32_t>(ImmSize);
  *Value = V;
  return true;
}

/**
 * @brief The 64-bit constant a mov-immediate site currently materialises.
 *
 * Reads the site's ImmSize guest bytes and zero-extends, matching
 * DecodeMovImmSite's *Value exactly. The caller must already have established
 * that those bytes are readable (they are: the site lies inside a live,
 * compiled, therefore mapped guest code page).
 */
inline uint64_t MovImmSiteValue(const MovImmSite& Site) {
  uint64_t V = 0;
  ::memcpy(&V, reinterpret_cast<const void*>(Site.ImmStart), Site.ImmSize);
  return V;
}

#ifdef ARCHITECTURE_ppc64le

// Number of words/bytes in the fixed-width guest-RIP materialisation window.
// Mirrors PPC64Emitter::Emitter::LoadConstantFixedBytes; the emitter header is
// deliberately NOT included here (it does `using namespace PPC64Emitter` inside
// FEXCore::CPU, which would leak r0..r31/v0..v31 into every translation unit
// that pulls in CPUBackend.h). PPC64JITCore::InsertGuestRIPMove asserts that
// the two encoders agree on every constant it ever emits, so drift is caught at
// compile time rather than at fault time.
constexpr size_t kRIPWindowWords = 5;
constexpr size_t kRIPWindowBytes = kRIPWindowWords * 4;

/**
 * @brief Reproduce the exact host words PPC64Emitter::LoadImm64Fixed emits.
 *
 * Hand-encoded copy of that sequence:
 *     lis  rt, hi>>16          addis rt, r0, imm16     (D-form,  op 15)
 *     ori  rt, rt, hi&0xFFFF                           (D-form,  op 24)
 *     sldi rt, rt, 32          rldicr rt, rt, 32, 31   (MD-form, op 30 xo 1)
 *     oris rt, rt, lo>>16                              (D-form,  op 25)
 *     ori  rt, rt, lo&0xFFFF                           (D-form,  op 24)
 */
inline void SynthesizeRIPWindow(uint32_t RegIdx, uint64_t RIP, uint32_t Words[kRIPWindowWords]) {
  const uint32_t Hi = static_cast<uint32_t>(RIP >> 32);
  const uint32_t Lo = static_cast<uint32_t>(RIP);
  const uint32_t rt = RegIdx & 31;

  const auto D = [](uint32_t Op, uint32_t RT, uint32_t RA, uint16_t Imm) {
    return (Op << 26) | (RT << 21) | (RA << 16) | Imm;
  };

  Words[0] = D(15, rt, 0, static_cast<uint16_t>(Hi >> 16));
  Words[1] = D(24, rt, rt, static_cast<uint16_t>(Hi & 0xFFFF));
  // MD-form: op(6) RS(5) RA(5) sh_low(5) me_low(6 incl. me_high at bit 5)
  //          xo(3 at bits 2-4) sh_high(1) Rc(1). sh = 32, me = 31.
  {
    constexpr uint32_t sh = 32, me = 31, xo = 1;
    Words[2] = (30u << 26) | (rt << 21) | (rt << 16) | ((sh & 0x1F) << 11) | ((me & 0x1F) << 6) | (((me >> 5) & 1) << 5) | (xo << 2) |
               (((sh >> 5) & 1) << 1);
  }
  Words[3] = D(25, rt, rt, static_cast<uint16_t>(Lo >> 16));
  Words[4] = D(24, rt, rt, static_cast<uint16_t>(Lo & 0xFFFF));
}

// The destination register index of a LoadImm64Fixed window, read out of its
// leading `lis rt, ...` (D-form, RT in bits 21-25).
inline uint32_t RIPWindowRegIdx(uint32_t Word0) {
  return (Word0 >> 21) & 31;
}

// One accepted host-code edit: a single naturally-aligned instruction word.
struct WordPatch {
  uint32_t* Address;
  uint32_t Value;
};

enum class SiteMatch {
  // The window does not currently materialise OldRIP: not this branch's exit.
  NoMatch,
  // Matches, and NewRIP is reachable by rewriting at most one word.
  Patchable,
  // Matches, but NewRIP would need two or more words rewritten: not atomically
  // publishable, so the whole patch attempt must be abandoned.
  MultiWord,
};

/**
 * @brief Test one fixed-width window against an old/new value pair.
 *
 * Value-generic: the RIP path passes branch targets, the mov-immediate path
 * passes guest immediates. In both cases the window must currently encode
 * OldRIP, or it is not the window we are looking for.
 *
 * On SiteMatch::Patchable, *Out is appended-to by the caller; NeedsWrite is
 * false when the two values encode identically (nothing to do).
 */
inline SiteMatch ClassifyRIPSite(uint64_t HostAddr, uint64_t OldRIP, uint64_t NewRIP, WordPatch* Out, bool* NeedsWrite) {
  auto* HostWords = reinterpret_cast<uint32_t*>(HostAddr);

  uint32_t Expected[kRIPWindowWords];
  SynthesizeRIPWindow(RIPWindowRegIdx(HostWords[0]), OldRIP, Expected);
  if (::memcmp(HostWords, Expected, kRIPWindowBytes) != 0) {
    return SiteMatch::NoMatch;
  }

  uint32_t Wanted[kRIPWindowWords];
  SynthesizeRIPWindow(RIPWindowRegIdx(HostWords[0]), NewRIP, Wanted);

  size_t DiffIndex = kRIPWindowWords;
  size_t DiffCount = 0;
  for (size_t i = 0; i < kRIPWindowWords; ++i) {
    if (Expected[i] != Wanted[i]) {
      DiffIndex = i;
      ++DiffCount;
    }
  }

  if (DiffCount == 0) {
    *NeedsWrite = false;
    return SiteMatch::Patchable;
  }
  if (DiffCount > 1) {
    return SiteMatch::MultiWord;
  }

  *NeedsWrite = true;
  Out->Address = &HostWords[DiffIndex];
  Out->Value = Wanted[DiffIndex];
  return SiteMatch::Patchable;
}

/**
 * @brief Publish one patched host instruction word.
 *
 * Single-copy-atomic 4-byte store, then the tree's existing code-publication
 * sequence for the containing cache block (PPC64Dispatcher.cpp:941).
 */
inline void ApplyWordPatch(const WordPatch& Patch) {
  __atomic_store_n(Patch.Address, Patch.Value, __ATOMIC_RELAXED);
  asm volatile("dcbst 0,%0; sync; icbi 0,%0; isync" ::"r"(Patch.Address) : "memory");
}

#endif // ARCHITECTURE_ppc64le

} // namespace FEXCore::SMC
