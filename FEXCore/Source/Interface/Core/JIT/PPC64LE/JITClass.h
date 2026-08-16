// SPDX-License-Identifier: MIT
// PPC64LE JIT backend class definition.
// Analogous to FEXCore/Source/Interface/Core/JIT/JITClass.h
#pragma once

#include "Interface/Core/ArchHelpers/PPC64Emitter.h"
#include <FEXCore/Utils/ArchHelpers/PPC64.h>
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/JIT/Relocations.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IntrusiveIRList.h"
#include "Interface/IR/RegisterAllocationData.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/fextl/list.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/Utils/LongJump.h>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <utility>
#include <variant>

namespace FEXCore::Core  { struct InternalThreadState; }
namespace FEXCore::Context { struct ExitFunctionLinkData; }
namespace FEXCore::IR { class RegisterAllocationPass; }

namespace FEXCore::CPU {

// RDRAND fallback (POWER8 has no `darn`); defined in JIT.cpp.
extern "C" uint64_t PPC64_RDRAND();

// Indices into the ppc64le helper-address table pointed at by
// CpuStateFrame::PPC64_HelperTable. Each entry holds the absolute host
// address of one JIT-callable C helper. The table itself is a static
// namespace-scope array in JIT.cpp; the pointer to it is written to
// CpuStateFrame in PPC64JITCore's constructor. Adding a new helper here
// requires (a) a new PPC64_HELPER_* enumerator, (b) an initializer in the
// same file's PPC64Helpers array, and (c) an emitter site that loads via
// `ld TMP1, PPC64_HelperTable_off(STATE); ld TMP1, IDX*8(TMP1)`.
// Enumerator order defines the offset — do not reorder without rebuilding
// every code cache (P3.2/P3.3 will make this a hard cache invariant; today
// no cache is live). Kept as scoped constants (not `enum class`) so the
// arithmetic reads naturally at emit sites: `IDX * 8`.
enum PPC64HelperIndex : uint32_t {
  PPC64_HELPER_SplitLockEmulate = 0,
  PPC64_HELPER_F16HiToF32x4,
  PPC64_HELPER_F32x4ToF16Hi,
  PPC64_HELPER_F64Sin,
  PPC64_HELPER_F64Cos,
  PPC64_HELPER_F64Tan,
  PPC64_HELPER_F64Atan,
  PPC64_HELPER_F64FYL2X,
  PPC64_HELPER_F64Scale,
  // No F64F2XM1 entry HERE — it was appended later (S3.7-C5, below) to keep
  // table offsets stable. The still-true half of the old note: it MUST NOT
  // reuse the upstream Pointers.F64F2XM1Handler slot — F64F2XM1Impl diverges
  // from it (expm1(x*ln2) vs exp2(src)-1.0, off by >1 ULP on 44.6% of
  // inputs); reusing that Pointers slot re-breaks D9_F0_02_F64.
  PPC64_HELPER_VAESImc,
  PPC64_HELPER_VAESKeyGenAssist,
  PPC64_HELPER_VAESEnc,
  PPC64_HELPER_VAESEncLast,
  PPC64_HELPER_VAESDec,
  PPC64_HELPER_VAESDecLast,
  PPC64_HELPER_VSha1H,
  PPC64_HELPER_VSha1C,
  PPC64_HELPER_VSha1M,
  PPC64_HELPER_VSha1P,
  PPC64_HELPER_VSha1SU1,
  PPC64_HELPER_VSha256H,
  PPC64_HELPER_VSha256H2,
  PPC64_HELPER_VSha256U0,
  PPC64_HELPER_VSha256U1,
  PPC64_HELPER_PCLMUL,
  PPC64_HELPER_RDRAND,
  PPC64_HELPER_CRC32,
  PPC64_HELPER_VPCMPESTRX,
  PPC64_HELPER_VPCMPISTRX,
  // S3.7-C5: appended AFTER existing entries so table offsets don't shift
  // (any code cached against the old table layout would misresolve helpers
  // if this reordered). MUST NOT reuse Pointers.F64F2XM1Handler — see the
  // note above about D9_F0_02_F64 divergence. Distinct implementation
  // (F64F2XM1Impl in VectorOps.cpp) with different semantics from
  // F64F2XM1Handler; the helper table entry points at the local impl.
  PPC64_HELPER_F64F2XM1,
  // Appended (same S3.7-C5 rule): the F16C f16x4<->f32x4 paths previously
  // bctrl'd through a bare LoadConstant of the host function address — the
  // exact serialized-block stale-pointer hazard the F64F2XM1 entry above was
  // added to fix. Table-resolved now.
  PPC64_HELPER_F16x4ToF32x4,
  PPC64_HELPER_F32x4ToF16x4,
  PPC64_HELPER_MAX,
};

// Returns the process-lifetime helper-address table. Written into
// CpuStateFrame::PPC64_HelperTable at PPC64JITCore construction. Defined in
// VectorOps.cpp because most helpers only have file-scope visibility there.
uint64_t* GetPPC64HelperTable();

// Byte size of one PPC64HelperTable slot (a raw uint64_t function address).
static constexpr int16_t PPC64HelperSlotSize = 8;

// -------------------------------------------------------------------------
// 128-bit constant pool
// -------------------------------------------------------------------------
// Several vector lowerings need a 16-byte constant that vspltis* cannot
// build. Each such site used to materialise it inline: LoadConstant (up to
// five instructions for a full 64-bit immediate), two stds to the red zone,
// an addi, and an lvx reading back what those stds had just written -- a
// store-hit-load on POWER8, per constant, per emission. A pooled load is
// three instructions and touches no store queue.
//
// The pool shares one allocation with the helper-address table so that the
// existing CpuStateFrame::PPC64_HelperTable pointer reaches both and no new
// CpuStateFrame field is needed. Helpers is first (so the published pointer
// is unchanged and still points at helper slot 0) and Constants is forced to
// a 16-byte boundary within a 16-byte-aligned object, which is what lvx
// requires -- it truncates the low four bits of the effective address, so a
// misaligned pool would silently read the wrong 16 bytes.
//
// Entries are stored exactly as the inline sequences wrote them: element
// [2*i] is the doubleword that went to the *low* address (r1-16) and [2*i+1]
// the one that went to r1-8, so a pooled lvx reproduces the old register
// image byte for byte with no endianness reasoning required.
//
// Enumerator order defines the offset, same caveat as the helper table.
enum PPC64VConstIndex : uint32_t {
  PPC64_VCONST_F32_2P31 = 0,   // splat f32(2^31)   -- f32->i32 overflow bound
  PPC64_VCONST_I32_MIN,        // splat i32 INT_MIN -- x86 integer-indefinite
  PPC64_VCONST_F64_2P63,       // splat f64(2^63)   -- f64->i64 overflow bound
  PPC64_VCONST_I64_MIN,        // splat i64 INT64_MIN
  PPC64_VCONST_PACK_DW_LO_I32, // vperm control: pack each dw's low i32 to LE-low
  PPC64_VCONST_LANE0_MASK_F32, // {~0u,0,0,0} in guest byte order: selects LE elem0 for xxsel
  PPC64_VCONST_F64_2P31,       // splat f64(2^31)   -- f64->i32 overflow bound (CVTPD2DQ)
  // CRC-32C via vpmsumd Barrett reduction (DEF_OP(CRC32), ALUOps.cpp). Both
  // live in dw0 with dw1 zero so vpmsumd's unused doubleword product
  // vanishes. Derived and verified symbolically (200k random vectors per
  // SrcSize against a bitwise reference) in unittests/GuestCrypto/crc32_derive.py:
  //   CRC32C_MU = reflect64(floor(x^96 / P) - x^64), P = 0x11EDC6F41
  //   CRC32C_P  = reflect33(P)
  PPC64_VCONST_CRC32C_MU,
  PPC64_VCONST_CRC32C_P,
  // VAddP (phaddw/phaddd/phaddb-class) vperm controls: even/odd element
  // selectors over [VL:VU], per element size, for the 128-bit and MMX (64-bit
  // RegSize) layouts. Values copied verbatim from the old inline builds in
  // DEF_OP(VAddP) — entry [+0] is what went to r1-16, [+1] to r1-8.
  PPC64_VCONST_ADDP_EVEN_B,  PPC64_VCONST_ADDP_ODD_B,
  PPC64_VCONST_ADDP_EVEN_H,  PPC64_VCONST_ADDP_ODD_H,
  PPC64_VCONST_ADDP_EVEN_W,  PPC64_VCONST_ADDP_ODD_W,
  PPC64_VCONST_ADDP_EVEN_B64, PPC64_VCONST_ADDP_ODD_B64,
  PPC64_VCONST_ADDP_EVEN_H64, PPC64_VCONST_ADDP_ODD_H64,
  PPC64_VCONST_ADDP_EVEN_W64, PPC64_VCONST_ADDP_ODD_W64,
  // VUMulH/VSMulH i16: vperm control interleaving the high halfwords of the
  // vmulo/vmule pair back into element order. Shared by both signednesses.
  PPC64_VCONST_MULH_HI_I16,
  // Splat f64(1.0) — numerator for VFRecp/VFRSqrt i64 xvdivdp paths.
  PPC64_VCONST_F64_ONE,
  PPC64_VCONST_MAX,
};

struct alignas(16) PPC64RuntimeTables {
  uint64_t Helpers[PPC64_HELPER_MAX];
  alignas(16) uint64_t Constants[2 * PPC64_VCONST_MAX];
};

// Byte offset of the constant pool from the published helper-table pointer.
static constexpr int16_t PPC64VConstPoolOffset = offsetof(PPC64RuntimeTables, Constants);
static constexpr int16_t PPC64VConstSlotSize = 16;
static_assert(PPC64VConstPoolOffset % 16 == 0, "lvx truncates the low 4 EA bits; pool must be 16-byte aligned");
static_assert(PPC64VConstPoolOffset + PPC64VConstSlotSize * (PPC64_VCONST_MAX - 1) <= INT16_MAX,
              "constant pool displacement must fit li's signed 16-bit immediate");

// -------------------------------------------------------------------------
// Block linking (constant-target JUMP exits only)
// -------------------------------------------------------------------------
// Data record emitted directly after each per-exit jump thunk in the code
// buffer. Layout contract shared by four sites, all in this backend:
//   - CompileCode's thunk emission (JIT.cpp) writes it via dc64,
//   - the thunk's linked-out-of-range leg loads HostCode from it,
//   - ExitFunctionLinkWithRecord (JIT.cpp) reads GuestRIP / writes HostCode
//     and computes the in-block patch site from CallerOffset,
//   - the delinkers (JIT.cpp) restore the stashed original words.
// The first three fields deliberately mirror Context::ExitFunctionLinkData
// (HostCode / GuestRIP / CallerOffset); the pointer registered with
// GuestToHostMap::AddBlockLink is a cast of this record. The two Orig*Word
// fields stash the exact pre-link instruction words so delinking is a
// byte-identical restore rather than a re-computation.
struct PPC64BlockLinkRecord {
  uint64_t HostCode;       // written by the linker BEFORE the thunk-word patch
  uint64_t GuestRIP;       // constant destination RIP of this exit
  int64_t CallerOffset;    // in-block patch site address minus &record (negative)
  uint32_t OrigCallerWord; // pre-link first word of the in-block L1 probe
  uint32_t OrigThunkWord;  // pre-link first word of the thunk (b LinkPath)
  // Cached dispatcher-stub address. The thunk's LinkPath leg loads this via a
  // single d-form ld off &record instead of ld off Pointers.<...>(STATE),
  // which keeps CpuStateFrame at its 2-page budget. Written once at thunk
  // emission from CTX->Dispatcher->GetExitFunctionLinkerWithRecordAddress()
  // (constant over the process lifetime after dispatcher generation).
  uint64_t StubAddr;
};
static_assert(sizeof(PPC64BlockLinkRecord) == 40, "emitted-record layout contract");
static_assert(offsetof(PPC64BlockLinkRecord, StubAddr) == 32, "thunk stub-addr load contract");
static_assert(offsetof(PPC64BlockLinkRecord, HostCode) == 0, "thunk ld displacement contract");

// Byte distance from a jump thunk's first instruction (the thunk-side patch
// site) to its PPC64BlockLinkRecord. Must match CompileCode's thunk emission
// exactly; the emission site has a Release-visible check.
static constexpr uint64_t PPC64LinkRecordFromThunkStart = 0x30;

class PPC64JITCore final : public CPUBackend, public PPC64EmitterBase {
public:
  explicit PPC64JITCore(FEXCore::Context::ContextImpl* ctx,
                        FEXCore::Core::InternalThreadState* Thread);
  ~PPC64JITCore() override;

  [[nodiscard]]
  CPUBackend::CompiledCode CompileCode(uint64_t Entry, uint64_t Size, bool SingleInst,
                                       const FEXCore::IR::IRListView* IR,
                                       FEXCore::Core::DebugData* DebugData,
                                       bool CheckTF) override;

  void ClearCache() override;

  void ClearRelocations() override { Relocations.clear(); }

  static uint64_t ExitFunctionLink(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP);

  // Block-linking variant, reached only from a link thunk's LinkPath leg via
  // the dispatcher's ExitFunctionLinkerWithRecord stub. Looks up or compiles
  // Record->GuestRIP, then — re-validated under the LookupCache WRITE lock —
  // registers the link and backpatches either the in-block patch site
  // (in ±32MiB `b` range) or the thunk (out of range). Returns the host code
  // address to dispatch to (0 if the block cannot be compiled).
  static uint64_t ExitFunctionLinkWithRecord(FEXCore::Core::CpuStateFrame* Frame,
                                             FEXCore::Context::ExitFunctionLinkData* Record);

  fextl::vector<FEXCore::CPU::Relocation> TakeRelocations(uint64_t GuestBaseAddress) override {
    // S3.7-C4: rebase RELOC_GUEST_RIP_* against the caller-supplied guest
    // base. On-disk format stores GuestRIP.GuestRIP as a delta from that
    // base, and ApplyCodeRelocations reconstructs the absolute value via
    // `GuestEntry + delta` on load. Mirror of ARM64
    // Arm64Relocations.cpp:105-119 including its non-idempotency — call at
    // most once per compile.
    for (auto& Reloc : Relocations) {
      switch (Reloc.Header.Type) {
      case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE:
      case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL:
        Reloc.GuestRIP.GuestRIP -= GuestBaseAddress;
        break;
      default:
        break;
      }
    }
    return std::move(Relocations);
  }

private:
  FEXCore::Context::ContextImpl*     CTX {};
  const FEXCore::IR::IRListView*     IR {};
  uint64_t                           Entry {};
  CPUBackend::CompiledCode           CodeData {};

  // SMC Idea 4: sticky "this block had more constant exits than
  // kMaxSitesPerBlock", so a later exit can't repopulate the cleared table.
  // Reset with CodeData at the top of CompileCode.
  bool                               ExitRIPSitesOverflowed {};

  // Same, for the mov-immediate window table.
  bool                               MovImmWindowsOverflowed {};

  // Per-block jump targets
  fextl::vector<PPC64Emitter::Label> JumpTargets;

  PPC64Emitter::Label* JumpTarget(IR::Ref Node) {
    auto Block = IR->GetOp<IR::IROp_CodeBlock>(Node);
    return &JumpTargets[Block->ID];
  }

  PPC64Emitter::Label* JumpTarget(IR::OrderedNodeWrapper Node) {
    auto Block = IR->GetOp<IR::IROp_CodeBlock>(Node);
    return &JumpTargets[Block->ID];
  }

  // -------------------------------------------------------------------------
  // Spin-loop SMT priority hints (FEX_DISABLESPINLOOPHINT kill switch).
  // AnalyzeSpinLoops (JIT.cpp) fills these per compile; DEF_OP(CondJump)/
  // DEF_OP(Jump) consult them per emitted edge via EmitSpinEdgeHint.
  // Edges are keyed (from CodeBlock ID << 32) | to CodeBlock ID. Plain
  // vectors + linear scan: a compile unit rarely carries more than one spin
  // loop, so these hold a handful of entries at most.
  // -------------------------------------------------------------------------
  bool SpinLoopHintEnabled {};
  fextl::vector<uint64_t> SpinBackedges;     // edges that re-enter a spin loop
  fextl::vector<uint64_t> SpinRestoreEdges;  // edges that leave a spin loop
  uint32_t CurrentBlockID {UINT32_MAX};      // IROp_CodeBlock::ID being emitted

  // Fallthrough elision (FEX_NOFALLTHROUGH kill switch): the CodeBlock ID of
  // the block emitted immediately after the current one, or UINT32_MAX when
  // there is none or falling into it would be unsound. DEF_OP(Jump)/
  // DEF_OP(CondJump) skip their trailing `b` when the edge targets this
  // block. CompileCode's block loop maintains it, and only ever sets it for a
  // non-EntryPoint successor: EntryPoint blocks emit an out-of-band prologue
  // (InlineJITBlockHeader store, suspend poke, spill-frame stdu) BEFORE their
  // intra-unit JumpTarget label binds, and intra-unit edges must land after
  // that prologue — falling into it would run the stdu on an already-live
  // frame. A fallthrough target is by construction forward/unbound, so the
  // backward-edge suspend poke in the jump handlers is never skipped by this.
  uint32_t FallthroughBlockID {UINT32_MAX};

  // -------------------------------------------------------------------------
  // 32-bit tail-mask elision (FEX_ZEXTOPT=0 kill switch).
  //
  // Every i32 GPR ALU handler canonicalizes its result with
  // rldicl(Dst,Dst,0,32) so that any observer — SRA writeback via a coalesced
  // StoreRegister, spill slots, signal-frame state reconstruction — sees the
  // guest's zero-extended 32-bit value. The LZMA-loop audit (2026-08-13)
  // measured those masks at 15% of emitted instructions, many provably dead.
  //
  // Elide32MaskSet[def ID] means the def's tail mask may be skipped. The
  // prepass (Compute32MaskElision) sets it only under ALL of:
  //   1. the def has exactly one IR use (OrderedNode::GetUses() == 1),
  //   2. that use is the IMMEDIATELY NEXT op in the same block (so the
  //      unmasked value cannot reach a spill, a block boundary, or an
  //      SRA-coalesced StoreRegister — the value dies at the next op), and
  //   3. the consumer's emitted encoding reads only the low 32 bits of that
  //      operand position, as a static ISA fact (word compares, word shifts,
  //      mullw/mulli-mod-2^32, narrow stores). See the table in
  //      Compute32MaskElision for the per-op verification notes.
  // Rule 2 is what keeps signal observation sound: a synchronous fault in a
  // LATER guest instruction can never observe this def as architectural
  // state, because the def is dead before any later instruction begins.
  // Spill/Fill are IR ops, so an RA-inserted spill between def and use breaks
  // the "immediately next" test and conservatively keeps the mask.
  // -------------------------------------------------------------------------
  fextl::vector<bool> Elide32MaskSet;
  void Compute32MaskElision();

  // -------------------------------------------------------------------------
  // Producer-side half of the same elision (same FEX_ZEXTOPT=0 kill switch;
  // deliberately NOT a second knob, so the two mechanisms can only be A/B'd
  // together and FEX_ZEXTOPT's existing CodeCache config hash — CodeCache.cpp,
  // the "Backend env toggles that change emitted block bytes" block — keeps
  // covering both without a new hash entry).
  //
  // Compute32MaskElision proves the mask dead by proving NOBODY LOOKS at the
  // high half. ComputeHighZeroElision proves it dead by proving the high half
  // IS ALREADY ZERO, so the rldicl would write back the bits it read. That is
  // a strictly stronger claim and it is what makes this half compose with
  // everything: the elided op's architectural result is bit-identical, so
  // multi-use values, values that cross a block boundary, values that reach a
  // spill slot, and defs coalesced onto an SRA (guest-architectural) register
  // are all in scope — none of the observability reasoning that constrains the
  // consumer side applies. A synchronous fault in any later guest instruction
  // observing an SRA def sees exactly the value it would have seen with the
  // mask emitted.
  //
  // The two results are OR'd into the same Elide32MaskSet. Compute32MaskElision
  // runs FIRST and is not restructured: its set is this pass's input, never its
  // output, so its soundness argument stays independently reviewable. The one
  // coupling runs the other way and is load-bearing — a def the CONSUMER pass
  // elided is NOT high-zero afterwards (that is the whole point of that pass),
  // so this pass must read Elide32MaskSet before adding to it and must never
  // treat a consumer-elided def as a zero source. See the source table and the
  // per-instruction ISA citations at ComputeHighZeroElision in JIT.cpp.
  //
  // Lattice: one bit per HOST GPR ("bits 63:32 of this register are zero"),
  // not per SSA node. Post-RA the operand wrappers are immediate-encoded
  // PhysicalRegisters and node identity is gone (see GetReg(OrderedNodeWrapper)
  // and the matching note in Compute32MaskElision), so the register file IS the
  // only addressable dataflow space. Host register indices are exact and
  // collision-free here because the SRA and RA pools are disjoint fixed
  // assignments (ArchHelpers/PPC64Emitter.h x64::SRA/RA, x32::SRA/RA) and
  // TMP1-TMP4 / r0 / r1 / STATE belong to neither.
  // -------------------------------------------------------------------------
  void ComputeHighZeroElision();

  // Tail-mask emission for i32 GPR results: rldicl unless provably dead.
  void Mask32Tail(PPC64Emitter::GPR Dst, IR::Ref Node) {
    const auto ID = IR->GetID(Node).Value;
    if (ID < Elide32MaskSet.size() && Elide32MaskSet[ID]) {
      return;
    }
    rldicl(Dst, Dst, 0, 32);
  }

  // -------------------------------------------------------------------------
  // TSO load->store adjacent-barrier elision (FEX_TSOPAIRELIDE=0 kill switch).
  //
  // DEF_OP(LoadMemTSO) ends with a trailing lwsync (acquire) and
  // DEF_OP(StoreMemTSO) begins with a leading lwsync (release). When the two
  // ops are adjacent up to non-memory register ops, the two barriers are
  // architecturally one: lwsync orders {Load->Load, Load->Store, Store->Store}
  // across itself, which is exactly TSO's requirement set (x86 permits
  // Store->Load reordering, so that direction never needs a barrier). The
  // store's leading lwsync is therefore redundant iff an lwsync has been
  // emitted since the LAST memory-access host instruction of any kind.
  //
  // TSOPairElideSet[store node ID] means DEF_OP(StoreMemTSO) may skip its
  // leading lwsync. The prepass (ComputeTSOPairElision) walks each block in
  // emission order and sets it only when every IR op between the LoadMemTSO
  // and the StoreMemTSO is on an explicit whitelist of ops whose DEF_OP
  // provably emits ZERO memory-access host instructions (see the per-op
  // verification table in ComputeTSOPairElision). A too-small whitelist only
  // costs missed elisions, never soundness. The full soundness argument lives
  // at the elision site in DEF_OP(StoreMemTSO).
  // -------------------------------------------------------------------------
  fextl::vector<bool> TSOPairElideSet;
  void ComputeTSOPairElision();

  bool TSOStoreLeadingBarrierElided(IR::Ref Node) {
    const auto ID = IR->GetID(Node).Value;
    return ID < TSOPairElideSet.size() && TSOPairElideSet[ID];
  }

  static constexpr uint64_t SpinEdgeKey(uint32_t From, uint32_t To) {
    return (static_cast<uint64_t>(From) << 32) | To;
  }

  void AnalyzeSpinLoops();

  // FEX_SPINHINT_ANYLOOP=1: drop the stationary-poll requirement on the SMT
  // priority hint, restoring the pre-fix behaviour where any load-carrying
  // backedge was hinted. Bisect switch only — the default is the gated form.
  bool SpinHintAnyLoop {};

  // -------------------------------------------------------------------------
  // FEX_SPINCOLLAPSE=1 (opt-in): batched budget decrement for counted
  // spin-poll loops — the RED4 redDispatcher shape (guest RIP 0x37fff37530a0
  // measured at 43% of process CPU driving / up to 50% of flythrough samples
  // under FEX_HWTSO; see notes/openworld-perf-review + the spin anatomy notes).
  //
  // Shape (post-pass IR, verified against a live dump of `dec ecx; jnz`):
  // CompareBranchFusion has already rewritten the flag-consuming jnz into a
  // VALUE compare, so no flags are consumed anywhere in the pattern:
  //   poll block:     LoadMemTSO work; SubWithFlags(work,0); CondJump(work,#0,
  //                   NEQ) -> found-exit
  //   backedge block: %new = Sub(%old, #1); Copy(%old); StoreRegister(%new);
  //                   CondJump(%old, #1, NEQ) -> backedge (else budget-exit)
  //
  // Two spellings of that backedge block occur, and BOTH must be admitted —
  // the second is CP2077's own worker loop, which the first-generation matcher
  // walked past for two sessions (live reject trace 2026-08-15):
  //   write-back: an explicit StoreRegister(%new), OR — when the budget is
  //               SRA-resident — an in-place update, Sub dest PR == src PR
  //               (`addi r8,r8,-1`), which emits no store at all.
  //   staging:    Copy(%old) for a 64-bit budget, or Bfe(#32,#0, %old) for a
  //               32-bit one (`mov eax,ecx` zero-extends). A Bfe-staged
  //               compare is admitted only against an i32 decrement.
  // Because the staged value may be zero-extended, the batched compare must
  // follow CompareSize (cmpwi/cmplwi at i32) — a 64-bit signed compare would
  // read a negative budget as huge and spin forever. See BranchOps.
  //
  // Rewrite (emission-time, nodes marked by the matcher in AnalyzeSpinLoops):
  //   Sub:      new = (old >u K) ? old - K : 0        (cmpldi cr7 + isel)
  //   CondJump: backedge taken iff old >u K           (cmpldi cr7 + bc GT)
  // Exit state is exact: the loop still leaves the budget register at 0 on
  // the budget-exhausted exit, and the found-exit still leaves via the poll
  // compare. Each iteration retires K budget instead of 1, cutting spin WALL
  // time ~K× so worker threads PARK sooner (park is cheap under ntsync).
  //
  // Legality: coarsened polling is indistinguishable from scheduling delay
  // under TSO. No flags are consumed (fusion shape, see above). KNOWN
  // semantic coarsening, why this ships opt-in/per-app: on the FOUND exit the
  // budget register holds a K-granular value instead of the exact iteration
  // count (engines reload the budget per episode; code that consumed the
  // leftover count would misbehave). Both emissions derive only from their
  // own operands — no state is carried between op handlers (the AES
  // mask-cache rule).
  // -------------------------------------------------------------------------
  // NOW A CONFIG OPTION, not a bare getenv (2026-08-15). SpinCollapse is
  // reachable from AppConfig, which is the only per-title mechanism this port
  // has — without that the largest measured win on the port could not be
  // persisted for the title it was measured on. FEX_SPINCOLLAPSE still works
  // unchanged; the option name generates that exact environment spelling.
  // 0 = off, 1 = on at kSpinCollapseKDefault, 2..1024 = on at that K.
  // -------------------------------------------------------------------------
  // K corrects the EMULATION INFLATION of a spin iteration, it does not
  // minimize spinning: the engine tuned its budget for native iteration
  // cost, and measurement shows the budget is load-bearing (CP2077
  // flythrough, K=32 under HWTSO: threads parked in ~1-2us and paid a wake
  // round trip per task batch — fps fell BELOW plain HWTSO). Emulated
  // iterations run ~6x native with TSO barriers, ~2-3x under FEX_HWTSO, so
  // K in that range restores the intended spin duration. FEX_SPINCOLLAPSE=1
  // uses the default; FEX_SPINCOLLAPSE=<2..1024> overrides K for tuning.
  // 2026-08-15 in-game sweep (CP2077, driving, HWTSO=1, collapse firing on the
  // real worker loop for the first time) — worker-loop share of process
  // samples, and the player's read of frame pacing:
  //   SMT4: K=8 22.8%   K=32 5.2% "good move"   K=64 1.7% "okay-ish"
  //   SMT2: K=16 7-10% "okay"  K=32 4.7-6.5% BEST  K=64 2.0-2.8% pacing WORSE
  // ★ Spin share falls monotonically with K, so it is the WRONG objective:
  // too-large K exhausts the budget early, workers PARK, and the wake
  // round-trip costs frame pacing in a way no block profile shows. K=32 was
  // preferred at BOTH SMT levels, i.e. the optimum did not track available
  // hardware threads — one constant looks defensible so far.
  // ☞ Every verdict above is subjective (no MangoHud CSV was captured); p99
  // frametime legs are owed before this default is trusted beyond opt-in use.
  static constexpr uint16_t kSpinCollapseKDefault = 32;
  uint16_t kSpinCollapseK = kSpinCollapseKDefault;
  bool SpinCollapseEnabled {};
  fextl::vector<bool> SpinCollapseSubs;
  fextl::vector<bool> SpinCollapseBranches;
  // Backedges matched from the SGT-0 idiom (`test old,old; jg`) rather than
  // NEQ-1 (`dec; jne`). Their batched compare must be SIGNED: a negative
  // value must exit the loop as the original SGT would, where the unsigned
  // `old >u K` reads it as huge and would spin forever (the NEQ shape only
  // ever coarsens — its worst case is exiting early).
  fextl::vector<bool> SpinCollapseBranchSigned;

  // -------------------------------------------------------------------------
  // FEX_MEMCPYDCBZ=1 (opt-in): cache-line store tier for the forward REP MOVSB
  // fast path in DEF_OP(MemCpy). A copy loop normally moves THREE lines of
  // traffic per line copied — read source, read-for-ownership the destination,
  // write destination back — because a partial-line store must fetch the line
  // it is about to overwrite. `dcbz` establishes the destination line in the
  // cache as zeroes WITHOUT reading it, so a loop that dcbz's a whole line and
  // then writes all of it pays only source-read + destination-write. That is
  // the one non-temporal-store-shaped lever POWER8 has, and it is why glibc's
  // own POWER memset is built on dcbz.
  //
  // TWO REASONS THIS IS OPT-IN RATHER THAN DEFAULT-ON, both structural:
  //
  //  1. CACHE-INHIBITED STORAGE. dcbz on caching-inhibited or write-through
  //     memory raises an alignment interrupt instead of zeroing. DEF_OP(MemSet)
  //     already accepts that exposure for `rep stosb`, but `rep movsb` reaches
  //     strictly more memory: a guest memcpy into a Vulkan/GL mapping that the
  //     host driver made uncached (see the vkMapMemory notes) would take a
  //     SIGBUS it does not take today. Nothing visible in the JIT can tell the
  //     two kinds of guest pointer apart.
  //
  //  2. FAULT GRANULARITY. Every other tier in that op guarantees that a fault
  //     mid-copy leaves the destination holding a byte-exact PREFIX of the
  //     copy. dcbz writes the destination line before the corresponding source
  //     loads run, so a faulting load leaves up to one line of zeroes past the
  //     prefix. FEX writes guest RCX/RSI/RDI back only at op end, so a handler
  //     that fixes the fault and returns re-runs the whole copy and the zeroes
  //     are overwritten; only a handler that *inspects* the partial
  //     destination can tell, and it could already not trust RCX.
  //     A second-order version of the same thing: when BOTH the source and the
  //     destination are unmapped, the dcbz faults on the destination where the
  //     load used to fault on the source, so si_addr changes. Same signal,
  //     same faulting guest instruction.
  //
  // Hashed into the code-cache config id (CodeCache.cpp) — blocks compiled
  // with the tier are not interchangeable with blocks compiled without it.
  // -------------------------------------------------------------------------
  bool MemCpyDcbzEnabled {};

  // FEX_MEMSETDCBZ=0: kill-switch for the LONG-SHIPPING dcbz block-zero path
  // in DEF_OP(MemSet). Default ON (unchanged behaviour) — this exists so the
  // path can be A/B'd under FEX_HWTSO, where PROT_SAO makes dcbz
  // disproportionately expensive (see the gate comment in MemoryOps.cpp).
  bool MemSetDcbzEnabled {true};

  bool IsSpinCollapseSub(IR::Ref Node) {
    const auto ID = IR->GetID(Node).Value;
    return ID < SpinCollapseSubs.size() && SpinCollapseSubs[ID];
  }
  bool IsSpinCollapseBranch(IR::Ref Node) {
    const auto ID = IR->GetID(Node).Value;
    return ID < SpinCollapseBranches.size() && SpinCollapseBranches[ID];
  }
  bool IsSpinCollapseBranchSigned(IR::Ref Node) {
    const auto ID = IR->GetID(Node).Value;
    return ID < SpinCollapseBranchSigned.size() && SpinCollapseBranchSigned[ID];
  }

  // Emit the priority hint (if any) for the edge CurrentBlockID -> Target.
  // Called immediately before the branch instruction so the hint executes
  // exactly when the edge is taken.
  void EmitSpinEdgeHint(IR::OrderedNodeWrapper Target) {
    if (SpinBackedges.empty() && SpinRestoreEdges.empty()) {
      return;
    }
    const auto To = IR->GetOp<IR::IROp_CodeBlock>(Target)->ID;
    const auto Key = SpinEdgeKey(CurrentBlockID, To);
    for (const auto Edge : SpinBackedges) {
      if (Edge == Key) {
        smt_very_low_priority();
        return;
      }
    }
    for (const auto Edge : SpinRestoreEdges) {
      if (Edge == Key) {
        smt_medium_priority();
        return;
      }
    }
  }

  // Block linking: one pending jump thunk per linkable constant-jump exit,
  // emitted after the block bodies at the tail of CompileCode. fextl::list,
  // NOT vector: the emitter's pending-branch fixups hold Label* into these
  // elements (DEF_OP(ExitFunction)'s miss leg branches to LinkPath before
  // the thunk exists), so element addresses must survive later insertions.
  struct PendingJumpThunk {
    uint64_t CallerAddress; // absolute address of the in-block patch site
    uint64_t GuestRIP;      // constant destination RIP (post 32-bit masking)
    PPC64Emitter::Label LinkPath {};
  };
  fextl::list<PendingJumpThunk> PendingJumpThunks;

  // Shared miss-leg spill stubs, one pair per compile unit, emitted at the
  // CompileCode tail next to the jump thunks and bound only when some exit
  // used them. Every ExitFunction miss leg used to inline SpillStaticRegs
  // (~90 instructions of cold code between hot blocks — the dominant static
  // bloat in DSP-heavy Witcher 3 mixer blocks, 16 stvx + 16 std per exit);
  // now a miss is a single `b` here. The spill must still execute inside the
  // code buffer (IsAddressInCodeBuffer is the signal delegator's proxy for
  // "SRA may be live"), which a tail stub satisfies just as well as an
  // inline one. Labels are members (not locals) because the emitter's
  // pending-fixup chain lives in the Label — see the COPY HAZARD note in
  // CodeEmitter's Label. Reset alongside PendingJumpThunks each compile.
  PPC64Emitter::Label SharedSpillExitLabel {};      // non-linkable: -> Pointers.ExitFunctionLinker
  PPC64Emitter::Label SharedSpillLinkLabel {};      // linkable thunk tail: TMP2=&record -> record.StubAddr
  bool SharedSpillExitUsed {};
  bool SharedSpillLinkUsed {};

  // Resolved once at construction: BlockLinking knob AND code caching off.
  // See the resolution site in JIT.cpp for the hard-gate rationale.
  bool BlockLinkingEnabled {};
  // Whether constant-target CALL exits may be linked. = BlockLinkingEnabled &&
  // !LazyLinkArmed: call-dense guests flood the relink/recompile path under
  // FEX_SMCLAZYLINK, so calls fall back to the L1 probe there. Resolved next to
  // BlockLinkingEnabled in the constructor.
  bool CallLinkingEnabled {};

  // Shadow return stack (FEX_SHADOWRETSTACK). Resolved once at construction,
  // mirroring BlockLinkingEnabled. Default OFF; the SMC interlock at the
  // resolution site forces it off in the one lazy-SMC configuration where the
  // RET fast path would reopen a same-thread stale-code window. When false,
  // DEF_OP(ExitFunction) emits the byte-for-byte legacy Call/Return sequences
  // and the block loop skips the entry-label bind, so the default path is
  // provably unchanged.
  bool ShadowRetStackEnabled {};

  // One shadow-return fast-path entry label per IR block, indexed by
  // IROp_CodeBlock::ID (the same ID space JumpTargets uses). Sized once per
  // CompileCode (before any emission) so element addresses are stable for the
  // pending forward-branch fixups a Call push records. Bound at each block's
  // EntryPoint landing -- BEFORE the spill-frame stdu -- so a shadow RET fast
  // path enters exactly where a dispatcher L1 hit would (full entry prologue,
  // incl. the deferred-signal poke and the stdu). Only populated when
  // ShadowRetStackEnabled; empty (and untouched) otherwise.
  fextl::vector<PPC64Emitter::Label> CallReturnEntryLabels;

  // Resolved once at construction: code caching OR SMCSemanticPatch on, i.e.
  // somebody rewrites the exit-RIP window in place and it has to stay a
  // fixed-width 20-byte site. Off means InsertExitRIPMove may use the ordinary
  // variable-width LoadConstant. See the resolution site in JIT.cpp.
  bool ExitRIPFixedWidth {};

  // Spill slots management.
  //
  // SpillSlots is sampled from IR->SpillSlots() at the top of CompileCode.
  // EmitEntryPoint allocates `SpillFrameSize` bytes below the dispatcher
  // frame via stdu r1, -SpillFrameSize, r1. SpillRegister/FillRegister then
  // address slots at POSITIVE offsets from the new r1, starting ABOVE the
  // ELFv2 96-byte linkage + parameter save block: slot 0 at [r1+96],
  // slot 1 at [r1+128], slot k at [r1 + 96 + k * 32]. Every block-exit
  // emit site calls ResetStack() to undo the frame extension before
  // transferring control out of the JIT.
  //
  // Mirrors Arm64JITCore::CompileCode + ResetStack (gemini-fex JIT.cpp:804
  // and JIT.cpp:1157). The previous fixed `SpillBase = -768` formula went
  // positive after slot 24 and silently walked off the top of r1; observed
  // as a SIGSEGV in add_sub_carry_2.asm.jit_500 where the RA spilled 200+
  // NZCV temps from 256 unrolled SBBs in a single IR block.
  //
  // The +96 prefix is the ELFv2 reservation: any bctrl issued from inside
  // the JIT block (Op_Unhandled, DEF_OP(Thunk), DEF_OP(Print)) allows the
  // callee to write LR/CR/TOC at [r1+8..31] and to use [r1+32..95] as its
  // parameter save area. Starting spill slots at [r1+0] like the old
  // formula did put slot 0 on top of the back chain, and slots 1-3 inside
  // the callee-scratch parameter area.
  uint32_t SpillSlots {};
  uint32_t SpillFrameSize {};

  static constexpr uint32_t kSpillSlotPrefix = 96;

  int32_t SpillOffset(uint32_t slot) const {
    return static_cast<int32_t>(kSpillSlotPrefix + slot * MaxSpillSlotSize);
  }

  // -----------------------------------------------------------------------
  // Register helpers
  // -----------------------------------------------------------------------

  [[nodiscard]]
  GPR GetReg(IR::PhysicalRegister Reg) const {
    const auto RegClass = Reg.AsRegClass();
    LOGMAN_THROW_A_FMT(RegClass == IR::RegClass::GPRFixed || RegClass == IR::RegClass::GPR,
                       "Unexpected RegClass: {}", Reg.Class);
    if (RegClass == IR::RegClass::GPRFixed)
      return StaticRegisters[Reg.Reg];
    return GeneralRegisters[Reg.Reg];
  }

  [[nodiscard]] GPR GetReg(IR::Ref Node)              const { return GetReg(IR::PhysicalRegister(Node)); }
  // OrderedNodeWrapper carries either an immediate-encoded PhysicalRegister
  // (post-RA, IsImmediate=true) or an SSA pointer (pre-RA, points to an
  // OrderedNode whose Reg byte holds the PhysicalRegister). Build the right
  // PhysicalRegister depending on which form it's in — calling GetImmediate()
  // on a non-immediate wrapper produces a garbage Reg/Class byte and OOBs
  // the SRA/RA span.
  [[nodiscard]] GPR GetReg(IR::OrderedNodeWrapper W)  const {
    if (W.IsImmediate()) {
      return GetReg(IR::PhysicalRegister(W));
    }
    return GetReg(IR::PhysicalRegister(IR->GetNode(W)));
  }

  [[nodiscard]]
  VR GetVReg(IR::PhysicalRegister Reg) const {
    const auto RegClass = Reg.AsRegClass();
    LOGMAN_THROW_A_FMT(RegClass == IR::RegClass::FPRFixed || RegClass == IR::RegClass::FPR,
                       "Unexpected RegClass: {}", Reg.Class);
    if (RegClass == IR::RegClass::FPRFixed)
      return StaticFPRegisters[Reg.Reg];
    return GeneralFPRegisters[Reg.Reg];
  }

  [[nodiscard]] VR GetVReg(IR::Ref Node)              const { return GetVReg(IR::PhysicalRegister(Node)); }
  [[nodiscard]] VR GetVReg(IR::OrderedNodeWrapper W)  const {
    if (W.IsImmediate()) {
      return GetVReg(IR::PhysicalRegister(W));
    }
    return GetVReg(IR::PhysicalRegister(IR->GetNode(W)));
  }

  [[nodiscard]]
  static IR::RegClass GetRegClass(IR::Ref Node) {
    return IR::PhysicalRegister(Node).AsRegClass();
  }

  [[nodiscard]]
  static bool IsFPR(IR::RegClass C) {
    return C == IR::RegClass::FPR || C == IR::RegClass::FPRFixed;
  }
  [[nodiscard]] static bool IsFPR(IR::Ref N) { return IsFPR(GetRegClass(N)); }
  [[nodiscard]] static bool IsFPR(IR::OrderedNodeWrapper W) {
    return IsFPR(IR::PhysicalRegister(W).AsRegClass());
  }
  [[nodiscard]]
  static bool IsGPR(IR::RegClass C) {
    return C == IR::RegClass::GPR || C == IR::RegClass::GPRFixed;
  }
  [[nodiscard]] static bool IsGPR(IR::Ref N) { return IsGPR(GetRegClass(N)); }
  [[nodiscard]] static bool IsGPR(IR::OrderedNodeWrapper W) {
    return IsGPR(IR::PhysicalRegister(W).AsRegClass());
  }

  [[nodiscard]]
  bool IsInlineConstant(const IR::OrderedNodeWrapper& Node, uint64_t* Value = nullptr) const;

  [[nodiscard]]
  bool IsInlineEntrypointOffset(const IR::OrderedNodeWrapper& WNode, uint64_t* Value) const;

  // Does this operand hold element 0's bits replicated across every element, so
  // that a consumer needing only element 0 may read any element and skip its
  // own splat? True for a VF*ScalarInsert the ScalarSplatChain IR pass granted
  // SplatResult, and for a LoadRegister it stamped with SplatElementSize -- the
  // latter matters because the frontend's per-instruction register-cache flush
  // routes almost every chain edge through the guest XMM's static register.
  //
  // Answering from the defining op is what makes this safe in both directions:
  // the producer's DEF_OP tests the exact same bit when it decides to leave the
  // result splatted, and anything that stands between def and use -- an
  // RA-inserted fill or copy -- changes the defining op to one that is not a
  // marked ScalarInsert, so the test degrades to "assume architectural" and the
  // splat gets emitted. (A fill is a full-width lvx of a full-width stvx, so
  // the value really is still splatted there; re-splatting it is merely
  // redundant, never wrong.)
  [[nodiscard]]
  bool IsSplatFormValue(const IR::OrderedNodeWrapper& WNode, IR::OpSize ElementSize) const;

  // Get a register that may be zero-register if the node is constant 0
  [[nodiscard]]
  GPR GetZeroableReg(IR::OrderedNodeWrapper Src) const {
    uint64_t Const;
    if (IsInlineConstant(Src, &Const) && Const == 0) {
      return r0;  // r0 reads as 0 in many PPC instructions (addi RA=r0 means imm only)
    }
    return GetReg(Src);
  }

  // -----------------------------------------------------------------------
  // Size helpers
  // -----------------------------------------------------------------------

  [[nodiscard]]
  static bool Is32Bit(const IR::IROp_Header* Op) {
    return Op->Size < IR::OpSize::i64Bit;
  }

  // Mask a value to N-bit width in-place, needed for sub-32-bit ops
  void MaskForSize(GPR dst, GPR src, IR::OpSize sz) {
    switch (sz) {
    case IR::OpSize::i8Bit:
      rlwinm(dst, src, 0, 24, 31);  // AND with 0xFF
      break;
    case IR::OpSize::i16Bit:
      rlwinm(dst, src, 0, 16, 31);  // AND with 0xFFFF
      break;
    case IR::OpSize::i32Bit:
      rlwinm(dst, src, 0, 0, 31);   // clear upper 32 bits
      break;
    default:
      if (dst != src) mr(dst, src);
      break;
    }
  }

  void SignExtendForSize(GPR dst, GPR src, IR::OpSize sz) {
    switch (sz) {
    case IR::OpSize::i8Bit:  extsb(dst, src); break;
    case IR::OpSize::i16Bit: extsh(dst, src); break;
    case IR::OpSize::i32Bit: extsw(dst, src); break;
    default: if (dst != src) mr(dst, src); break;
    }
  }

  // -----------------------------------------------------------------------
  // Condition mapping (from IR CondClass to PPC64 branch condition)
  // We use CR0 for all comparisons.
  // -----------------------------------------------------------------------
  [[nodiscard]]
  static PPC64Emitter::Cond MapCC(IR::CondClass Cond);

  // Emit compare for a CondJump that evaluates Src1 op Src2.
  // After this, CR0 reflects the comparison result for MapCC(Cond).
  void EmitCompare(IR::CondClass Cond, IR::OpSize Sz,
                   IR::OrderedNodeWrapper Src1, IR::OrderedNodeWrapper Src2,
                   uint8_t CRField = 0);

  // True when ProjectXERToCR1() emits the ISA 3.0 single-instruction `mcrxrx`
  // form (POWER9+) rather than the POWER8 mfxer/rotlwi/mtocrf fallback. The
  // two produce DIFFERENT CR1 layouts, so this one predicate must drive both
  // the emitted sequence and every bit index read back out of CR1 — otherwise
  // the sequence and the index can drift apart silently.
  [[nodiscard]] bool ProjectXERUsesMcrxrx() const;

  // PPC CR-bit index holding XER.OV after ProjectXERToCR1(): 4 (CR1.LT) on the
  // mcrxrx layout, 5 (CR1.GT) on the pre-3.0 layout. XER.CA is CR1.EQ (bit 6)
  // in both, so C-consuming conditions need no equivalent accessor.
  [[nodiscard]] uint32_t XEROVBitIndex() const;

  // Project XER's carry/overflow state into CR1 non-destructively (XER itself
  // is unchanged). Used to make C/V flags branch-testable after an x86
  // *WithFlags op. Read the OV bit index from XEROVBitIndex(), never a
  // literal. Clobbers TMP1/TMP2 on the pre-3.0 path; the ISA 3.0 path clobbers
  // no GPRs, but callers may assume the larger clobber set unconditionally.
  void ProjectXERToCR1();

  // Write a 4-bit NZCV literal (bit3=N, bit2=Z, bit1=C, bit0=V) into our
  // flag domain (CR0.LT/EQ + XER.CA/OV). Other CR0 / XER bits preserved.
  // Used by CondAddNZCV / CondSubNZCV "false" paths.
  void SetNZCVConstant(uint8_t NZCV);

  // After a sub-64-bit AND result has been computed in `Result`, mask/extend
  // it to the IR operand size and set CR0 from the resized value, so that
  // CR0.LT/EQ encode SF/ZF for the operand width (TestNZ/TestZ helper).
  void EmitTestNZSetCR(GPR Result, IR::OpSize Size);

  // Build a 16-byte vperm control vector at r1-16 then `lvx` into Dst.
  // hi packs phys[8..15] (byte 7 = phys[8], byte 0 = phys[15]).
  // lo packs phys[0..7]  (byte 7 = phys[0], byte 0 = phys[7]).
  void LoadPermCtrl(VR Dst, uint64_t hi, uint64_t lo);

  // Map an IR CondClass to a PPC bc cond using NZCV semantics — i.e., the
  // condition is decoded against the packed PSTATE NZCV flags rather than a
  // direct compare. May emit ProjectXERToCR1() and CR-bit ops (crand/crxor/...)
  // to synthesize composite conditions; returns the {BO, BI} for the final bc.
  PPC64Emitter::Cond MapNZCVCC(IR::CondClass Cond);

  // Emit a misaligned-LOCK-RMW helper call (split-lock path).
  // Sets up a 64-byte mini-frame, stages Val and Addr into stack slots,
  // spills dynamic regs, marshals (op, addr, value_ptr, result_ptr, size)
  // into r3..r7, calls PPC64_SplitLockEmulate, restores dyn regs, then
  // loads the helper's result into Dst. The mini-frame is sized to keep
  // the original [r1-8] CR0 stash untouched, so callers can leave their
  // existing mfcr/std/ld/mtcrf bracket in place.
  void EmitSplitLockHelperCall(FEXCore::ArchHelpers::PPC64::SplitLockOp Op,
                               PPC64Emitter::GPR Addr, PPC64Emitter::GPR Val,
                               PPC64Emitter::GPR Dst, IR::OpSize Sz);

  // CAS variant: same frame, but Expected is also staged into the result
  // slot so the helper can compare-and-swap. Returns the loaded value in
  // Dst (caller computes ZF by cmp'ing Dst against Expected).
  void EmitSplitLockCASCall(PPC64Emitter::GPR Addr, PPC64Emitter::GPR Expected,
                            PPC64Emitter::GPR Desired, PPC64Emitter::GPR Dst,
                            IR::OpSize Sz);

  // C6: JIT-inline ldarx/stdcx. container loop for the doubleword-contained
  // subset of misaligned Fetch*/Swap ops (2-/4-byte fields with
  // (EA & 7) + size <= 8). Emitted in the misaligned branch before the
  // helper call; branches to *Done when it handled the op, falls through
  // (emitting nothing on the reject path beyond the containment test) when
  // the case is crossing/quadword-contained — or emits nothing at all when
  // the SplitLockInlineContained knob is off or the size is not 2/4 — so
  // the caller's EmitSplitLockHelperCall still covers those. See the
  // definition for the register accounting and the CR0/r0 contracts.
  void EmitInlineContainedRMW(FEXCore::ArchHelpers::PPC64::SplitLockOp Op,
                              PPC64Emitter::GPR Addr, PPC64Emitter::GPR Val,
                              PPC64Emitter::GPR Dst, IR::OpSize Sz,
                              PPC64Emitter::Label* Done);

  // C7: CAS variant of EmitInlineContainedRMW, same gating and fall-through
  // behaviour. On the taken path it leaves Dst = observed old field
  // (zero-extended) and CR0 = the CAS ZF contract (EQ on success, NE on
  // compare-mismatch), matching the aligned LL/SC exit exactly.
  void EmitInlineContainedCAS(PPC64Emitter::GPR Addr, PPC64Emitter::GPR Expected,
                              PPC64Emitter::GPR Desired, PPC64Emitter::GPR Dst,
                              IR::OpSize Sz, PPC64Emitter::Label* Done);

  // -----------------------------------------------------------------------
  // Stack management
  // -----------------------------------------------------------------------
  void ResetStack();

  // -----------------------------------------------------------------------
  // Relocation support
  // -----------------------------------------------------------------------
  fextl::vector<FEXCore::CPU::Relocation> Relocations;

  // S3.7-C0: byte offset of this block's BlockBegin within the whole
  // CodeBuffer. Relocation Header.Offset must be WHOLE-BUFFER relative
  // because ApplyCodeRelocations indexes from the buffer base, while
  // GetOffset() is relative to the per-block SetBuffer at JIT.cpp:2246.
  // Snapshotted just BEFORE SetBuffer opens the block's window because
  // CodeBuffers.LatestOffset is advanced later at JIT.cpp:2486. Mirror
  // of ARM64's fixup loop at JIT/JIT.cpp:1111 — ARM64 does the same
  // offset += LatestOffset arithmetic in a post-loop pass; snapshotting
  // once at the top of CompileCode is the same numerically and needs no
  // post-loop walk.
  uint64_t BlockBufferOffset {};

  // Load a named thunk's function pointer into Reg via LoadConstant, recording
  // a RELOC_NAMED_THUNK_MOVE relocation for code-cache patching.
  void InsertNamedThunkRelocation(GPR Reg, const IR::SHA256Sum& Sum);

  // S3.7-C2: Load a guest-RIP-derived Constant into Reg via LoadConstantFixed
  // and record a RELOC_GUEST_RIP_MOVE. Every site that used to emit a bare
  // `LoadConstant(reg, Entry + Op->Offset)` must use this instead, or cached
  // code loaded in a different ASLR session will jump to a stale address.
  // TakeRelocations() rebases these against the caller-supplied guest base
  // before serialization; the patcher adds the new base back on load.
  void InsertGuestRIPMove(GPR Reg, uint64_t Constant);

  // DEF_OP(EntrypointOffset)'s guest RIP -- the return address a guest `call`
  // pushes, so one of the hottest constants the JIT materialises. Same gating
  // argument as InsertExitRIPMove: the fixed 20-byte window and its
  // RELOC_GUEST_RIP_MOVE exist solely so the code cache can re-emit a rebased
  // address into it, so with ExitRIPFixedWidth false this drops to a plain
  // variable-width LoadConstant (1-3 instructions for any sub-4GiB RIP) and
  // records no relocation.
  void InsertEntrypointRIPMove(GPR Reg, uint64_t Constant);

  // SMC Idea 4 (FEX_SMCSEMANTICPATCH): as InsertGuestRIPMove, but additionally
  // records the host address of the 20-byte window in CodeData.ExitRIPSites so
  // the SMC fault handler can repatch this destination when the guest rewrites
  // the rel32 that produced it. Only ExitFunction destinations may use this --
  // the fault handler identifies a window by the RIP value it materialises, and
  // recording any other guest-RIP constant would make that lookup ambiguous.
  // See Interface/Core/SMCSemanticPatch.h.
  //
  // When ExitRIPFixedWidth is false (no code cache, no semantic patching) this
  // drops to a plain variable-width LoadConstant with no relocation and no
  // site record -- nothing rewrites the window in that configuration.
  void InsertExitRIPMove(GPR Reg, uint64_t Constant);

  // SMC Idea 4, mov-immediate half: materialise a constant the frontend tagged
  // as a patchable guest immediate (IROp_Constant::PatchSite != 0) into the same
  // fixed-width 20-byte window, and record it against its site index. Returns
  // false without emitting anything when the constant is untagged, the flag is
  // off, or the table overflowed -- the caller then emits the ordinary
  // variable-width LoadConstant. Unlike InsertGuestRIPMove this records NO
  // relocation: the value is a plain guest immediate, not an address, so it is
  // correct as-is in a code-cache session with a different ASLR base.
  // See Interface/Core/SMCSemanticPatch.h.
  bool TryInsertPatchableImmMove(GPR Reg, uint64_t Constant, uint32_t PatchSite);

  // Emit the JIT block entry sequence (SRA fill, TF check)
  void EmitEntryPoint(PPC64Emitter::Label& HeaderLabel, bool CheckTF);

  // Load a PPC64 helper's absolute host address into `dst` via the two
  // ld-through-STATE dance:
  //   ld dst, PPC64_HelperTable_off(STATE)   ; dst = HelperTable pointer
  //   ld dst, IDX*8(dst)                     ; dst = helper address
  // Two d-form loads instead of LoadConstant's 1-5 instructions per call
  // site, and PIE-safe (no absolute address baked into JIT). Caller is
  // responsible for the ELFv2 `mr r12, dst; mtctr dst; bctrl` postlude.
  // Placed inline in the header so all JIT source files see the same body
  // without cross-TU linkage games. See P2.1 C1/C2 in build-agent-notes.md.
  void EmitLoadPPC64Helper(PPC64Emitter::GPR dst, FEXCore::CPU::PPC64HelperIndex idx) {
    static_assert(offsetof(FEXCore::Core::CpuStateFrame, PPC64_HelperTable) <= INT16_MAX,
                  "PPC64_HelperTable offset must fit int16_t for d-form ld");
    ld(dst,
       static_cast<int16_t>(offsetof(FEXCore::Core::CpuStateFrame, PPC64_HelperTable)),
       STATE);
    ld(dst, static_cast<int16_t>(idx * PPC64HelperSlotSize), dst);
  }

  // Load 128-bit constant `idx` from the pool into `dst`:
  //   ld  base, PPC64_HelperTable_off(STATE)   ; base = table/pool allocation
  //   li  off,  PoolOffset + idx*16
  //   lvx dst,  base, off
  // Three instructions and no store queue traffic, versus LoadConstant + two
  // stds + addi + lvx per constant. `base` and `off` are caller-supplied
  // scratch GPRs; base must not be r0 (lvx would read it as literal zero).
  void EmitLoadPPC64VConst(PPC64Emitter::VR dst, FEXCore::CPU::PPC64VConstIndex idx, PPC64Emitter::GPR base,
                           PPC64Emitter::GPR off) {
    static_assert(offsetof(FEXCore::Core::CpuStateFrame, PPC64_HelperTable) <= INT16_MAX,
                  "PPC64_HelperTable offset must fit int16_t for d-form ld");
    ld(base, static_cast<int16_t>(offsetof(FEXCore::Core::CpuStateFrame, PPC64_HelperTable)), STATE);
    li(off, static_cast<int16_t>(FEXCore::CPU::PPC64VConstPoolOffset + idx * FEXCore::CPU::PPC64VConstSlotSize));
    lvx(dst, base, off);
  }

  // Store the address of the JITCodeHeader (bound at HeaderLabel) into
  // CpuStateFrame::State.InlineJITBlockHeader so RestoreRIPFromHostPC and the
  // other GetFrameBlockInfo consumers can find the tail. Emitted at every
  // dispatcher-reachable entry so any signal fault into this block finds a
  // fresh header pointer regardless of which entry point the dispatcher used.
  // Uses `bcl 20,31,$+4; mflr` (LK=1 form the CPU does not push to the link
  // stack) to load PC then subtracts the emit-time delta to recover BlockBegin.
  // Clobbers TMP1 and TMP2 — safe: only called during entry-point prologue
  // before any IR op writes to SRA/spill state.
  void EmitStoreBlockBeginToInlineHeader(PPC64Emitter::Label& HeaderLabel);

  // Emit a one-instruction poke of the thread's InterruptFaultPage. PPC64LE
  // treats the whole JIT code buffer as an async-signal deferral region
  // (SignalDelegator's InJIT_ForDefer): a deferred signal mprotects the page
  // PROT_NONE and relies on this store faulting at the next guaranteed-
  // coherent guest boundary to drain the queue. Emitted at every dispatcher-
  // reachable EntryPoint and before every backward intra-unit branch so a
  // hot guest loop of fully-linked blocks cannot spin forever with the
  // signal queued (and the host mask left at the handler's sa_mask).
  void EmitSuspendInterruptCheck();

  // -----------------------------------------------------------------------
  // Memory operation helpers (defined in MemoryOps.cpp)
  // -----------------------------------------------------------------------

  // Compute effective address: Base + Offset (scaled by OffsetScale)
  GPR ComputeAddress(GPR Base, IR::OrderedNodeWrapper Offset,
                     IR::MemOffsetType OffsetType, uint8_t OffsetScale);

  // SVE predicate mem ops — thin wrappers reusing load/store logic
  void StoreMem_Impl(const IR::IROp_Header* IROp, IR::Ref Node);
  void LoadMem_Impl(const IR::IROp_Header* IROp, IR::Ref Node);

  // -----------------------------------------------------------------------
  // Op dispatch helpers
  // -----------------------------------------------------------------------
  IR::RegisterAllocationPass* RAPass {};
  FEXCore::Core::DebugData*   DebugData {};

  // -----------------------------------------------------------------------
  // AES lowering helpers (VectorOps.cpp)
  //
  // The POWER8 cipher instructions read the AES state big-endian while a guest
  // XMM is held with guest byte 0 at BE byte element 15, so every AES round is
  // bracketed by a byte reversal. EmitAESLoadMask materializes the {15..0}
  // vperm mask into VTMP1 - statelessly on a cold call (4 instructions, no
  // memory, no cross-host-call register trust; see the vs14-vs31 dw1 hazard
  // note in PPC64Emitter.h), or with a single xxlor from the VTMP3_VSX (vs12)
  // park when AESMaskCached says a preceding AES-family op in this block
  // already built it.
  //
  // AESMaskCached is EMISSION-TIME bookkeeping only. The invariant that makes
  // a hit sound: between the op that parked the mask and the op that reuses
  // it, no other host instruction was emitted at all. CompileCode enforces
  // this by invalidating on every non-AES-family op and at every block bind;
  // the AES handlers' Op_Unhandled bail paths invalidate explicitly since
  // the loop-level check can't see them.
  //
  // ALL OF THE ABOVE IS THE POWER8 (ISA 2.07) ARM. When
  // HostFeatures.SupportsISA30 is set the handlers take an xxbrq arm instead:
  // one instruction per reversal, no mask, no vs12 park. EmitAESLoadMask is
  // the only writer of AESMaskCached and only the POWER8 arm calls it, so on
  // an ISA 3.0 host the flag stays false forever and the (still-running)
  // CompileCode invalidation is a harmless no-op. Nothing needs to change
  // there if a new AES-family op is added to the ISA 3.0 arm only.
  // -----------------------------------------------------------------------
  void EmitAESLoadMask();
  bool AESMaskCached = false;
  void InvalidateAESCache() { AESMaskCached = false; }

  // Emit-time "CR1 currently mirrors XER" flag for the ProjectXERToCR1 cache.
  // Lifecycle owned by CompileCode: reset at block entry, cleared after every
  // op not on the verified no-XER/CR1-write allowlist (see the post-handler
  // switch in CompileCode and the rationale in ProjectXERToCR1).
  bool XERProjectionValid = false;

  // Emit-time last-constant cache for DEF_OP(Constant): when the previous
  // materialized constant is still live in its (dynamic, callee-saved) RA
  // register and the new value is within ±32K, emit one addi off it instead
  // of a 2-5 insn LoadConstant. Targets clustered guest addresses (rip-
  // relative coefficient loads in polynomial code: one lis+ori then addi per
  // subsequent constant). Lifecycle owned by CompileCode's post-handler
  // switch: set by non-PatchSite OP_CONSTANT with a dynamic-GPR dest,
  // survives ONLY across the verified no-dynamic-GPR-write allowlist
  // (FPR-class LoadMem, the scalar-FP insert family), reset at block entry.
  struct {
    uint64_t Value;
    uint8_t Reg;      // GeneralRegisters[] index
    bool Valid;
  } LastConstantCache {};

  // Load-and-splat fusion for FMA memory operands (both per-block, cleared at
  // block entry). CompileCode's pre-pass fills SplatCandidateLoads with node
  // IDs of single-use f64 FPR LoadMems whose lone consumer is an FMA-family
  // scalar insert (Vector1/Vector2/Addend position — never Upper).
  // DEF_OP(LoadMem) emits those via lxvdsx (value in BOTH doublewords) and
  // records the node in SplatFormLoadNodes; the FMA handlers consult that to
  // skip their own splat. Single-use SSA temps only, so splat form never
  // reaches guest-architectural state (the hazard that convicted the
  // ScalarSplatChain pass does not apply).
  fextl::vector<uint32_t> SplatCandidateLoads;
  fextl::vector<uint32_t> SplatFormLoadNodes;
  static bool IdInVec(const fextl::vector<uint32_t>& V, uint32_t Id) {
    return std::find(V.begin(), V.end(), Id) != V.end();
  }

  // Shared SHA-256 four-round emitter for VSha256H (returns ABCD half) and
  // VSha256H2 (returns EFGH half). Fully inline: vshasigmaw ST=1 for both
  // big-Sigma functions, vsel-form Ch/Maj, vsldoi lane rotations. Borrows two
  // dynamic VRs (excluded from Dst/sources) for compute space; see the
  // borrow-protocol comment at the definition (VectorOps.cpp).
  void EmitSha256Rounds4(PPC64Emitter::VR Dst, PPC64Emitter::VR ABCD, PPC64Emitter::VR EFGH,
                         PPC64Emitter::VR WK, bool ReturnABCD);

  // Shared SHA-1 four-round emitter for VSha1C/M/P (Choose/Majority/Parity).
  // Same structure and borrow protocol as EmitSha256Rounds4.
  enum class Sha1Fn { Choose, Majority, Parity };
  void EmitSha1Rounds4(PPC64Emitter::VR Dst, PPC64Emitter::VR ABCD, PPC64Emitter::VR E,
                       PPC64Emitter::VR WK, Sha1Fn Fn);

  // -----------------------------------------------------------------------
  // Op handler declarations (filled in by the separate *.cpp files)
  // -----------------------------------------------------------------------
#define DEF_OP(x) void Op_##x(IR::IROp_Header const* IROp, IR::Ref Node)

  DEF_OP(Unhandled);
  DEF_OP(NoOp);

#define IROP_DISPATCH_DEFS
#include <FEXCore/IR/IRDefines_Dispatch.inc>

  // -----------------------------------------------------------------------
  // PPC64LE-only vector ops (VectorOps.cpp).
  // IR.json marks these JITDispatch:false so that adding them does not force
  // every other backend to grow a lowering — the OpcodeDispatcher only emits
  // them under ARCHITECTURE_ppc64le. That also keeps them out of the
  // auto-generated dispatch table, so declare and register them by hand
  // (same mechanism the x87 stack ops below use).
  // -----------------------------------------------------------------------
  DEF_OP(VMaddPairwise16);
  DEF_OP(VExtractSignBits);
  DEF_OP(VAnyNonZero);

  // PPC64LE-only fused byte-reversed memory ops (MemoryOps.cpp) — the MOVBE
  // lowering. Same JITDispatch:false / hand-registered mechanism as above.
  DEF_OP(LoadMemRev);
  DEF_OP(StoreMemRev);

  // -----------------------------------------------------------------------
  // x87 stack bookkeeping ops (X87Ops.cpp).
  // These IR ops are normally lowered away by the x87StackOptimization pass
  // into LoadContext/StoreContext primitives. The pass is conditional on
  // !DisablePasses(), so when O0 is set (or the optimizer doesn't fully
  // eliminate them) they survive to the JIT. The base FallbackHandler table
  // has no entry for any of these — relying on Op_Unhandled would silently
  // leave destination registers unwritten, so we implement the slow-path
  // semantics directly here, mirroring the IR the pass would have emitted.
  // -----------------------------------------------------------------------
  DEF_OP(InitStack);
  DEF_OP(IncStackTop);
  DEF_OP(DecStackTop);
  DEF_OP(InvalidateStack);
  DEF_OP(PushStack);
  DEF_OP(CopyPushStack);
  DEF_OP(PopStackDestroy);
  DEF_OP(ReadStackValue);
  DEF_OP(StoreStackMem);
  DEF_OP(StoreStackToStack);
  DEF_OP(StackValidTag);
  DEF_OP(SyncStackToSlow);
  DEF_OP(StackForceSlow);

  // Native f64→f80 conversion (X87Ops.cpp). IR.json marks F80CVTTO
  // JITDispatch:false (every other size/backend uses the FABI softfloat
  // bridge); we override the i64 source case with a branchy bit-manipulation
  // lowering because FXSAVE in ReducedPrecisionMode hammers it.
  DEF_OP(F80CVTTo);

  // Bucket C: stack-form arithmetic ops that survive the optimisation pass.
  // Each is a thin wrapper that loads operands from x87 stack slots, calls
  // the corresponding F80 fallback handler via the existing FABI bridge,
  // and stores the result back to a stack slot.
  DEF_OP(F80AddStack);
  DEF_OP(F80SubStack);
  DEF_OP(F80MulStack);
  DEF_OP(F80DivStack);
  DEF_OP(F80AddValue);
  DEF_OP(F80SubValue);
  DEF_OP(F80SubRValue);
  DEF_OP(F80MulValue);
  DEF_OP(F80DivValue);
  DEF_OP(F80DivRValue);
  DEF_OP(F80CmpStack);
  DEF_OP(F80CmpValue);
  DEF_OP(F80StackTest);
  DEF_OP(F80SQRTStack);
  DEF_OP(F80SINStack);
  DEF_OP(F80COSStack);
  DEF_OP(F80F2XM1Stack);
  DEF_OP(F80SINCOSStack);
  DEF_OP(F80RoundStack);
  DEF_OP(F80FYL2XStack);
  DEF_OP(F80SCALEStack);
  DEF_OP(F80FPREMStack);
  DEF_OP(F80FPREM1Stack);
  DEF_OP(F80PTANStack);
  DEF_OP(F80ATANStack);
  DEF_OP(F80VBSLStack);
  DEF_OP(F80StackXchange);
  DEF_OP(F80StackChangeSign);
  DEF_OP(F80StackAbs);
#undef DEF_OP
};

#define DEF_OP(x) void PPC64JITCore::Op_##x(IR::IROp_Header const* IROp, IR::Ref Node)

[[nodiscard]]
fextl::unique_ptr<CPUBackend> CreatePPC64JITCore(FEXCore::Context::ContextImpl* ctx,
                                                  FEXCore::Core::InternalThreadState* Thread);

} // namespace FEXCore::CPU
