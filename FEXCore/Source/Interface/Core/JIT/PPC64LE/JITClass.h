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
  // Deliberately NO F64F2XM1 entry — F64F2XM1Impl diverges from the
  // upstream F64F2XM1Handler slot (expm1(x*ln2) vs exp2(src)-1.0, off by
  // >1 ULP on 44.6% of inputs); reusing that Pointers slot re-breaks
  // D9_F0_02_F64. Its call site keeps LoadConstant for now.
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

  // Project XER.SO/OV/CA -> CR1.LT/GT/EQ non-destructively. Used to make
  // C/V flags branch-testable after an x86 *WithFlags op. Clobbers TMP1, TMP2.
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
