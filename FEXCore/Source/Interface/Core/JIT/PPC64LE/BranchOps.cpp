// SPDX-License-Identifier: MIT
// PPC64LE branch/control-flow operations for FEX JIT backend.
#include "Interface/Context/Context.h"
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/JIT/PPC64LE/JITClass.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/MathUtils.h>

namespace FEXCore::CPU {

DEF_OP(CallbackReturn) {
  // Spill SRA back to context
  SpillStaticRegs(TMP1);
  ResetStack();

  // Decrement signal handler ref counter
  int32_t ref_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, SignalHandlerRefCounter));
  lwz(TMP2, ref_off, STATE);
  addi(TMP2, TMP2, -1);
  stw(TMP2, ref_off, STATE);

  // Adjust RSP by 8 (restore "misaligned" state from before callback)
  int32_t rsp_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, State.gregs[FEXCore::X86State::REG_RSP]));
  ld(TMP2, rsp_off, STATE);
  addi(TMP2, TMP2, 8);
  std(TMP2, rsp_off, STATE);

  PopCalleeSavedRegisters();
  blr();
}

// Inlined L1 lookup at every block exit.
//
// Previously this op stored State.rip, ran SpillStaticRegs (62 instructions),
// and jumped to Pointers.DispatcherLoopTop, which then did the ~15-instruction
// L1 probe and bctr'd to the block. On an L1 hit that whole spill was pure
// waste: ppc64le SRA registers are FIXED physical assignments (PPC64Emitter.h
// x64::SRA / x32::SRA), disjoint from the dynamic RA pool, so no SSA value is
// ever allocated to one and guest state is live in registers unconditionally.
// The dispatcher's hit leg branches to CodeData.EntryPoints[GuestEntry], which
// JIT.cpp records AFTER EmitEntryPoint's FillStaticRegs, so the warm target
// never refills — meaning the spill was written and then immediately made
// redundant by registers that were never disturbed.
//
// So: do the probe here and jump straight to the target, and pay the spill
// only on the miss leg.
//
// Register / flag discipline this sequence must honour:
//
//   CR7, never CR0. CR0 carries the block's live packed-NZCV (FillStaticRegs
//   sets it, downstream FromNZCV consumers read it) and SpillStaticRegs on the
//   miss leg packs CR0+XER into flags[RFLAG_NZCV_LOC]. Every instruction below
//   is a no-Rc form and the compare targets cr7, so both CR0 and XER reach the
//   miss-leg spill exactly as the block left them.
//
//   r0 stays 0. Guest loads/stores are X-form with r0 in the rB slot (where
//   PPC does NOT substitute literal zero), so a nonzero r0 silently offsets
//   every memory access in the target block. Nothing here writes r0, and no
//   rB=r0 form is used; the invariant simply carries through, which is why the
//   dispatcher's `li r0, 0` has no counterpart on the inlined hit leg.
//
//   Address dependency on the HostCode load. See the ORDERING NOTE in
//   PPC64Dispatcher.cpp and LookupCacheEntry::Publish: the conditional branch
//   does NOT order load->load on Power, so the GuestCode value is fed into the
//   HostCode load's base register.
//
// BLOCK LINKING (constant-target JUMP exits only, BlockLinking knob).
//
// When BlockLinkingEnabled and this exit is a plain jump to a constant RIP
// (Hint == None — calls, returns and CheckTF exits are excluded; patching a
// call exit to `bl` would push the probe's second instruction onto POWER9's
// link stack while the architectural return goes elsewhere, mispredicting
// every linked call/ret pair, and that redesign is not done), the exit is
// reordered so the WHOLE L1 probe becomes the patch target:
//
//     InsertExitRIPMove TMP1, NewRIP      (1-5 insns; 5 fixed when
//                                          ExitRIPFixedWidth -- see below)
//     std   TMP1, State.rip(STATE)        hoisted from BOTH probe legs
//     li    r0, 0                         hoisted from the hit leg (P5.0.2)
//   PatchSite:                            4-byte aligned by construction
//     <L1 probe, hit leg ends mtctr;bctr, miss leg spills and branches to
//      this exit's jump thunk LinkPath — see CompileCode's thunk emission>
//
// Unlinked, PatchSite holds the probe's first instruction and behaviour is
// identical to the non-linking lowering below (the rip store and r0 re-zero
// run earlier, on both legs instead of split across them — architecturally
// invisible). On link, ExitFunctionLinkWithRecord atomically rewrites
// PatchSite to `b HostCode` (I-form, ±32MiB) or, out of range — the common
// case against a 128MiB code buffer — `b Thunk`, with the thunk's own first
// word patched to the `bcl 20,31,$+4` PC-discovery idiom that loads HostCode
// from the adjacent record.
//
// The hoist ordering is load-bearing:
//   - std State.rip BEFORE PatchSite keeps the P5.0.1 invariant (below) on
//     the linked fast path, which never executes probe instructions at all.
//   - li r0,0 BEFORE PatchSite: a linked branch skips the probe's hit leg,
//     so leaving the re-zero inside it would let a nonzero r0 reach the
//     target block's X-form rB=r0 addressing — silent guest memory
//     corruption. The invariant must be re-established before the patchable
//     word, not after it.
DEF_OP(ExitFunction) {
  auto Op = IROp->C<IR::IROp_ExitFunction>();
  ResetStack();

  const int32_t rip_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, State.rip));

  // ---------------------------------------------------------------------
  // Materialise the destination RIP into a register.
  //
  // TMP1 is the staging register: the probe below uses only TMP2/TMP3/TMP4,
  // and in the register case RIPReg is an RA- or SRA-allocated GPR (r7-r26,
  // r30, r31 across both guest modes) which is disjoint from TMP1-TMP4, so
  // nothing here can clobber a still-live SSA value. ResetStack may itself
  // use TMP1 for oversized frames, hence this comes after it.
  // ---------------------------------------------------------------------
  GPR RIPReg = TMP1;
  uint64_t NewRIP;
  bool ConstRIP = false;
  if (IsInlineConstant(Op->NewRIP, &NewRIP) ||
      IsInlineEntrypointOffset(Op->NewRIP, &NewRIP)) {
    ConstRIP = true;
    // 32-bit guest: ensure the RIP constant is canonical 32-bit. For inline
    // constants the value was already produced from a 32-bit source so the
    // upper 32 should already be zero, but mask defensively for jumps from
    // RIP-relative computations.
    if (!CTX->Config.Is64BitMode()) {
      NewRIP &= 0xFFFFFFFFull;
    }
    // S3.7-C2: this constant is a guest RIP baked into host instruction bytes;
    // a code cache saved in one ASLR session and loaded in another would jump
    // to a stale address without a RELOC_GUEST_RIP_MOVE. Record placed AFTER
    // the 32-bit mask so the recorded value matches the emitted immediate.
    // SMC Idea 4: this is the ONLY guest-RIP constant the semantic-patch fault
    // handler is allowed to rewrite, so it is the only one recorded.
    //
    // WIDTH: InsertExitRIPMove emits the fixed 20-byte window only when
    // something rewrites it in place — code caching (ApplyCodeRelocations) or
    // FEX_SMCSEMANTICPATCH (the fault handler's SynthesizeRIPWindow). With
    // both off it degrades to a variable-width LoadConstant and records no
    // relocation; see PPC64JITCore::ExitRIPFixedWidth in JIT.cpp. Neither the
    // hoist below nor the linker cares about the width — PatchSite is captured
    // from the cursor after this call, not computed from a fixed offset.
    // (Note BlockLinking is separately interlocked off when
    // FEX_SMCSEMANTICPATCH is enabled; see JIT.cpp BlockLinkingEnabled.)
    InsertExitRIPMove(TMP1, NewRIP);
    RIPReg = TMP1;
  } else {
    GPR NewRIPReg = GetReg(Op->NewRIP);
    if (!CTX->Config.Is64BitMode()) {
      // 32-bit guest: mask into TMP1 rather than mutating the SSA-allocated
      // NewRIPReg, which may still be live elsewhere.
      rldicl(TMP1, NewRIPReg, 0, 32);
      RIPReg = TMP1;
    } else {
      RIPReg = NewRIPReg;
    }
  }

  // ---------------------------------------------------------------------
  // Block-linking hoist + patch-site registration (see header comment).
  // Only for constant-target plain jumps with the knob on; every other exit
  // shape keeps the exact non-linking lowering below.
  // ---------------------------------------------------------------------
  const bool Linkable =
    ConstRIP && Op->Hint == IR::BranchHint::None && BlockLinkingEnabled;
  PPC64Emitter::Label* LinkPathLabel = nullptr;
  if (Linkable) {
    // Hoisted region: rip store + r0 re-zero, then the patch site. Both
    // probe legs below skip their own copies when Linkable.
    std(RIPReg, rip_off, STATE);
    li(r(0), 0);
    // PatchSite == the probe's first instruction (the ld of L1Pointer just
    // below). All emitted instructions are 4 bytes and SetBuffer lands on a
    // 16-byte boundary, so this address is always 4-byte aligned for the
    // linker's atomic 4-byte rewrite.
    PendingJumpThunks.push_back({GetCursorAddress<uint64_t>(), NewRIP, {}});
    LinkPathLabel = &PendingJumpThunks.back().LinkPath;
  }

  // ---------------------------------------------------------------------
  // L1 probe. Mirrors the dispatcher's arithmetic exactly (PPC64Dispatcher.cpp
  // DispatcherLoopTop): L1Mask is pre-scaled by sizeof(LookupCacheEntry)=16,
  // so the index is (RIP << 4) & L1Mask.
  // ---------------------------------------------------------------------
  const int32_t l1_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, State.L1Pointer));
  const int32_t l1mask_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, State.L1Mask));

  auto MissLabel = PPC64Emitter::Label{};

  ld(TMP2, l1_off, STATE);       // TMP2 = L1Pointer
  ld(TMP3, l1mask_off, STATE);   // TMP3 = L1Mask (pre-scaled)
  sldi(TMP4, RIPReg, 4);         // log2(sizeof(LookupCacheEntry)) == 4
  and_(TMP4, TMP4, TMP3);
  add(TMP2, TMP2, TMP4);         // TMP2 = &L1[hash]

  ld(TMP4, 8, TMP2);             // TMP4 = GuestCode (the "key"), loaded FIRST
  if (CTX->Config.Is64BitMode()) {
    cmpd(cr(7), TMP4, RIPReg);
  } else {
    // 32-bit guest: compare only the low 32 so a publisher that left junk in
    // the upper half cannot force a spurious miss. Matches the dispatcher.
    cmpw(cr(7), TMP4, RIPReg);
  }
  // BO=4 (branch if false), BI=30 (CR7.EQ at PPC bit 4*7+2). i.e. bne cr7.
  bc({4, 30}, &MissLabel);

  // Hit. Carry the GuestCode value into the HostCode load's address so the
  // hardware cannot hoist it above the GuestCode load and observe
  // {stale HostCode, new GuestCode} mid-Publish. TMP3 is 0 by construction.
  // Same one-instruction fold as the dispatcher's match_label leg: the data
  // dependency rides ldx's index operand (TMP3 == 0), preserving the
  // load-load ordering the comment above requires.
  xor_(TMP3, TMP4, TMP4);
  ldx(TMP3, TMP2, TMP3);         // TMP3 = HostCode (loaded under address-dep)
  mtctr(TMP3);
  if (!Linkable) {
    // P5.0.1: store the destination RIP into State.rip on the hit leg too.
    // Rationale: RestoreRIPFromHostPC's fallback (Frame->State.rip) is invoked
    // whenever a JIT block has no per-instruction RIP entries or the host PC
    // sits outside a header'd block; without this store the fallback returns
    // whatever the last L1 *miss* stored, which can be arbitrarily stale.
    // Symptom (silent): guest signal frames carry wrong-but-plausible RIPs and
    // sigreturn resumes at the wrong address. 1 instruction on a 14-instruction
    // leg. Reviewed against Power ISA v3.0B — safe placement here (RIPReg is
    // still live; no dependency on TMP1-TMP4 that could be misordered).
    std(RIPReg, rip_off, STATE);
    // P5.0.2: reset r0 to 0 before the bctr. JIT blocks emit X-form indexed
    // memory ops with r0 in the rB slot (ldx/stdx and friends), which read r0
    // as its actual value (not literal zero — the "r0 reads as zero" rule
    // applies only to rA). A nonzero r0 silently offsets every load/store in
    // the target block. Every mflr(r0) in the backend today is paired with a
    // restore, so no bug is visible — but the invariant is currently globally
    // assumed, and the failure mode is silent guest memory corruption. Make
    // the local guarantee explicit for 1 extra instruction on this hot leg.
    li(r(0), 0);
  }
  // Linkable exits hoisted both of the above ABOVE the patch site: a linked
  // branch replaces the probe's first instruction, so anything after it on
  // this leg would be skipped by linked callers (P5.0.2's failure mode is
  // silent guest memory corruption — see the hoist comment up top).
  bctr();

  // ---------------------------------------------------------------------
  // Miss. This is where the spill lives now.
  //
  // It is RELOCATED, not deleted. SignalDelegator's SIGNAL_FOR_PAUSE (and
  // Stop) handling gates only on IsAddressInCodeBuffer, which excludes the
  // dispatcher's separate mmap — so a dispatcher PC always takes the
  // "non-jit, SRA is already spilled" branch and reads guest state that only
  // a completed spill makes valid. (The LOGMAN_THROW_A_FMT that would catch a
  // dispatcher PC there is inside #if ASSERTIONS_ENABLED and inert in
  // Release, and the async-signal deferral does not cover it because
  // PauseHandler is a host handler.) Spilling here, inside the code buffer
  // and before the branch out, keeps IsAddressInCodeBuffer a valid proxy and
  // needs no signal-delegator change.
  //
  // Extending the delegator to IsAddressInDispatcher instead would be
  // actively unsafe: ExitFunctionLinker continues past a bctrl, after which
  // r7-r12 (SRA-mapped, ELFv2-volatile) hold garbage.
  //
  // Correspondingly, Pointers.ExitFunctionLinker no longer spills; the
  // dispatcher's own L1 miss branches to a second, SRA-spilling entry.
  // ---------------------------------------------------------------------
  Bind(&MissLabel);
  if (!Linkable) {
    std(RIPReg, rip_off, STATE); // BEFORE the spill clobbers TMP1-TMP4
  }
  SpillStaticRegs(TMP1);

  if (Linkable) {
    // Linkable miss leg: State.rip was already stored by the hoisted region.
    // Branch to this exit's jump thunk LinkPath (emitted at the tail of
    // CompileCode), which PC-discovers the adjacent PPC64BlockLinkRecord and
    // enters the dispatcher's ExitFunctionLinkerWithRecord stub with
    // r4 = &record. That path compiles/looks up the target AND backpatches
    // the probe above; it dispatches exactly like ExitFunctionLinker
    // otherwise (deferred-signal guard, FillStaticRegs, bctr).
    b(LinkPathLabel);
  } else {
    const int32_t exit_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, Pointers.ExitFunctionLinker));
    ld(TMP1, exit_off, STATE);
    mtctr(TMP1);
    bctr();
  }
}

DEF_OP(Jump) {
  auto Op = IROp->C<IR::IROp_Jump>();
  auto Target = JumpTarget(Op->TargetBlock);
  // A bound label means the target block was already emitted, i.e. this is a
  // backward edge -- a potential guest loop that must pass a deferred-signal
  // drain point (see EmitSuspendInterruptCheck).
  if (Target->bound) {
    EmitSuspendInterruptCheck();
  }
  b(Target);
}

DEF_OP(CondJump) {
  auto Op = IROp->C<IR::IROp_CondJump>();

  // PPC `bc` has a signed 14-bit displacement (±32KB). Block-to-block jumps
  // can easily exceed that, so emit the canonical long-conditional idiom:
  // `bc !cond, skip; b TrueBlock; skip: b FalseBlock`. Both `b` insns have
  // a 24-bit displacement (±32MB), well past any single-function code size.
  Cond CC;
  if (Op->VCmpElementSize != IR::OpSize::iInvalid) {
    // Vector-compare branch (glibc vector-scan fusion; see
    // docs/VCMPEQ_FUSION_DESIGN.md and HostFeatures::SupportsVCmpFlagBranch).
    // Cmp1/Cmp2 are FPR-class here, NOT GPRs.
    //
    // The record form of the VMX integer compares writes CR field 6:
    //   CR6 bit 0 (CR bit 24) = every lane compared equal
    //   CR6 bit 2 (CR bit 26) = NO lane compared equal
    // so a single `bc` on CR bit 26 answers "did any lane match" with the lane
    // mask never leaving the vector unit. VTMP1 absorbs the (unused) VRT.
    //
    //   Cond == NEQ -> TrueBlock when ANY lane matched  -> CR6[2] clear -> BO=4
    //   Cond == EQ  -> TrueBlock when NO  lane matched  -> CR6[2] set   -> BO=12
    const auto V1 = GetVReg(Op->Cmp1);
    const auto V2 = GetVReg(Op->Cmp2);
    switch (Op->VCmpElementSize) {
    case IR::OpSize::i8Bit: vcmpequb_(VTMP1, V1, V2); break;
    case IR::OpSize::i16Bit: vcmpequh_(VTMP1, V1, V2); break;
    case IR::OpSize::i32Bit: vcmpequw_(VTMP1, V1, V2); break;
    case IR::OpSize::i64Bit: vcmpequd_(VTMP1, V1, V2); break;
    default: LOGMAN_MSG_A_FMT("CondJump: unhandled VCmpElementSize {}", static_cast<uint32_t>(Op->VCmpElementSize)); break;
    }
    LOGMAN_THROW_A_FMT(Op->Cond == IR::CondClass::NEQ || Op->Cond == IR::CondClass::EQ,
                       "CondJump vector-compare mode only encodes EQ/NEQ over 'any lane matched'");
    // BI 26 = CR6's "none matched" bit (CR field 6 occupies CR bits 24..27).
    CC = (Op->Cond == IR::CondClass::NEQ) ? Cond {4, 26} : Cond {12, 26};
  } else if (Op->FromNZCV) {
    CC = MapNZCVCC(Op->Cond);
  } else if (Op->Cond == IR::CondClass::TSTZ || Op->Cond == IR::CondClass::TSTNZ) {
    // Bit-test branch: Cmp2 is an inline constant giving the bit POSITION
    // (0..63), not a mask. TSTZ jumps if bit clear, TSTNZ if bit set.
    // Extract the bit and compare against zero via cr7, so we don't disturb
    // CR0 — downstream IR ops (e.g. a CondJumpNZCV in the very next block
    // produced by x86 `jp; je`) consume CR0 as the AXFlag/NZCV side-channel,
    // and clobbering CR0 here would silently corrupt them.
    //
    // (This is the same invariant honored by DEF_OP(Parity), which uses
    //  rldicl (no Rc) rather than andi. for exactly this reason — see
    //  ALUOps.cpp::Parity.)
    uint64_t Bit;
    LOGMAN_THROW_A_FMT(IsInlineConstant(Op->Cmp2, &Bit) && Bit < 64,
                       "CondJump TSTZ/TSTNZ: expected inline-constant bit < 64");
    auto Reg = GetReg(Op->Cmp1);
    uint32_t sh = (64u - static_cast<uint32_t>(Bit)) & 63u;
    rldicl(TMP1, Reg, sh, 63);          // TMP1 = (Reg >> Bit) & 1 (no Rc, CR untouched)
    cmpldi(cr(7), TMP1, 0);             // cr7 = (TMP1 == 0)
    // bc BI = cr7*4 + EQ_bit(2) = 30. BO=12 → take when EQ set; BO=4 → when clear.
    CC = (Op->Cond == IR::CondClass::TSTNZ) ? Cond{4, 30} : Cond{12, 30};
  } else {
    // Route the compare through cr(7) so we don't disturb CR0 / XER.
    // CR0 carries packed-NZCV N/Z bits filled by FillStaticRegs at block
    // entry (and consumed by downstream FromNZCV CondJump / NZCVSelect
    // ops). Under CONFIG_SMC_FULL the SMC IR pass emits a non-FromNZCV
    // CondJump (on the ValidateCode result) right before the actual x86
    // instruction body — clobbering CR0 here cascades into wrong-direction
    // x86 conditional jumps. (See SelfModifyingCode/Delinking under
    // SMC_FULL: cmp/jg + cmp/je fall the wrong way because CR0 held the
    // validate compare's eq/lt outcome rather than the guest cmp result.)
    EmitCompare(Op->Cond, Op->CompareSize, Op->Cmp1, Op->Cmp2, /*CRField=*/7);
    CC = MapCC(Op->Cond);
    // MapCC returns a Cond with BI numbered against CR0 (BI in 0..3).
    // Shift to the equivalent CR7 bit positions (BI in 28..31).
    CC = {CC.BO, static_cast<uint8_t>(CC.BI + 28)};
  }
  Label Skip;
  bc(InvertCond(CC), &Skip);
  // Backward edges (bound labels) must pass a deferred-signal drain point;
  // see DEF_OP(Jump). Each leg pokes independently so the forward leg stays
  // poke-free.
  auto TrueTarget = JumpTarget(Op->TrueBlock);
  if (TrueTarget->bound) {
    EmitSuspendInterruptCheck();
  }
  b(TrueTarget);
  Bind(&Skip);
  auto FalseTarget = JumpTarget(Op->FalseBlock);
  if (FalseTarget->bound) {
    EmitSuspendInterruptCheck();
  }
  b(FalseTarget);
}

DEF_OP(Break) {
  auto Op = IROp->C<IR::IROp_Break>();
  ResetStack();

  // Pack the fault data into a single 64-bit value and store it
  FEXCore::Core::CpuStateFrame::SynchronousFaultDataStruct FaultData = {
    .FaultToTopAndGeneratedException = 1,
    .Signal    = Op->Reason.Signal,
    .TrapNo    = Op->Reason.TrapNumber,
    .si_code   = Op->Reason.si_code,
    .err_code  = Op->Reason.ErrorRegister,
  };
  uint64_t Constant = 0;
  memcpy(&Constant, &FaultData, sizeof(FaultData));

  LoadConstant(TMP2, Constant);
  int32_t fault_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, SynchronousFaultData));
  std(TMP2, fault_off, STATE);

  // Spill SRA before calling signal handler
  SpillStaticRegs(TMP1);

  // Jump to the appropriate guest signal handler pointer
  int32_t sig_off;
  switch (Op->Reason.Signal) {
  case FEXCore::Core::FAULT_SIGILL:
    sig_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, Pointers.GuestSignal_SIGILL));
    break;
  case FEXCore::Core::FAULT_SIGTRAP:
    sig_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, Pointers.GuestSignal_SIGTRAP));
    break;
  case FEXCore::Core::FAULT_SIGSEGV:
    sig_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, Pointers.GuestSignal_SIGSEGV));
    break;
  default:
    sig_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, Pointers.GuestSignal_SIGTRAP));
    break;
  }
  ld(TMP1, sig_off, STATE);
  mtctr(TMP1);
  bctr();
}

DEF_OP(Syscall) {
  auto Op = IROp->C<IR::IROp_Syscall>();

  // Spill SRA to STATE (physical registers retain their values for arg reads below).
  SpillStaticRegs(TMP1);

  // Mark that we are inside the JIT-emitted Syscall op. The signal handler
  // path in HandleDispatcherGuestSignal reads (InSyscallInfo & 0xFFFF) as the
  // SpillSRA IgnoreMask — bits 0..15 each represent one already-spilled SRA
  // GPR. PPC64LE's x64-mode SRA has 16 GPRs, all spilled by the call above,
  // so we set 0xFFFF. Mirrors ARM64 backend at JIT/BranchOps.cpp:277-278.
  // Without this, an async signal arriving between SpillStaticRegs and
  // FillStaticRegs causes the handler to re-spill from post-bctrl volatile
  // registers, overwriting the freshly-stored gregs[RAX] with junk.
  {
    const int32_t isi_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, InSyscallInfo));
    LoadConstant(TMP1, 0xFFFFu);
    std(TMP1, static_cast<int16_t>(isi_off), STATE);
  }

  // Create a mini-frame for the C call.  Layout (16-byte aligned):
  //   [r1+  0]:                back chain (old r1)
  //   [r1+  8..31]:            ELFv2 linkage area (CR/LR/TOC save for HandleSyscall)
  //   [r1+ 32..95]:            ELFv2 parameter save area (8 doublewords, callee-scratch)
  //   [r1+ 96..151]:           SyscallArguments (7 × 8 = 56 bytes)
  //   [r1+152..159]:           padding
  //   [r1+160..]:              volatile dynamic-FPR save area (see below):
  //                            4 × 16 = 64 bytes in x64 mode  -> frame 224
  //                            12 × 16 = 192 bytes in x32 mode -> frame 352
  //
  // SyscallArguments MUST live above the 96-byte ELFv2 linkage+param block:
  // the parameter save area is defined by ELFv2 §2.2.2 as callee-scratch --
  // HandleSyscall or any of its transitive callees can overwrite [r1+32..95]
  // freely, so putting SyscallArguments there and handing HandleSyscall an
  // r5 pointer into it was a data hazard. Move the SSA-source pack to +96
  // and grow the frame to 160B to keep 16B alignment.
  //
  // ---- Volatile dynamic-FPR save area ----------------------------------
  // This op spills STATIC registers only, and on Linux `syscall` is NOT
  // block-end (X86Tables.h:409-414 adds FLAGS_BLOCK_END on _WIN32 only), so
  // JIT-internal vector SSA values are routinely live across the bctrl. The
  // named-vector-constant cache is per-BLOCK and survives FlushRegisterCache
  // (OpcodeDispatcher.h:2288, sole clear at :167 on block reset), and such
  // values are never rematerialised (RegisterAllocationPass.cpp:126-128 --
  // only OP_CONSTANT is). The allocator hands out the lowest free index
  // (:479), i.e. RAFPR[0] = v16 in x64 and v8 in x32, and both are
  // ELFv2-volatile. So the first FPR value allocated in a block was being
  // silently destroyed by any syscall in that block.
  //
  // Guest XMM state was never at risk -- SRAFPR is spilled by
  // SpillStaticRegs. The exposure is JIT-internal temporaries, which is why
  // it presented as rare non-deterministic wrong results rather than as a
  // reproducible failure.
  //
  // Saved into this op's OWN mini-frame rather than via PushDynamicRegs:
  // that helper would pay a second stdu and a second 96-byte linkage
  // reservation on top of the one already reserved here, and would save the
  // non-volatile half of the pool for nothing. The loop is driven off
  // RAFPRVolatile so there is still exactly one list; the static_asserts in
  // ArchHelpers/PPC64Emitter.h are what keep that list in step with RAFPR.
  //
  // The dynamic GPR pool needs no equivalent: RA is r24-r26/r30-r31 (x64) and
  // r16-r26/r30-r31 (x32), all ELFv2 callee-saved. Asserted in the header.
  //
  // Signal safety is unchanged: these are IR SSA temporaries, not guest
  // state, so SpillSRA never reads them. On an abandon/restart path the
  // restore below simply does not run, exactly as before.
  static_assert(FEXCore::HLE::SyscallArguments::MAX_ARGS == 7);

  constexpr int kFPRSaveOff = 160;
  const auto RAFPRVolatile = CTX->Config.Is64BitMode()
                               ? std::span<const VR>(x64::RAFPRVolatile)
                               : std::span<const VR>(x32::RAFPRVolatile);
  const int16_t FrameSize =
    static_cast<int16_t>(kFPRSaveOff + RAFPRVolatile.size() * 16);

  stdu(r1, static_cast<int16_t>(-FrameSize), r1);

  // Save the volatile dynamic FPRs. r1 is 16-byte aligned per ELFv2 and every
  // offset is a multiple of 16, so stvx's address masking is a no-op.
  for (size_t i = 0; i < RAFPRVolatile.size(); ++i) {
    LoadImm32(TMP1, static_cast<uint32_t>(kFPRSaveOff + i * 16));
    stvx(RAFPRVolatile[i], r1, TMP1);
  }

  // Fill SyscallArguments from the IR op's source nodes.
  // After SpillStaticRegs the physical SRA registers still hold the live values.
  for (uint32_t i = 0; i < FEXCore::HLE::SyscallArguments::MAX_ARGS; ++i) {
    if (Op->Header.Args[i].IsInvalid()) continue;
    const int16_t slot_off = static_cast<int16_t>(96 + i * 8);
    uint64_t Const;
    if (IsInlineConstant(Op->Header.Args[i], &Const)) {
      LoadConstant(TMP1, Const);
      std(TMP1, slot_off, r1);
    } else {
      std(GetReg(Op->Header.Args[i]), slot_off, r1);
    }
  }

  // Call: SyscallHandler::HandleSyscall(this, Frame*, SyscallArguments*)
  //   r3 = SyscallHandlerObj (this)
  //   r4 = Frame* (CpuStateFrame*)
  //   r5 = SyscallArguments* (at [r1+96])
  //   r12 = callee address (ELFv2 indirect-call requirement)
  {
    const int32_t obj_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, Pointers.SyscallHandlerObj));
    const int32_t fn_off  = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, Pointers.SyscallHandlerFunc));

    ld(r3,    obj_off, STATE);   // r3  = this
    ld(r(12), fn_off,  STATE);   // r12 = fn ptr
    mr(r4, STATE);               // r4  = Frame
    addi(r5, r1, 96);            // r5  = &SyscallArguments
  }

  std(r2, 24, r1);     // save TOC (ELFv2 linkage area, unchanged offset)
  mtctr(r(12));
  bctrl();
  ld(r2, 24, r1);      // restore TOC

  // HandleSyscall returns the new guest RAX value in r3.
  {
    const int32_t rax_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame,
               State.gregs[FEXCore::X86State::REG_RAX]));
    std(r3, rax_off, STATE);
  }

  // Mirror ARM64 (JIT/BranchOps.cpp:319-323): write the syscall result to
  // the IR destination SSA reg so consumers reading the edge directly (not
  // via _LoadRegister(RAX)) get the right value. Must happen BEFORE
  // FillStaticRegs because that helper uses TMP1=r3 as scratch and will
  // clobber the return value. GetReg(Node) is in the dynamic RA pool
  // (r24-r26, r30-r31), all callee-saved per ELFv2, so it survives
  // everything that follows.
  mr(GetReg(Node), r3);

  // Restore the volatile dynamic FPRs. Deliberately after both consumers of
  // r3 above, because the loop uses TMP1 (= r3) to form the index.
  for (size_t i = 0; i < RAFPRVolatile.size(); ++i) {
    LoadImm32(TMP1, static_cast<uint32_t>(kFPRSaveOff + i * 16));
    lvx(RAFPRVolatile[i], r1, TMP1);
  }

  // Free the mini-frame, then reload SRA from STATE (picks up the RAX result).
  addi(r1, r1, FrameSize);
  FillStaticRegs();
  // HandleSyscall is a host C function; r0 was clobbered. Restore the JIT's
  // r0=0 zero-index invariant before falling back into JIT code that uses
  // ldx/stdx.
  li(r(0), 0);

  // Clear InSyscallInfo. From here onward the JIT-emitted Syscall op is
  // done; any signal arriving treats this code as normal JIT and the full
  // SRA spill path is correct again.
  {
    const int32_t isi_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, InSyscallInfo));
    li(TMP1, 0);
    std(TMP1, static_cast<int16_t>(isi_off), STATE);
  }
}

DEF_OP(Thunk) {
  // ELFv2 ABI: r3 = ArgPtr (void* to guest argument data), thunk function
  // pointer in TMP2=r4. ArgPtr comes from an SRA register (guest GPR) so it
  // survives SpillStaticRegs (which only COPIES SRA regs to ctx; the physical
  // registers retain their values until PushDynamicRegs overwrites them).
  auto Op = IROp->C<IR::IROp_Thunk>();

  SpillForABICall(TMP1);

  // Set up the single argument: ArgPtr in r3
  mr(r3, GetReg(Op->ArgPtr));

  // Load thunk function address into TMP2; record relocation for cache patching
  InsertNamedThunkRelocation(TMP2, Op->ThunkNameHash);

  // Call: set r12 = callee GEP per ELFv2, then branch via CTR.
  //
  // The thunk callee lives in a *different* DSO (libGL-host.so etc), so it is
  // entered at its global entry point, overwrites r2 with its own TOC, and
  // returns with r2 changed. ELFv2 (OpenPOWER 64-bit ELF V2 ABI 2.2.1.1)
  // makes the *caller* responsible for preserving r2 across a call through a
  // function pointer. Same idiom as DEF_OP(Syscall) above. r1 has already
  // been lowered by SpillForABICall -> PushDynamicRegs, and kDynGPRStart ==
  // kDynLinkArea == 96, so [r1+24] is this frame's own (unused) linkage-area
  // TOC doubleword.
  mr(r(12), TMP2);
  std(r2, 24, r1);     // save TOC (ELFv2 linkage area, unchanged offset)
  mtctr(TMP2);
  bctrl();
  ld(r2, 24, r1);      // restore TOC

  FillForABICall();
}

} // namespace FEXCore::CPU
