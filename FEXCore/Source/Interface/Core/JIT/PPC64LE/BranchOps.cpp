// SPDX-License-Identifier: MIT
// PPC64LE branch/control-flow operations for FEX JIT backend.
#include "Interface/Context/Context.h"
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/JIT/PPC64LE/JITClass.h"

#include <bit>
#include <cstdlib>

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
// BLOCK LINKING (constant-target exits, BlockLinking knob).
//
// When BlockLinkingEnabled and this exit has a constant target RIP —
// Hint == None (plain jumps) or Hint == Call (guest CALL, whose target is a
// constant and whose x86 return address is an EntrypointOffset constant the
// guest pushed to ITS stack, entirely independent of host control flow) —
// the exit is reordered so the WHOLE L1 probe becomes the patch target.
//
// Calls were HISTORICALLY excluded by an objection about patching to `bl`:
// that would push the probe's second instruction onto the hardware link
// stack while the architectural return goes elsewhere, mispredicting every
// call/ret pair. But the linker below never emits `bl` — it patches a plain
// `b` (or `b Thunk`), creating no link-stack entry, and a 2026-08-05 storm
// profile put the unlinked path (ExitFunctionLink->FindBlock) at 4.1% of
// CPU in a call-dense Mono workload, so the exclusion cost real time for a
// hazard the mechanism doesn't have. The backend consults Hint nowhere else
// (verified by audit), and linked targets land on the callee's EntryPoint
// prologue, whose deferred-signal drain is hint-agnostic.
//
// Still excluded: Return (dynamic target — nothing constant to link) and
// CheckTF (must reach the dispatcher's trap check every time). A shadow
// return stack for the Return side is the remaining, genuinely
// design-heavy half.
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
  // Shadow return stack (FEX_SHADOWRETSTACK). See JITClass.h, the
  // resolution+interlock in JIT.cpp, and the CallReturnEntryLabels bind in
  // CompileCode's block loop.
  //
  // RET pop: peek the top {guest_ret_rip, host_trampoline}; if the recorded
  // guest RIP equals this RET's target, branch straight to the trampoline
  // (which re-enters the return block at its L1-hit landing), skipping the L1
  // probe. The pop is unconditional (mirrors the stack discipline): a mismatch,
  // an empty stack, or any prior invalidation just falls through to the probe,
  // which is the correctness net.
  //
  // CALL push: record {guest_ret_rip, &trampoline} so a matching RET can take
  // the fast path. Emitted BEFORE the existing (possibly linkable) exit to the
  // callee, which is left byte-for-byte unchanged.
  //
  // Discipline: every compare targets cr7 with a no-Rc form, so CR0's packed
  // NZCV and XER reach the target block / the miss-leg spill exactly as the
  // block left them (identical to the L1 probe below). r0 is rewritten (to 0)
  // only on the taken RET fast path, immediately before the bctr, preserving
  // the X-form zero-index invariant. The bounds are read per-op from the
  // frame's callret_base/callret_end mirrors (CoreState.h) — the code buffer
  // is shared across threads so they cannot be immediates, and the mirrors
  // replace the former Frame->Thread->CallRetStackBase two-load pointer chase
  // (+addis for base+SIZE) with one D-form ld off STATE; callret_end shares
  // callret_sp's cache line for the pop. Both mirrors are set at thread
  // creation next to callret_sp and never change (base is immutable until
  // thread teardown). [base, base+SIZE) is exactly the R/W region between the
  // frontend's two guard pages, so the bounds checks never fault. Overflow
  // (push) resets to empty and skips the store; empty (pop) skips the fast
  // path; neither ever corrupts memory. Threads without a frontend-allocated
  // call-ret stack carry zero mirrors: pops read sp(0) >= end(0) -> empty,
  // pushes see new sp(-16) < base(0) -> overflow reset, never storing.
  // ---------------------------------------------------------------------
  PPC64Emitter::Label ShadowRetReprobe{};
  const bool ShadowActive = ShadowRetStackEnabled &&
    (Op->Hint == IR::BranchHint::Return || Op->Hint == IR::BranchHint::Call);
  if (ShadowActive) {
    const int16_t sp_off = static_cast<int16_t>(
      offsetof(FEXCore::Core::CpuStateFrame, State.callret_sp));
    const int16_t base_off = static_cast<int16_t>(
      offsetof(FEXCore::Core::CpuStateFrame, State.callret_base));
    const int16_t end_off = static_cast<int16_t>(
      offsetof(FEXCore::Core::CpuStateFrame, State.callret_end));

    if (Op->Hint == IR::BranchHint::Return) {
      ld(TMP2, sp_off, STATE);            // TMP2 = sp
      ld(TMP3, end_off, STATE);           // TMP3 = base + SIZE (empty / top guard)
      cmpd(cr(7), TMP2, TMP3);
      bc({4, 28}, &ShadowRetReprobe);     // sp >= base+SIZE -> empty -> probe
      ld(TMP3, 0, TMP2);                  // TMP3 = guest_ret_rip (top slot)
      if (CTX->Config.Is64BitMode()) {
        cmpd(cr(7), TMP3, RIPReg);
      } else {
        cmpw(cr(7), TMP3, RIPReg);        // 32-bit guest: compare low 32 only
      }
      addi(TMP2, TMP2, 16);               // pop (unconditional, mirrors ARM64)
      std(TMP2, sp_off, STATE);
      bc({4, 30}, &ShadowRetReprobe);     // guest_ret_rip != target -> probe
      ld(TMP3, -8, TMP2);                 // TMP3 = host trampoline (== old sp + 8)
      std(RIPReg, rip_off, STATE);        // P5.0.1: store rip before the jump
      mtctr(TMP3);
      li(r(0), 0);                        // P5.0.2: restore zero-index invariant
      bctr();
      // Empty / mismatch fall through into the unchanged L1 probe (ShadowRetReprobe).
    } else {
      // BranchHint::Call push.
      const GPR HostPtr = TMP2;           // host trampoline pointer (0 if no in-buffer return block)
      if (!Op->CallReturnBlock.IsInvalid()) {
        // host trampoline = &l_cont, discovered PC-relatively so it is
        // position-independent and needs no relocation across code-cache
        // save/load. Fixed 3-instruction layout after mflr keeps the addi
        // delta a hard constant (= 12 bytes, {mflr, addi, b}):
        //     bcl 20,31,$+4 ; mflr TMP2      TMP2 = &mflr  (LK form: no link-stack push)
        //     addi TMP2, TMP2, 12            TMP2 = &l_cont
        //     b l_skip                       jump over the 1-insn trampoline
        //   l_cont: b CallReturnEntryLabels[return-block]
        //   l_skip:
        PPC64Emitter::Label l_skip{};
        const uint32_t CRBID = IR->GetOp<IR::IROp_CodeBlock>(Op->CallReturnBlock)->ID;
        bcl(20, 31, 4);
        mflr(TMP2);
        addi(TMP2, TMP2, 12);
        b(&l_skip);
        b(&CallReturnEntryLabels[CRBID]); // l_cont trampoline (reached only via a matching RET)
        Bind(&l_skip);
      } else {
        li(TMP2, 0);                      // no return block: push a zero entry (never matches)
      }
      ld(TMP3, sp_off, STATE);            // TMP3 = sp
      ld(TMP4, base_off, STATE);          // TMP4 = base (frame mirror)
      addi(TMP3, TMP3, -16);              // TMP3 = new sp
      cmpd(cr(7), TMP3, TMP4);
      PPC64Emitter::Label l_do_push{}, l_push_done{};
      bc({4, 28}, &l_do_push);            // new sp >= base -> room to push
      // Overflow: reset to empty (base+SIZE, read from the end mirror), skip
      // the store, never write below the low guard page.
      ld(TMP4, end_off, STATE);
      std(TMP4, sp_off, STATE);
      b(&l_push_done);
      Bind(&l_do_push);
      if (!Op->CallReturnBlock.IsInvalid()) {
        std(GetReg(Op->CallReturnAddress), 0, TMP3); // slot0 = guest_ret_rip
      } else {
        std(HostPtr, 0, TMP3);            // slot0 = 0
      }
      std(HostPtr, 8, TMP3);              // slot8 = host trampoline (0 if invalid)
      std(TMP3, sp_off, STATE);           // callret_sp = new sp
      Bind(&l_push_done);
      // Fall through to the existing exit (linkable hoist + L1 probe to callee);
      // RIPReg (= TMP1 for const targets) was deliberately left untouched.
    }
  }

  // ---------------------------------------------------------------------
  // Block-linking hoist + patch-site registration (see header comment).
  // Only for constant-target plain jumps with the knob on; every other exit
  // shape keeps the exact non-linking lowering below.
  // ---------------------------------------------------------------------
  // Plain jumps link whenever BlockLinkingEnabled. CALL exits additionally
  // require CallLinkingEnabled (= BlockLinkingEnabled && !LazyLinkArmed):
  // under FEX_SMCLAZYLINK the SMC scrub severs links constantly, and call-
  // dense guests (32-bit Mono/Unity — Dex) then flood ExitFunctionLinkWith
  // Record with relink-and-recompile on every call, a compile storm that
  // throttles guest execution (measured on Dex load 2026-08-05). Under lazy
  // linking, calls take the fast rldic L1 probe instead; the call-linking win
  // is retained only where links actually stick (non-lazy configs).
  const bool Linkable = ConstRIP &&
    ((Op->Hint == IR::BranchHint::None && BlockLinkingEnabled) ||
     (Op->Hint == IR::BranchHint::Call && CallLinkingEnabled));
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

  // A shadow RET that found an empty stack or a mismatched top re-enters the
  // normal lookup here, so the fast path degrades to exactly the L1-probe
  // behaviour on any miss.
  if (ShadowActive && Op->Hint == IR::BranchHint::Return) {
    Bind(&ShadowRetReprobe);
  }

  ld(TMP2, l1_off, STATE);       // TMP2 = L1Pointer
  if (!FEXCore::Config::Get_DYNAMICL1CACHE()) {
    // Static L1: constant-mask probe, one rldic instead of L1Mask load +
    // sldi + and_. Same derivation as the dispatcher's DispatcherLoopTop.
    static_assert((FEXCore::LookupCache::MAX_L1_ENTRIES & (FEXCore::LookupCache::MAX_L1_ENTRIES - 1)) == 0,
                  "rldic probe requires a power-of-two L1");
    constexpr uint32_t L1MB = 64 - (std::countr_zero(FEXCore::LookupCache::MAX_L1_ENTRIES) + 4);
    rldic(TMP4, RIPReg, 4, L1MB);
  } else {
    ld(TMP3, l1mask_off, STATE);   // TMP3 = L1Mask (pre-scaled)
    sldi(TMP4, RIPReg, 4);         // log2(sizeof(LookupCacheEntry)) == 4
    and_(TMP4, TMP4, TMP3);
  }
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
  if (Linkable) {
    // Linkable miss leg: State.rip was already stored by the hoisted region.
    // Branch to this exit's jump thunk LinkPath (emitted at the tail of
    // CompileCode), which PC-discovers the adjacent PPC64BlockLinkRecord into
    // TMP2 and tail-branches to the shared SpillStaticRegs stub
    // (SharedSpillLinkLabel — SpillStaticRegs preserves TMP2 through f0, so
    // &record survives it), which then enters the dispatcher's
    // ExitFunctionLinkerWithRecord stub with r4 = &record and SRA spilled.
    // That path compiles/looks up the target AND backpatches the probe above;
    // it dispatches exactly like ExitFunctionLinker otherwise (deferred-signal
    // guard, FillStaticRegs, bctr).
    b(LinkPathLabel);
  } else {
    std(RIPReg, rip_off, STATE); // BEFORE the shared stub's spill clobbers TMP1-TMP4
    // Shared per-compile-unit spill stub (CompileCode tail): SpillStaticRegs +
    // dispatch to Pointers.ExitFunctionLinker. Replaces ~90 inline cold
    // instructions per exit with this one branch; see SharedSpillExitLabel.
    SharedSpillExitUsed = true;
    b(&SharedSpillExitLabel);
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
  // Spin-loop SMT priority hint for this edge, if AnalyzeSpinLoops marked it.
  EmitSpinEdgeHint(Op->TargetBlock);
  // Fallthrough elision: the target is the next emitted block (necessarily
  // forward/unbound, so the suspend poke above did not run and must not).
  // See FallthroughBlockID in JITClass.h; EndBlock after this op is a no-op.
  if (IR->GetOp<IR::IROp_CodeBlock>(Op->TargetBlock)->ID == FallthroughBlockID) {
    return;
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
  } else if (IsSpinCollapseBranch(Node)) {
    // FEX_SPINCOLLAPSE (contract at kSpinCollapseK, JITClass.h): the spin
    // backedge of a matched counted-decrement pair whose Sub now retires K
    // budget per iteration. Exit exactly when the batched decrement lands on
    // 0, i.e. keep spinning iff old > K. Compare signedness follows the
    // matched idiom: NEQ-1 (`dec; jne`) budgets are canonicalized
    // zero-extended values — unsigned cmpldi, worst case is exiting early;
    // SGT-0 (`test; jg` — CP2077's redDispatcher worker loop) must use the
    // SIGNED cmpdi so a negative value exits like the original branch would,
    // where `>u K` would read it as huge and spin forever. cr7, no Rc.
    if (IsSpinCollapseBranchSigned(Node)) {
      cmpdi(cr(7), GetReg(Op->Cmp1), static_cast<int16_t>(kSpinCollapseK));
    } else {
      cmpldi(cr(7), GetReg(Op->Cmp1), kSpinCollapseK);
    }
    // BO=12 (branch if set), BI=29 (cr7.GT): TrueBlock (the backedge) taken
    // while old > K.
    CC = {12, 29};
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
  const uint32_t TrueID = IR->GetOp<IR::IROp_CodeBlock>(Op->TrueBlock)->ID;
  const uint32_t FalseID = IR->GetOp<IR::IROp_CodeBlock>(Op->FalseBlock)->ID;

  // Fallthrough elision (see FallthroughBlockID in JITClass.h). A fallthrough
  // target is by construction the next emitted block: forward, unbound, so
  // the backward-edge suspend poke never applies to an elided leg.
  //
  // TrueBlock is the fallthrough: flip the legs. Take the bc on CC (not the
  // inversion) over the false leg, and fall into TrueBlock. The false leg
  // keeps its own poke/hint discipline. (TrueID == FalseID degenerates to
  // the generic shape below; both cannot be elided.)
  if (TrueID == FallthroughBlockID && FalseID != TrueID) {
    Label TakeFall;
    bc(CC, &TakeFall);
    auto FalseTarget = JumpTarget(Op->FalseBlock);
    if (FalseTarget->bound) {
      EmitSuspendInterruptCheck();
    }
    EmitSpinEdgeHint(Op->FalseBlock);
    b(FalseTarget);
    Bind(&TakeFall);
    // Hint after the bind so it executes exactly when the true edge is taken.
    EmitSpinEdgeHint(Op->TrueBlock);
    return;
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
  // Spin-loop SMT priority hints, per edge (see AnalyzeSpinLoops). Emitted
  // inside each leg so the hint executes exactly when that edge is taken.
  EmitSpinEdgeHint(Op->TrueBlock);
  b(TrueTarget);
  Bind(&Skip);
  // FalseBlock is the fallthrough: the bc's skip label lands directly on the
  // next block's body.
  if (FalseID == FallthroughBlockID) {
    EmitSpinEdgeHint(Op->FalseBlock);
    return;
  }
  auto FalseTarget = JumpTarget(Op->FalseBlock);
  if (FalseTarget->bound) {
    EmitSuspendInterruptCheck();
  }
  EmitSpinEdgeHint(Op->FalseBlock);
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

// kInSyscallSentinel — the value parked in CpuStateFrame::InSyscallInfo for
// the duration of a JIT host-call crossing — lives in ArchHelpers/
// PPC64Emitter.h with its full bit-layout rationale, now that DEF_OP(Thunk)
// and the FABI bridge stubs (PPC64Dispatcher.cpp GenerateABICall) share it
// with this op via ArmInSyscallSentinel/FillForABICallChecked. This op keeps
// its original inline copy of the check because the elision interleaves with
// the RAX result handling below.

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
  //
  // Bit 24 on top of that mask is a "nobody has touched the guest state
  // behind our back" tripwire, read back by the fill below. See
  // kInSyscallSentinel.
  {
    const int32_t isi_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, InSyscallInfo));
    LoadConstant(TMP1, kInSyscallSentinel);
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
  // non-volatile half of the pool for nothing. The save/restore pair is the
  // FABI-callsite helper (SaveDynVRsToFrame/RestoreDynVRsFromFrame), which
  // honours DynVRSpillMask — CompileCode sets it to this op's RA live-in ∪
  // dest before dispatch, so only vector SSA values actually live across the
  // bctrl are stored (most syscalls touch none). The save area stays sized
  // for the full volatile set; the helper packs saved regs densely from
  // kFPRSaveOff and both loops iterate the same unchanged mask, so they
  // cannot fall out of lockstep.
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

  // Save the live volatile dynamic FPRs (DynVRSpillMask-selected; clobbers
  // TMP3, which nothing here holds live yet). r1 is 16-byte aligned per ELFv2
  // and every offset is a multiple of 16, so stvx's address masking is a
  // no-op.
  SaveDynVRsToFrame(kFPRSaveOff);

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

  // Restore the saved dynamic FPRs under the same (unchanged) DynVRSpillMask.
  // Clobbers TMP3 (= r5, dead since the bctrl); kept after both consumers of
  // r3 above anyway so the ordering stays obviously safe.
  RestoreDynVRsFromFrame(kFPRSaveOff);

  // Free the mini-frame, then reload SRA from STATE (picks up the RAX result).
  addi(r1, r1, FrameSize);

  // ---- Fill elision -----------------------------------------------------
  // SRA slots 6..15 map to r14..r23, which ELFv2 preserves across the bctrl
  // above. Nothing between SpillStaticRegs and here touches them: the arg
  // pack and the result move use the dynamic RA pool (r24-r26/r30-r31 in
  // x64), the call sequence uses r3/r4/r5/r12, and TMP1..TMP4 are r3-r6. So
  // in the common case those ten host registers still hold the live guest
  // values and reloading them from the frame is pure overhead.
  //
  // The uncommon case is a signal: HandleDispatcherGuestSignal / the guest
  // handler / RestoreThreadState can rewrite ANY greg in the frame while the
  // host registers keep their pre-signal contents, so those ten loads are
  // mandatory there. kInSyscallSentinel's bit 24 detects exactly that — it is
  // erased by the uint16_t ContextBackup round trip, so "some bit above 15 is
  // still set" is a sound proof that no signal republished the frame.
  //
  // NOT applied to i686 guests: their fill uses lwz for its zero-extension
  // side effect, which a surviving host register does not provide.
  //
  // NOTE this only elides the *fill*. The spill must stay complete: syscalls
  // that snapshot guest state read it straight out of the frame — e.g.
  // Thread.cpp:103 `TM.CreateThread(0, 0, &Frame->State, ...)` hands the
  // parent's whole CPUState to a new guest thread — and a partial spill would
  // hand them a stale RSI/RDI/R8-R15.
  if (CTX->Config.Is64BitMode()) {
    const int32_t isi_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, InSyscallInfo));
    PPC64Emitter::Label SentinelIntact;
    ld(TMP1, isi_off, STATE);
    // TMP1 = InSyscallInfo >> 16, recording into CR0: EQ iff nothing above
    // bit 15 survived, i.e. iff the frame was republished behind us.
    rldicl_(TMP1, TMP1, 48, 16);
    // BO=4 (branch if false), BI=2 (CR0.EQ) — i.e. bne cr0.
    bc({4, 2}, &SentinelIntact);
    FillStaticRegs(FillMode::NonVolatileGPRsOnly);
    Bind(&SentinelIntact);
    FillStaticRegs(FillMode::SkipNonVolatileGPRs);
  } else {
    FillStaticRegs();
  }
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

  // Sentinel-guarded partial SRA GPR refill, ported from DEF_OP(Syscall)'s
  // fill elision above: the ELFv2 callee cannot touch r14-r23, so the ten
  // non-volatile SRA GPR reloads after the bctrl are pure overhead unless
  // something republished the frame during the call. The sentinel proves the
  // negative: a guest-signal delivery truncates it through the uint16_t
  // ContextBackup stash on either HandleDispatcherGuestSignal branch, and a
  // host->guest callback (thunk callees DO re-enter the guest — X11 event
  // handlers etc.) clears it at the dispatcher's CallbackPtr entry before any
  // callback guest block runs. Both the arm and the checked fill live on
  // PPC64EmitterBase (shared with the FABI bridge stubs); see
  // kInSyscallSentinel in ArchHelpers/PPC64Emitter.h for the full contract.
  // 64-bit guests only — the 32-bit lwz zero-extension invariant forbids
  // partial fills (PPC64Emitter.cpp FillStaticRegs) — and 32-bit keeps
  // today's unarmed full-fill path byte for byte. XMM/VR fills are NEVER
  // elidable: v0-v15 are ELFv2-volatile and the frame copy is also what
  // signal delivery reads mid-call.
  static const bool NoPartialFill = getenv("FEX_NO_THUNK_PARTIAL_FILL") != nullptr;
  const bool PartialFill = CTX->Config.Is64BitMode() && !NoPartialFill;

  SpillForABICall(TMP1);
  if (PartialFill) {
    // Strictly after the spill completes (the mask claims "already
    // spilled"), strictly before the callee can run. Clobbers TMP1 only —
    // the ArgPtr/relocation setup below uses r3/TMP2 after this point.
    ArmInSyscallSentinel();
  }

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

  if (PartialFill) {
    FillForABICallChecked();
  } else {
    FillForABICall();
  }
}

} // namespace FEXCore::CPU
