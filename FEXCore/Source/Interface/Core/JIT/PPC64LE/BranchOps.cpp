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

DEF_OP(ExitFunction) {
  // ORDERING NOTE: when NewRIP is a register (e.g. popped return address from
  // `ret`), it lives in a host GPR allocated by RA. SpillStaticRegs clobbers
  // TMP1/TMP3/TMP4 (and TMP2 inside the NZCV-save block); if RA happened to
  // assign that host reg to NewRIP we'd wipe the return address before storing
  // it. So: snapshot NewRIP into State.rip *first*, then spill.
  auto Op = IROp->C<IR::IROp_ExitFunction>();
  ResetStack();

  int32_t rip_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, State.rip));

  uint64_t NewRIP;
  if (IsInlineConstant(Op->NewRIP, &NewRIP) ||
      IsInlineEntrypointOffset(Op->NewRIP, &NewRIP)) {
    // 32-bit guest: ensure the RIP constant is canonical 32-bit. For inline
    // constants the value was already produced from a 32-bit source so the
    // upper 32 should already be zero, but mask defensively for jumps from
    // RIP-relative computations.
    if (!CTX->Config.Is64BitMode()) {
      NewRIP &= 0xFFFFFFFFull;
    }
    LoadConstant(TMP2, NewRIP);
    std(TMP2, rip_off, STATE);
    SpillStaticRegs(TMP1);
  } else {
    GPR NewRIPReg = GetReg(Op->NewRIP);
    // 32-bit guest: stash a 32-bit-masked RIP into TMP2 first so we don't
    // mutate the SSA-allocated NewRIPReg (which may still be live elsewhere).
    if (!CTX->Config.Is64BitMode()) {
      rldicl(TMP2, NewRIPReg, 0, 32);
      std(TMP2, rip_off, STATE);
    } else {
      std(NewRIPReg, rip_off, STATE);   // save BEFORE spill clobbers temps
    }
    SpillStaticRegs(TMP1);
  }

  // Jump to the dispatcher loop top. After spilling SRA, the dispatcher will
  // look up the new RIP in the lookup cache and dispatch to the target block.
  int32_t loop_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
  ld(TMP1, loop_off, STATE);
  mtctr(TMP1);
  bctr();
}

DEF_OP(Jump) {
  auto Op = IROp->C<IR::IROp_Jump>();
  b(JumpTarget(Op->TargetBlock));
}

DEF_OP(CondJump) {
  auto Op = IROp->C<IR::IROp_CondJump>();

  // PPC `bc` has a signed 14-bit displacement (±32KB). Block-to-block jumps
  // can easily exceed that, so emit the canonical long-conditional idiom:
  // `bc !cond, skip; b TrueBlock; skip: b FalseBlock`. Both `b` insns have
  // a 24-bit displacement (±32MB), well past any single-function code size.
  Cond CC;
  if (Op->FromNZCV) {
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
    EmitCompare(Op->Cond, Op->CompareSize, Op->Cmp1, Op->Cmp2);
    CC = MapCC(Op->Cond);
  }
  Label Skip;
  bc(InvertCond(CC), &Skip);
  b(JumpTarget(Op->TrueBlock));
  Bind(&Skip);
  b(JumpTarget(Op->FalseBlock));
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

  // Create a mini-frame for the C call.  Layout (96 bytes, 16-byte aligned):
  //   [r1+ 0]: back chain (old r1)
  //   [r1+ 8]: empty
  //   [r1+16]: empty
  //   [r1+24]: TOC save (r2)
  //   [r1+32 .. r1+87]: SyscallArguments (7 × 8 = 56 bytes)
  static_assert(FEXCore::HLE::SyscallArguments::MAX_ARGS == 7);
  stdu(r1, -96, r1);

  // Fill SyscallArguments from the IR op's source nodes.
  // After SpillStaticRegs the physical SRA registers still hold the live values.
  for (uint32_t i = 0; i < FEXCore::HLE::SyscallArguments::MAX_ARGS; ++i) {
    if (Op->Header.Args[i].IsInvalid()) continue;
    const int16_t slot_off = static_cast<int16_t>(32 + i * 8);
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
  //   r5 = SyscallArguments* (at [r1+32])
  //   r12 = callee address (ELFv2 indirect-call requirement)
  {
    const int32_t obj_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, Pointers.SyscallHandlerObj));
    const int32_t fn_off  = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, Pointers.SyscallHandlerFunc));

    ld(r3,    obj_off, STATE);   // r3  = this
    ld(r(12), fn_off,  STATE);   // r12 = fn ptr
    mr(r4, STATE);               // r4  = Frame
    addi(r5, r1, 32);            // r5  = &SyscallArguments
  }

  std(r2, 24, r1);     // save TOC
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

  // Free the mini-frame, then reload SRA from STATE (picks up the RAX result).
  addi(r1, r1, 96);
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

  // Call: set r12 = callee GEP per ELFv2, then branch via CTR
  mr(r(12), TMP2);
  mtctr(TMP2);
  bctrl();

  FillForABICall();
}

} // namespace FEXCore::CPU
