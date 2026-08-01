// SPDX-License-Identifier: MIT
// PPC64LE host signal context helpers.
// Included by MContext.h inside namespace FEX::ArchHelpers::Context.
// Do not include directly.

// Indices into mcontext_t.gp_regs[] — mirrors the kernel pt_regs layout for ppc64le.
// The 48-element array covers: r0-r31 (0-31), NIP(32), MSR(33), ORIG_R3(34),
// CTR(35), LR(36), XER(37), CCR(38), SOFTE(39), TRAP(40), DAR(41), DSISR(42),
// RESULT(43), DSCR(44..47).
constexpr uint32_t PPC_PT_R1    = 1;   // Stack pointer
constexpr uint32_t PPC_PT_R4    = 4;   // TMP2 / ENTRY_FILL_SRA_SINGLE_INST_REG
constexpr uint32_t PPC_PT_NIP   = 32;  // Program counter (Next Instruction Pointer)
constexpr uint32_t PPC_PT_MSR   = 33;  // Machine State Register
constexpr uint32_t PPC_PT_CTR   = 35;  // Count Register
constexpr uint32_t PPC_PT_LR    = 36;  // Link Register
constexpr uint32_t PPC_PT_XER   = 37;  // Fixed-Point Exception Register
constexpr uint32_t PPC_PT_CCR   = 38;  // Condition Register
constexpr uint32_t PPC_PT_DSISR = 42;  // Data Storage Interrupt Status Register
constexpr uint32_t PPC_PT_STATE = 27;  // FEX JIT thread-state pointer (r27)

struct PPC64ContextBackup {
  // ELFv2 caller-frame reservation: linkage area (+0..31) + parameter
  // save area (+32..95). MUST be at the head of the backup so that any
  // code which runs with `r1 == &Backup` and writes within the standard
  // ABI-defined caller-frame slots lands here instead of clobbering GPRs.
  //
  // Why this matters: HandleDispatcherGuestSignal sets host PC to
  // `DispatcherLoopTopFillSRAAddress` (PAST the dispatcher's
  // PushCalleeSavedRegisters prologue). The kernel resumes user code with
  // r1 == NewSP == &Backup and no dispatcher frame pushed. Two distinct
  // families of writes then hit Backup memory without the pad:
  //
  //   (a) The dispatcher's `std r2, 24, r1` (ExitFunctionLinker's TOC save
  //       across the C bctrl) writes at r1+24. Without the linkage portion
  //       of the pad that clobbered Backup->GPRs[3] -- sigsuspend then
  //       returned a TOC pointer instead of -EINTR. (Fixed first in
  //       commit 3b9b640a3 with a 32-byte head pad.)
  //
  //   (b) Any callee invoked by `bctrl` is entitled by ELFv2 to spill its
  //       incoming r3..r10 args into the CALLER's parameter save area at
  //       r1+32..r1+95. With only the 32-byte linkage pad, a callee's
  //       spill of r5 (parameter slot at r1+48) clobbered Backup->GPRs[2].
  //       Restore then fed back a stale host TOC, and the host PC ran into
  //       an unmapped library page when resuming libc::select -- observed
  //       as sigaction-17-12's MAXINST=500 infinite SIGSEGV loop.
  //
  // 96 bytes (12 doublewords) covers both. Sized as 16 for headroom.
  uint64_t LinkageArea[16];  // 128 bytes (>= 96 required by ELFv2 caller-frame ABI)

  // All 48 gregs: r0-r31, then NIP/MSR/ORIG_R3/CTR/LR/XER/CCR/...
  uint64_t GPRs[48];

  // 2026-05-15: AltiVec (VMX) register save area.  The FEX JIT maps the guest
  // XMM register file to V0..V31 via SRA, so a signal interrupting a JIT
  // block leaves live XMM values in those registers.  Without this save the
  // signal handler's RestoreContext would resume the dispatcher with the
  // host's post-handler AltiVec state, then SpillStaticRegs at block exit
  // would copy that stale state to State.xmm, corrupting XMM for every
  // subsequent block.  The previous workaround (route through FillSRA in
  // SignalDelegator::RestoreThreadState) avoided the corruption but breaks
  // signal-driven sync wakeups inside the guest (Steam manifest deadlock,
  // Mono/.NET GC spin -- see project_steam_2026-05-12_evening_summary.md).
  //
  // Mirrors ArmContextBackup::{FPRs,FPCR,FPSR}.  glibc's ppc64le mcontext
  // exposes 32 vrregs + VSCR + VRSAVE via __v_regs.
  alignas(16) __uint128_t VRRs[32];  // V0..V31, each 128-bit
  uint32_t VSCR;
  uint32_t VRSAVE;

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  // Sanity check trailing the GPRs (the head used to hold this cookie, but
  // ExitFunctionLinker would clobber it before any consumer could read it,
  // so the cookie now sits past the linkage area).
  uint64_t StackCookie;
#endif
  uint64_t sa_mask;
  uint16_t InSyscallInfo;
  bool FaultToTopAndGeneratedException;

  int Signal;
  uint32_t Flags;
  uint64_t OriginalRIP;
  uint64_t FPStateLocation;
  uint64_t UContextLocation;
  uint64_t SigInfoLocation;
  FEXCore::Core::CPUState GuestState;

  // ELFv2 ABI §2.2.2.4 mandates a 288-byte red zone below the stack
  // pointer -- accessible without adjusting r1. StoreThreadState at
  // SignalDelegator.cpp:304-318 subtracts RedZoneSize from OldSP before
  // stamping ContextBackup, so RedZoneSize=0 causes every signal
  // delivery to overwrite [OldSP-288, OldSP) with a ContextBackup whose
  // GuestState tail sits exactly at OldSP. The JIT uses r1-negative
  // scratch in ~250 places (JIT.cpp, ALUOps.cpp, AtomicOps.cpp,
  // VectorOps.cpp, MemoryOps.cpp; e.g. ALUOps.cpp:3629 does
  // `addi(TMP1, r1, -32); stvx(...); lfd(..., -32, r1)`), so any block
  // holding scratch in the red zone across a signal delivery gets its
  // scratch replaced with the tail of a guest CPUState, and the block
  // resumes reading corruption. This is guest-state corruption from an
  // ordinary signal with no thread race required.
  //
  // Corresponds to MContext_x86_64.h:25 which sets 128 for x86-64's red
  // zone. MContext_arm64.h:49 correctly sets 0 (AArch64 Linux has no
  // red zone) -- ppc64le originally copied that.
  static constexpr int RedZoneSize = 288;
};

using ContextBackup = PPC64ContextBackup;

static inline uint64_t GetSp(void* ucontext) {
  return GetMContext(ucontext)->gp_regs[PPC_PT_R1];
}

static inline uint64_t GetPc(void* ucontext) {
  return GetMContext(ucontext)->gp_regs[PPC_PT_NIP];
}

static inline void SetSp(void* ucontext, uint64_t val) {
  GetMContext(ucontext)->gp_regs[PPC_PT_R1] = val;
}

static inline void SetPc(void* ucontext, uint64_t val) {
  GetMContext(ucontext)->gp_regs[PPC_PT_NIP] = val;
}

static inline uint64_t GetState(void* ucontext) {
  return GetMContext(ucontext)->gp_regs[PPC_PT_STATE];
}

static inline void SetState(void* ucontext, uint64_t val) {
  GetMContext(ucontext)->gp_regs[PPC_PT_STATE] = val;
}

// SRA single-instruction fill: when the SMC SIGSEGV handler (in
// SyscallsSMCTracking.cpp) needs to force the next JIT entry to compile a
// single-x86-instruction block, it sets ENTRY_FILL_SRA_SINGLE_INST_REG
// (TMP2 = PPC r4) to non-zero in the kernel ucontext. The dispatcher's
// DispatcherLoopTopFillSRAAddress entry checks this BEFORE FillStaticRegs
// clobbers TMP2 in its NZCV unpack stage and branches to a CompileSingleStep
// helper if set. Mirrors Arm64Emitter.h:ENTRY_FILL_SRA_SINGLE_INST_REG.
static inline void SetFillSRASingleInst(void* ucontext, bool SingleInst) {
  GetMContext(ucontext)->gp_regs[PPC_PT_R4] = SingleInst ? 1 : 0;
}

// GetArmReg / SetArmReg map ARM64 caller-saved register IDs onto the closest
// ppc64le equivalent.  Cross-arch callers (e.g. the SMC SIGSEGV handler in
// SyscallsSMCTracking.cpp using ARM64 X1 == ENTRY_FILL_SRA_SINGLE_INST_REG ==
// TMP2) refer to ARM register indices; we have to map those to ppc64le's
// SRA/scratch numbering or the wrong host GPR gets written.
//
// Mapping:
//   ARM X0  (= TMP1 / first arg)      → ppc64le r3   (TMP1)
//   ARM X1  (= TMP2 / second arg / ENTRY_FILL_SRA_SINGLE_INST_REG)
//                                     → ppc64le r4   (TMP2)
//   ARM X2  (= TMP3 / third arg)      → ppc64le r5   (TMP3)
//   ARM X3  (= TMP4 / fourth arg)     → ppc64le r6   (TMP4)
//   ARM X30 (= LR)                    → ppc64le LR (PPC_PT_LR)
//   any other id:                     → ppc64le gp_regs[id+3] (best-effort)
//
// BUG history: previously did `gp_regs[id == 0 ? 3 : id]`, so id=1 wrote
// the STACK POINTER (r1) instead of TMP2 (r4).  SyscallHandler::HandleSegfault
// calls SetArmReg(ucontext, 1, 1) to force single-step on SMC retries; on
// PPC64LE that silently corrupted r1, leading to an immediate fault when
// the dispatcher resumed and touched the stack.
static inline uint64_t GetArmReg(void* ucontext, uint32_t id) {
  if (id == 30) {
    return GetMContext(ucontext)->gp_regs[PPC_PT_LR];
  }
  // ARM X(i) → PPC r(i+3) for i in [0..3] (TMP1..TMP4).  For larger IDs we
  // currently have no caller mapping; fall through to gp_regs[id+3] as a
  // best-effort -- any future caller using id > 3 should map explicitly.
  return GetMContext(ucontext)->gp_regs[3u + id];
}

static inline void SetArmReg(void* ucontext, uint32_t id, uint64_t val) {
  if (id == 30) {
    GetMContext(ucontext)->gp_regs[PPC_PT_LR] = val;
    return;
  }
  GetMContext(ucontext)->gp_regs[3u + id] = val;
}

static inline uint64_t GetArmPState(void* ucontext) {
  // Assemble the packed ARM-PSTATE word ReconstructCompactedEFLAGS expects.
  // ppc64le maps guest NZCV across TWO host regs at JIT emission time (see
  // FEXCore/Source/Interface/Core/ArchHelpers/PPC64Emitter.cpp:152-160 for the
  // pack, :225-236 for the unpack): CR0 carries N/Z, XER carries C/V. The
  // prior implementation returned raw CCR — that gave the right N by
  // coincidence (CR0.LT@31 aliases N@31) but delivered CR0.GT as Z, CR0.EQ as
  // ~C and CR0.SO as V, corrupting ZF/CF/OF on every in-JIT signal. Every
  // guest signal, SMC single-step redirect and drained async signal (which
  // ppc64le drains inside the code buffer via the fault-page poke, so
  // WasInJIT is true there) went through this path.
  //
  //   Packed ARM-PSTATE word:  N @ bit31, Z @ bit30, C @ bit29, V @ bit28
  //   From CCR (raw CR): LT@bit31, GT@bit30, EQ@bit29, SO@bit28
  //   From XER:          SO@bit31, OV@bit30, CA@bit29
  const uint64_t ccr = GetMContext(ucontext)->gp_regs[PPC_PT_CCR];
  const uint64_t xer = GetMContext(ucontext)->gp_regs[PPC_PT_XER];
  return  (ccr & (1ULL << 31))          // N ← CR0.LT
        | ((ccr & (1ULL << 29)) << 1)   // Z ← CR0.EQ, shift into bit 30
        | ( xer & (1ULL << 29))          // C ← XER.CA
        | ((xer & (1ULL << 30)) >> 2);  // V ← XER.OV, shift into bit 28
}

static inline uint64_t* GetArmGPRs(void* ucontext) {
  return reinterpret_cast<uint64_t*>(&GetMContext(ucontext)->gp_regs[0]);
}

// Read a 128-bit AltiVec register from the signal mcontext.
// glibc's ppc64le mcontext_t exposes __vrregs[34]: v0-v31 + VSCR + VRSAVE.
// The kernel saves VMX state whenever MSR_VEC is set; since FEX always uses
// AltiVec in the JIT, VMX state is always present in the signal frame.
static inline __uint128_t GetArmFPR(void* ucontext, uint32_t id) {
  __uint128_t result;
  // __v_regs is a pointer to vrregset_t; always valid when FEX uses AltiVec
  memcpy(&result, &GetMContext(ucontext)->v_regs->vrregs[id], sizeof(__uint128_t));
  return result;
}

static inline uint32_t GetProtectFlags(void* ucontext) {
  // DSISR bit 25 (0x02000000) indicates a store-caused fault (write).
  const uint64_t dsisr = GetMContext(ucontext)->gp_regs[PPC_PT_DSISR];
  uint32_t ProtectFlags = FEXCore::X86State::X86_PF_USER;
  if (dsisr & 0x02000000ULL) {
    ProtectFlags |= FEXCore::X86State::X86_PF_WRITE;
  }
  return ProtectFlags;
}

template<typename T>
static inline void BackupContext(void* ucontext, T* Backup) {
  static_assert(std::is_same_v<T, PPC64ContextBackup>, "BackupContext: wrong type for ppc64le host");
  auto _ucontext = GetUContext(ucontext);
  auto _mcontext = GetMContext(ucontext);

  memcpy(&Backup->GPRs[0], &_mcontext->gp_regs[0], 48 * sizeof(uint64_t));
  memcpy(&Backup->sa_mask, &_ucontext->uc_sigmask, sizeof(uint64_t));

  // 2026-05-15: save AltiVec/VMX state alongside GPRs.  The kernel saves
  // vrregs whenever MSR_VEC is set; since the FEX JIT always uses AltiVec
  // (V0..V31 are SRA-mapped to guest XMM), v_regs is always populated when
  // we land in the signal handler from JIT code.  vrregset_t layout is
  // documented as { vector unsigned int vrregs[32][4]; vector unsigned int
  // vscr; unsigned int vrsave; }, i.e. 32 × 128-bit vector regs followed by
  // VSCR (in element 3 of a 16-byte aligned slot) and VRSAVE (4 bytes).
  if (_mcontext->v_regs) {
    memcpy(&Backup->VRRs[0], &_mcontext->v_regs->vrregs[0], sizeof(Backup->VRRs));
    Backup->VSCR   = _mcontext->v_regs->vscr.vscr_word;
    Backup->VRSAVE = _mcontext->v_regs->vrsave;
  } else {
    // No VMX state in this frame (e.g. signal landed in pre-FillSRA stub).
    // Zero so RestoreContext is deterministic.
    memset(&Backup->VRRs[0], 0, sizeof(Backup->VRRs));
    Backup->VSCR   = 0;
    Backup->VRSAVE = 0;
  }

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  Backup->StackCookie = STACK_COOKIE_MAGIC;
#endif
}

template<typename T>
static inline void RestoreContext(void* ucontext, T* Backup) {
  static_assert(std::is_same_v<T, PPC64ContextBackup>, "RestoreContext: wrong type for ppc64le host");
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  LOGMAN_THROW_A_FMT(Backup->StackCookie == STACK_COOKIE_MAGIC,
                     "Stack cookie didn't match! 0x{:x}", Backup->StackCookie);
#endif
  auto _ucontext = GetUContext(ucontext);
  auto _mcontext = GetMContext(ucontext);

  memcpy(&_mcontext->gp_regs[0], &Backup->GPRs[0], 48 * sizeof(uint64_t));
  memcpy(&_ucontext->uc_sigmask, &Backup->sa_mask, sizeof(uint64_t));

  // 2026-05-15: restore AltiVec/VMX state so the dispatcher resumes with
  // the pre-handler V0..V31 (= guest XMM via SRA).  Without this, the JIT
  // block's first SpillStaticRegs would write whatever AltiVec values the
  // signal handler happened to leave behind into State.xmm.
  if (_mcontext->v_regs) {
    memcpy(&_mcontext->v_regs->vrregs[0], &Backup->VRRs[0], sizeof(Backup->VRRs));
    _mcontext->v_regs->vscr.vscr_word = Backup->VSCR;
    _mcontext->v_regs->vrsave         = Backup->VRSAVE;
  }
}
