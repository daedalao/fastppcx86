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

// MSR_VSX, from arch/powerpc/include/asm/reg.h:
//   #define MSR_VSX_LG 23   /* Enable VSX */
//   #define MSR_VSX    __MASK(MSR_VSX_LG)
// In a SIGNAL FRAME this bit does not mean "the CPU had VSX enabled". It is
// the kernel's validity flag for the vs0-31 doubleword-1 region described at
// PPC_SIGCONTEXT_VSX_DW1_OFFSET below: setup_sigcontext clears it
// unconditionally (`msr &= ~MSR_VSX;`) and re-sets it only on the same branch
// that copies the region out. Consumers must test it before touching that
// memory, and restore paths must keep it consistent with what they wrote.
constexpr uint64_t PPC_MSR_VSX = 1ULL << 23;

// Byte offset from mcontext_t::v_regs to the vs0-31 doubleword-1 region.
// The kernel's setup_sigcontext publishes v_regs pointing at the 34-quadword
// VMX area (v0-v31, VSCR, VRSAVE = ELF_NVRREG entries of elf_vrreg_t, which is
// __vector128), THEN does `v_regs += ELF_NVRREG` before copy_vsx_to_user, so
// the doubleword-1 region starts exactly ELF_NVRREG * 16 == 544 bytes past the
// pointer userspace sees. copy_vsx_to_user writes 32 bare host-LE u64s indexed
// by VSR number, so `((uint64_t*)((uint8_t*)v_regs + 544))[n] == vs(n).dw1`.
//
// SIZING TRAP: this region is real memory in every kernel-built rt_sigframe --
// struct sigcontext reserves `long vmx_reserve[ELF_NVRREG + ELF_NVRREG + 1 +
// 32]` (101 doublewords) for it -- but glibc's mcontext_t under-declares the
// same array as `long vmx_reserve[__NVRREG + __NVRREG + 1]` (69). The region
// therefore sits PAST the end of the struct as the compiler sees it. Never
// bound-check it against sizeof(mcontext_t) or sizeof(ucontext_t); the only
// meaningful checks are the two in HasPPCVSXLowBankDW1 below.
constexpr size_t PPC_SIGCONTEXT_VSX_DW1_OFFSET = 34 * 16;

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

  // Floating-point register file and FPSCR.
  //
  // FPSCR is the correctness half: it is where the PPC rounding mode lives, and
  // the JIT writes it PERSISTENTLY. DEF_OP(SetRoundingMode) (ALUOps.cpp) turns
  // a guest LDMXCSR / FLDCW into an mtfsf that leaves the host FPSCR holding
  // the guest's requested mode for the rest of the block and beyond -- there is
  // no save/restore bracket around it. Without FPSCR in this backup, ANY signal
  // taken between the SetRoundingMode and the arithmetic it was meant to govern
  // silently reverts the guest to round-to-nearest: BackupContext copies
  // everything except FPSCR, the handler runs (glibc/host code freely resets
  // rounding), and RestoreContext puts back a context whose FPSCR field is
  // whatever the handler left. The guest then computes with the wrong rounding
  // mode and nothing anywhere reports an error. Mono's GC hammers every thread
  // with suspend signals, so this is a real corruption source, not a theoretical
  // one, and it is the kind that shows up as drift rather than a crash.
  //
  // FPRs are the same argument as the VRR block above: the JIT uses f0..f31 for
  // scalar FP and as general scratch, so a signal landing mid-block leaves live
  // values there; restoring them keeps resumption transparent.
  //
  // LAYOUT: glibc's ppc64le mcontext_t declares `fpregset_t fp_regs`, and
  // `typedef double fpregset_t[__NFPREG]` with __NFPREG == 33 -- 32 FPRs
  // followed by FPSCR in the 33rd slot (index 32). This matches the kernel:
  // arch/powerpc/kernel/signal_64.c's copy_fpr_to_user()/copy_fpr_from_user()
  // write the 32 FPRs then stash fpscr in buf[32], and rt_sigreturn feeds the
  // whole 33-element array back through copy_fpr_from_user, so a value written
  // into fp_regs[32] here is genuinely reloaded into FPSCR on return from the
  // handler. Stored as raw bit patterns (uint64_t), never as `double`: FPSCR is
  // not a float, and round-tripping FPR bits through a double would canonicalise
  // signalling NaNs.
  //
  // Unconditional, unlike the VRR block -- fp_regs is an inline array in
  // mcontext_t, not a pointer, so there is no null case to guard.
  uint64_t FPRs[32];
  uint64_t FPSCR;

  // vs0-vs31 DOUBLEWORD 1 -- the vector half of the FPR-aliased low VSX bank.
  //
  // FPRs[] above is doubleword 0 and nothing else: mcontext_t::fp_regs[N] IS
  // vs(N).dw0, and the other half lives in a separate region of the frame (see
  // PPC_SIGCONTEXT_VSX_DW1_OFFSET). Backing up only fp_regs therefore saved
  // half of every low-bank VSX register, and restoring only fp_regs put that
  // half back on top of whatever dw1 the RESTORE-side signal frame happened to
  // carry -- a different frame, captured at a different instant.
  //
  // Live consequence, not a theoretical one. The AVX-high bank pins guest
  // YMM_hi[i] in vs(16+i) (AVXHIGH_BANK_FIRST, FEXCore ArchHelpers/
  // PPC64Emitter.h) whenever HostFeatures.SupportsAVX is set -- default off on
  // this tree, but individual titles turn it on through AppConfig -- and it
  // holds them in the VR convention: dw0 = guest HIGH qword, dw1 = guest LOW
  // qword. An INJIT delivery resumes at the ORIGINAL NIP with the live
  // register file rather than through FillSRA (see the CONTEXT_FLAG_INJIT
  // comment in SignalDelegator::RestoreThreadState), so what this pair puts
  // back IS the guest's architectural state. dw0-only meant every one of the
  // 16 YMM upper halves came back torn: high qword from the interrupted
  // context, low qword from whatever last ran on the restore-side frame --
  // typically the guest's own signal handler, which executed JIT code with the
  // bank live and left its own YMM highs in these registers. No fault, no
  // diagnostic, just wrong arithmetic afterwards; exactly the failure shape of
  // the vs15 AES-mask bug that this hazard class was named for.
  //
  // Not merged into FPRs[] as a 128-bit array because the two halves are NOT
  // adjacent in the frame and are not even governed by the same validity rule:
  // fp_regs is an inline, always-present member, while this region is
  // conditional on MSR_VSX (see VSXRegionValid).
  uint64_t VSXDW1[32];

  // Whether VSXDW1 above was actually captured, i.e. whether HasPPCVSXLowBankDW1
  // held for the frame BackupContext read.
  //
  // This is what keeps the restore honest rather than merely non-crashing.
  // RestoreContext copies all 48 gp_regs back, MSR included, so the frame it
  // hands to rt_sigreturn carries the MSR_VSX bit that was captured HERE. The
  // kernel then acts on that bit: restore_sigcontext reloads dw1 of vs0-31
  // from the region when it is set, and ZEROES dw1 of all 32 registers when it
  // is clear. Writing the region without the bit would be a silent no-op;
  // claiming the bit without the data would hand the guest 32 doublewords of
  // stale sigframe stack. Carrying the flag makes both impossible: a context
  // backed up without VSX is restored without VSX.
  bool VSXRegionValid;

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

// Raw ppc64le GPR access by *hardware* register number (r0..r31), for callers
// that decode host instructions (the SMC store-emulation fast path) and
// therefore already speak PPC numbering. Deliberately separate from
// GetArmReg/SetArmReg below, which translate ARM64 register IDs — mixing the
// two numbering schemes is exactly the bug class recorded in the SetArmReg
// history note.
static inline uint64_t GetPPCGpReg(void* ucontext, uint32_t HwReg) {
  return GetMContext(ucontext)->gp_regs[HwReg];
}

static inline void SetPPCGpReg(void* ucontext, uint32_t HwReg, uint64_t val) {
  GetMContext(ucontext)->gp_regs[HwReg] = val;
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

// AVX-high bank capture: read low-bank VSX register vsN (N < 32) out of the
// signal frame. The kernel splits vs0-31 across two areas (arch/powerpc/
// kernel/signal_64.c setup_sigcontext): doubleword 0 is the FPR half in
// fp_regs[N]; doubleword 1 lives in the VSX region that FOLLOWS the 34
// vector entries at v_regs (`v_regs += ELF_NVRREG` (34), then
// copy_vsx_to_user of 32 u64s). Both are host-LE u64s. The JIT keeps guest
// YMM_hi values in the VR convention — dw0 = guest HIGH qword, dw1 = guest
// LOW qword — so the SpillSRA caller maps DW1 -> avx_high[i][0] (low) and
// DW0 -> avx_high[i][1] (high). Valid mid-host-call too: the bank registers
// f16-f31 are ELFv2 callee-saved.
static inline uint64_t GetPPCVSXLowBankDW0(void* ucontext, uint32_t n) {
  uint64_t v;
  memcpy(&v, &GetMContext(ucontext)->fp_regs[n], sizeof(v));
  return v;
}

// Does this frame carry the vs0-31 doubleword-1 region at all?
//
// MANDATORY before GetPPCVSXLowBankDW1 / PPCVSXLowBankDW1 below. Two separate
// things have to hold and they fail differently:
//
//  * v_regs != nullptr. Every CONFIG_ALTIVEC kernel publishes a pointer here
//    unconditionally -- setup_sigcontext sets it before it even knows whether
//    VMX state is live, precisely so VRSAVE always has a home -- but the
//    `#else /* CONFIG_ALTIVEC */` arm stores 0. The region address is derived
//    from this pointer, so a null one turns the access into a read or write of
//    address 0x220, not a fault-free no-op. BackupContext's existing VRR block
//    already guards on it; this is the same guard for the same reason.
//
//  * MSR_VSX set in the frame's saved MSR. This is a VALIDITY flag, not a CPU
//    state bit: setup_sigcontext clears it and re-sets it only on the branch
//    that runs copy_vsx_to_user (gated on tsk->thread.used_vsr). With it clear
//    the 256 bytes are untouched sigframe stack -- addressable, because
//    struct sigcontext reserves them either way, but holding garbage. Reading
//    them yields nonsense; writing them is discarded, because restore_sigcontext
//    reads the region only when the same bit is set and otherwise zeroes dw1 of
//    all 32 registers.
static inline bool HasPPCVSXLowBankDW1(void* ucontext) {
  const auto* mctx = GetMContext(ucontext);
  return mctx->v_regs != nullptr && (mctx->gp_regs[PPC_PT_MSR] & PPC_MSR_VSX) != 0;
}

static inline uint64_t* PPCVSXLowBankDW1(void* ucontext) {
  auto* mctx = GetMContext(ucontext);
  return reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(mctx->v_regs) + PPC_SIGCONTEXT_VSX_DW1_OFFSET);
}

// Precondition: HasPPCVSXLowBankDW1(ucontext). Deliberately NOT self-guarding.
// There is no in-band value that could mean "absent" -- 0 is a perfectly good
// guest qword -- so a self-guarding version would have to invent one, and the
// only two callers (SpillSRA's AVX-high capture, in LinuxEmulation and
// FEXInterpreter) need to skip the whole per-register loop rather than fold a
// sentinel into State.avx_high[]. Make the caller ask the question.
static inline uint64_t GetPPCVSXLowBankDW1(void* ucontext, uint32_t n) {
  return PPCVSXLowBankDW1(ucontext)[n];
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

  // FPRs + FPSCR. See the FPRs/FPSCR declaration for why FPSCR in particular
  // must round-trip. fp_regs is `double[33]`; copy the bit patterns.
  static_assert(sizeof(_mcontext->fp_regs) == 33 * sizeof(uint64_t),
                "ppc64le mcontext fp_regs is expected to be 32 FPRs followed by FPSCR");
  memcpy(&Backup->FPRs[0], &_mcontext->fp_regs[0], sizeof(Backup->FPRs));
  memcpy(&Backup->FPSCR, &_mcontext->fp_regs[32], sizeof(Backup->FPSCR));

  // The other half of vs0-31. See the VSXDW1 declaration for why dw0 alone is
  // not a register save on a backend that keeps guest YMM highs in this bank.
  // Modelled on the v_regs guard above, plus the MSR_VSX validity bit the VMX
  // block does not need (its region is unconditional once v_regs is non-null).
  Backup->VSXRegionValid = HasPPCVSXLowBankDW1(ucontext);
  if (Backup->VSXRegionValid) {
    memcpy(&Backup->VSXDW1[0], PPCVSXLowBankDW1(ucontext), sizeof(Backup->VSXDW1));
  } else {
    // Zero for determinism, exactly as the VRR else-branch does -- and it is
    // also what the guest would observe anyway, since a frame restored with
    // MSR_VSX clear has dw1 of vs0-31 zeroed by restore_sigcontext.
    memset(&Backup->VSXDW1[0], 0, sizeof(Backup->VSXDW1));
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

  // Put back the FP register file and, critically, FPSCR -- otherwise a guest
  // that set a non-default rounding mode via LDMXCSR/FLDCW silently loses it to
  // any signal that happens to land afterwards. rt_sigreturn reloads all 33
  // slots, so writing fp_regs[32] here really does restore the rounding mode.
  memcpy(&_mcontext->fp_regs[0], &Backup->FPRs[0], sizeof(Backup->FPRs));
  memcpy(&_mcontext->fp_regs[32], &Backup->FPSCR, sizeof(Backup->FPSCR));

  // ...and the vector half of vs0-31, which fp_regs does not carry.
  //
  // SYMMETRY, and why the condition is the BACKUP's flag rather than this
  // frame's MSR: the gp_regs memcpy at the top of this function has already
  // replaced _mcontext->gp_regs[PPC_PT_MSR] with the MSR we captured, so the
  // frame's MSR_VSX bit is now the backup's. Driving the write off
  // Backup->VSXRegionValid states that dependency instead of relying on
  // statement order, and it makes both halves of the contract explicit:
  //   VSXRegionValid  -> MSR_VSX is set in the restored gp_regs, and
  //                      restore_sigcontext will reload dw1 of vs0-31 from the
  //                      bytes we are writing here.
  //   !VSXRegionValid -> MSR_VSX is clear, restore_sigcontext ignores the
  //                      region and zeroes dw1 itself, so writing would be a
  //                      no-op that only pretends to have restored something.
  // A context backed up without VSX is therefore never restored with it.
  //
  // The v_regs re-check is not redundant with the flag: this is a DIFFERENT
  // signal frame from the one BackupContext read (the backup travels on the
  // host stack from the delivery handler to the sigreturn/pause handler that
  // unwinds it), so its pointer has to be validated on its own terms before it
  // is used as a write base.
  if (Backup->VSXRegionValid && _mcontext->v_regs) {
    memcpy(PPCVSXLowBankDW1(ucontext), &Backup->VSXDW1[0], sizeof(Backup->VSXDW1));
  }
}
