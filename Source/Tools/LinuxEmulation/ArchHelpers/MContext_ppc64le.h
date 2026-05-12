// SPDX-License-Identifier: MIT
// PPC64LE host signal context helpers.
// Included by MContext.h inside namespace FEX::ArchHelpers::Context.
// Do not include directly.

// Indices into mcontext_t.gp_regs[] — mirrors the kernel pt_regs layout for ppc64le.
// The 48-element array covers: r0-r31 (0-31), NIP(32), MSR(33), ORIG_R3(34),
// CTR(35), LR(36), XER(37), CCR(38), SOFTE(39), TRAP(40), DAR(41), DSISR(42),
// RESULT(43), DSCR(44..47).
constexpr uint32_t PPC_PT_R1    = 1;   // Stack pointer
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

  // ppc64le ELFv2 ABI has no red zone
  static constexpr int RedZoneSize = 0;
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

// SRA single-instruction fill is handled inside the JIT dispatcher for ppc64le.
static inline void SetFillSRASingleInst(void*, bool) {}

// GetArmReg / SetArmReg map caller-saved ARM64 register conventions onto the
// closest ppc64le equivalent. ARM64 r30 (link register) → ppc64le LR;
// ARM64 r0 (return/arg) → ppc64le r3.
static inline uint64_t GetArmReg(void* ucontext, uint32_t id) {
  if (id == 30) {
    return GetMContext(ucontext)->gp_regs[PPC_PT_LR];
  }
  return GetMContext(ucontext)->gp_regs[id == 0 ? 3u : id];
}

static inline void SetArmReg(void* ucontext, uint32_t id, uint64_t val) {
  GetMContext(ucontext)->gp_regs[id == 0 ? 3u : id] = val;
}

static inline uint64_t GetArmPState(void* ucontext) {
  // CCR (condition register) contains the FEX NZCV-equivalent in bits [31:28]:
  // StoreNZCV places N(SF)→bit31, Z(ZF)→bit30, C(~CF)→bit29, V(OF)→bit28,
  // matching the ARM64 PSTATE bit positions that ReconstructCompactedEFLAGS expects.
  return GetMContext(ucontext)->gp_regs[PPC_PT_CCR];
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
}
