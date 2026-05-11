// SPDX-License-Identifier: MIT
// x86-64 host signal context helpers.
// Included by MContext.h inside namespace FEX::ArchHelpers::Context.
// Do not include directly.

struct X86ContextBackup {
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  uint64_t StackCookie;
#endif
  // RIP and RSP are stored in GPRs[REG_RIP] / GPRs[REG_RSP]
  uint64_t GPRs[23];
  FEXCore::x86_64::_libc_fpstate FPRState;
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

  static constexpr int RedZoneSize = 128;
};

using ContextBackup = X86ContextBackup;

static inline uint64_t GetSp(void* ucontext) {
  return GetMContext(ucontext)->gregs[REG_RSP];
}

static inline uint64_t GetPc(void* ucontext) {
  return GetMContext(ucontext)->gregs[REG_RIP];
}

static inline void SetSp(void* ucontext, uint64_t val) {
  GetMContext(ucontext)->gregs[REG_RSP] = val;
}

static inline void SetPc(void* ucontext, uint64_t val) {
  GetMContext(ucontext)->gregs[REG_RIP] = val;
}

static inline uint64_t GetState(void* ucontext) {
  return GetMContext(ucontext)->gregs[REG_R14];
}

static inline void SetState(void* ucontext, uint64_t val) {
  GetMContext(ucontext)->gregs[REG_R14] = val;
}

// These exist only on arm64 / ppc64le hosts.
static inline void SetFillSRASingleInst(void*, bool) {
  ERROR_AND_DIE_FMT("SetFillSRASingleInst: not implemented for x86-64 host");
}

static inline uint64_t GetArmReg(void*, uint32_t) {
  ERROR_AND_DIE_FMT("GetArmReg: not implemented for x86-64 host");
}

static inline void SetArmReg(void*, uint32_t, uint64_t) {
  ERROR_AND_DIE_FMT("SetArmReg: not implemented for x86-64 host");
}

static inline __uint128_t GetArmFPR(void*, uint32_t) {
  ERROR_AND_DIE_FMT("GetArmFPR: not implemented for x86-64 host");
}

static inline uint64_t GetArmPState(void*) {
  ERROR_AND_DIE_FMT("GetArmPState: not implemented for x86-64 host");
}

static inline uint64_t* GetArmGPRs(void*) {
  ERROR_AND_DIE_FMT("GetArmGPRs: not implemented for x86-64 host");
}

static inline uint32_t GetProtectFlags(void* ucontext) {
  return GetMContext(ucontext)->gregs[REG_ERR];
}

template<typename T>
static inline void BackupContext(void* ucontext, T* Backup) {
  static_assert(std::is_same_v<T, X86ContextBackup>, "BackupContext: wrong type for x86-64 host");
  auto _ucontext = GetUContext(ucontext);
  auto _mcontext = GetMContext(ucontext);

  memcpy(&Backup->GPRs[0], &_mcontext->gregs[0], sizeof(X86ContextBackup::GPRs));
  memcpy(&Backup->FPRState, _mcontext->fpregs, sizeof(X86ContextBackup::FPRState));
  memcpy(&Backup->sa_mask, &_ucontext->uc_sigmask, sizeof(uint64_t));

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  Backup->StackCookie = STACK_COOKIE_MAGIC;
#endif
}

template<typename T>
static inline void RestoreContext(void* ucontext, T* Backup) {
  static_assert(std::is_same_v<T, X86ContextBackup>, "RestoreContext: wrong type for x86-64 host");
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  LOGMAN_THROW_A_FMT(Backup->StackCookie == STACK_COOKIE_MAGIC,
                     "Stack cookie didn't match! 0x{:x}", Backup->StackCookie);
#endif
  auto _ucontext = GetUContext(ucontext);
  auto _mcontext = GetMContext(ucontext);

  memcpy(&_mcontext->gregs[0], &Backup->GPRs[0], sizeof(X86ContextBackup::GPRs));
  memcpy(_mcontext->fpregs, &Backup->FPRState, sizeof(X86ContextBackup::FPRState));
  memcpy(&_ucontext->uc_sigmask, &Backup->sa_mask, sizeof(uint64_t));
}
