// SPDX-License-Identifier: MIT
// AArch64 host signal context helpers.
// Included by MContext.h inside namespace FEX::ArchHelpers::Context.
// Do not include directly.

constexpr uint32_t FPR_MAGIC  = 0x46508001U;
constexpr uint32_t ESR1_MAGIC = 0x45535201U;

struct HostCTXHeader {
  uint32_t Magic;
  uint32_t Size;
};

struct HostFPRState {
  HostCTXHeader Head;
  uint32_t FPSR;
  uint32_t FPCR;
  __uint128_t FPRs[32];
};

struct HostESRState {
  HostCTXHeader Head;
  uint64_t ESR;
};

struct ArmContextBackup {
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  uint64_t StackCookie;
#endif
  uint64_t GPRs[31];
  uint64_t PrevSP;
  uint64_t PrevPC;
  uint64_t PState;
  uint32_t FPSR;
  uint32_t FPCR;
  __uint128_t FPRs[32];
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

  static constexpr int RedZoneSize = 0;
};

using ContextBackup = ArmContextBackup;

static inline uint64_t GetSp(void* ucontext) {
  return GetMContext(ucontext)->sp;
}

static inline uint64_t GetPc(void* ucontext) {
  return GetMContext(ucontext)->pc;
}

static inline uint64_t* GetArmPc(void* ucontext) {
  return reinterpret_cast<uint64_t*>(&GetMContext(ucontext)->pc);
}

static inline void SetSp(void* ucontext, uint64_t val) {
  GetMContext(ucontext)->sp = val;
}

static inline void SetPc(void* ucontext, uint64_t val) {
  GetMContext(ucontext)->pc = val;
}

static inline uint64_t GetState(void* ucontext) {
  return GetMContext(ucontext)->regs[28];
}

static inline void SetState(void* ucontext, uint64_t val) {
  GetMContext(ucontext)->regs[28] = val;
}

static inline void SetFillSRASingleInst(void* ucontext, bool SingleInst) {
  GetMContext(ucontext)->regs[1] = SingleInst;
}

static inline uint64_t GetArmReg(void* ucontext, uint32_t id) {
  return GetMContext(ucontext)->regs[id];
}

static inline void SetArmReg(void* ucontext, uint32_t id, uint64_t val) {
  GetMContext(ucontext)->regs[id] = val;
}

static inline uint64_t GetArmPState(void* ucontext) {
  return GetMContext(ucontext)->pstate;
}

static inline uint64_t* GetArmGPRs(void* ucontext) {
  return reinterpret_cast<uint64_t*>(GetMContext(ucontext)->regs);
}

static inline __uint128_t GetArmFPR(void* ucontext, uint32_t id) {
  auto MContext = GetMContext(ucontext);
  HostFPRState* HostState = reinterpret_cast<HostFPRState*>(&MContext->__reserved[0]);
  LOGMAN_THROW_A_FMT(HostState->Head.Magic == FPR_MAGIC, "Wrong FPR Magic: 0x{:08x}", HostState->Head.Magic);
  return HostState->FPRs[id];
}

static inline __uint128_t* GetArmFPRs(void* ucontext) {
  auto MContext = GetMContext(ucontext);
  HostFPRState* HostState = reinterpret_cast<HostFPRState*>(&MContext->__reserved[0]);
  LOGMAN_THROW_A_FMT(HostState->Head.Magic == FPR_MAGIC, "Wrong FPR Magic: 0x{:08x}", HostState->Head.Magic);
  return &HostState->FPRs[0];
}

static inline uint64_t GetArmESR(void* ucontext) {
  auto MContext = GetMContext(ucontext);
  size_t i = 0;
  auto HostState = reinterpret_cast<HostCTXHeader*>(&MContext->__reserved[i]);
  do {
    if (HostState->Magic == ESR1_MAGIC) {
      return reinterpret_cast<HostESRState*>(HostState)->ESR;
    }
    i += HostState->Size;
    HostState = reinterpret_cast<HostCTXHeader*>(&MContext->__reserved[i]);
  } while (HostState->Size != 0);
  return 0;
}

constexpr static uint64_t ESR1_EC                             = 0b111111U << 26;
constexpr static uint64_t ESR1_EC_DataAbort                   = 0b100100U << 26;
constexpr static uint64_t ESR1_WNR                            = 1 << 6;
constexpr static uint64_t ESR1_DataAbort_DFSC                 = 0b111111;
constexpr static uint64_t ESR1_DataAbort_TranslationFault_EL0 = 0b000111;
constexpr static uint64_t ESR1_DataAbort_PermissionFault_EL0  = 0b001111;
constexpr static uint64_t ESR1_DataAbort_Level                = 0b11;
constexpr static uint64_t ESR1_DataAbort_Level_EL3            = 0b00;
constexpr static uint64_t ESR1_DataAbort_Level_EL2            = 0b01;
constexpr static uint64_t ESR1_DataAbort_Level_EL1            = 0b10;
constexpr static uint64_t ESR1_DataAbort_Level_EL0            = 0b11;

std::string_view GetESRName(uint64_t ESR);

static inline uint32_t GetProtectFlags(void* ucontext) {
  uint64_t ESR = GetArmESR(ucontext);
  LOGMAN_THROW_A_FMT((ESR & ESR1_EC) == ESR1_EC_DataAbort,
                     "Unknown ESR1 EC type: 0x{:x} != 0x{:x}. Received '{}'",
                     ESR & ESR1_EC, ESR1_EC_DataAbort, GetESRName(ESR));
  uint32_t ProtectFlags {};
  if ((ESR & ESR1_DataAbort_Level) == ESR1_DataAbort_Level_EL0) {
    ProtectFlags |= FEXCore::X86State::X86_PF_USER;
  }
  if (ESR & ESR1_WNR) {
    ProtectFlags |= FEXCore::X86State::X86_PF_WRITE;
  }
  return ProtectFlags;
}

template<typename T>
static inline void BackupContext(void* ucontext, T* Backup) {
  static_assert(std::is_same_v<T, ArmContextBackup>, "BackupContext: wrong type for arm64 host");
  auto _ucontext = GetUContext(ucontext);
  auto _mcontext = GetMContext(ucontext);

  memcpy(&Backup->GPRs[0], &_mcontext->regs[0], 31 * sizeof(uint64_t));
  Backup->PrevSP = GetSp(ucontext);
  Backup->PrevPC = GetPc(ucontext);
  Backup->PState = _mcontext->pstate;

  HostFPRState* HostState = reinterpret_cast<HostFPRState*>(&_mcontext->__reserved[0]);
  LOGMAN_THROW_A_FMT(HostState->Head.Magic == FPR_MAGIC, "Wrong FPR Magic: 0x{:08x}", HostState->Head.Magic);
  Backup->FPSR = HostState->FPSR;
  Backup->FPCR = HostState->FPCR;
  memcpy(&Backup->FPRs[0], &HostState->FPRs[0], 32 * sizeof(__uint128_t));
  memcpy(&Backup->sa_mask, &_ucontext->uc_sigmask, sizeof(uint64_t));

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  Backup->StackCookie = STACK_COOKIE_MAGIC;
#endif
}

template<typename T>
static inline void RestoreContext(void* ucontext, T* Backup) {
  static_assert(std::is_same_v<T, ArmContextBackup>, "RestoreContext: wrong type for arm64 host");
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  LOGMAN_THROW_A_FMT(Backup->StackCookie == STACK_COOKIE_MAGIC,
                     "Stack cookie didn't match! 0x{:x}", Backup->StackCookie);
#endif
  auto _ucontext = GetUContext(ucontext);
  auto _mcontext = GetMContext(ucontext);

  HostFPRState* HostState = reinterpret_cast<HostFPRState*>(&_mcontext->__reserved[0]);
  LOGMAN_THROW_A_FMT(HostState->Head.Magic == FPR_MAGIC, "Wrong FPR Magic: 0x{:08x}", HostState->Head.Magic);
  memcpy(&HostState->FPRs[0], &Backup->FPRs[0], 32 * sizeof(__uint128_t));
  HostState->FPCR = Backup->FPCR;
  HostState->FPSR = Backup->FPSR;

  _mcontext->pstate = Backup->PState;
  SetPc(ucontext, Backup->PrevPC);
  SetSp(ucontext, Backup->PrevSP);
  memcpy(&_mcontext->regs[0], &Backup->GPRs[0], 31 * sizeof(uint64_t));
  memcpy(&_ucontext->uc_sigmask, &Backup->sa_mask, sizeof(uint64_t));
}
