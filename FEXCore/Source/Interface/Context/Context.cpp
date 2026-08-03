// SPDX-License-Identifier: MIT
#include "Interface/Context/Context.h"
#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/LookupCache.h"
#ifndef ARCHITECTURE_ppc64le
#include "Interface/Core/Dispatcher/Dispatcher.h"
#endif
#include "Interface/Core/X86Tables/X86Tables.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CPUID.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/HLE/SyscallHandler.h>

#include <FEXCore/Core/Thunks.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>
#include "FEXCore/Debug/InternalThreadState.h"

#include <algorithm>

namespace FEXCore::Context {
fextl::unique_ptr<FEXCore::Context::Context> FEXCore::Context::Context::CreateNewContext(const FEXCore::HostFeatures& Features) {
  return fextl::make_unique<FEXCore::Context::ContextImpl>(Features);
}

void FEXCore::Context::ContextImpl::CompileRIP(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP) {
  CompileBlock(Thread->CurrentFrame, GuestRIP);
}

void FEXCore::Context::ContextImpl::CompileRIPCount(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst) {
  CompileBlock(Thread->CurrentFrame, GuestRIP, MaxInst);
}

void FEXCore::Context::ContextImpl::SetSignalDelegator(FEXCore::SignalDelegator* _SignalDelegation) {
  SignalDelegation = _SignalDelegation;
}

void FEXCore::Context::ContextImpl::SetSyscallHandler(FEXCore::HLE::SyscallHandler* Handler) {
  SyscallHandler = Handler;
  SourcecodeResolver = Handler->GetSourcecodeResolver();
}

void FEXCore::Context::ContextImpl::SetThunkHandler(FEXCore::ThunkHandler* Handler) {
  ThunkHandler = Handler;
}

FEXCore::CPUID::FunctionResults FEXCore::Context::ContextImpl::RunCPUIDFunction(uint32_t Function, uint32_t Leaf) {
  return CPUID.RunFunction(Function, Leaf);
}

FEXCore::CPUID::XCRResults FEXCore::Context::ContextImpl::RunXCRFunction(uint32_t Function) {
  return CPUID.RunXCRFunction(Function);
}

FEXCore::CPUID::FunctionResults FEXCore::Context::ContextImpl::RunCPUIDFunctionName(uint32_t Function, uint32_t Leaf, uint32_t CPU) {
  return CPUID.RunFunctionName(Function, Leaf, CPU);
}

bool FEXCore::Context::ContextImpl::IsAddressInCodeBuffer(FEXCore::Core::InternalThreadState* Thread, uintptr_t Address) const {
  return Thread->CPUBackend->IsAddressInCodeBuffer(Address);
}

bool FEXCore::Context::ContextImpl::GuestRangeOverlapsCompiledCode(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  return Thread->LookupCache->RangeOverlapsCompiledCode(Start, Length);
}

// SMC Idea 4 (FEX_SMCSEMANTICPATCH). See Interface/Core/SMCSemanticPatch.h for
// the design, the PPC64LE exit-structure analysis, and the soundness argument.
bool FEXCore::Context::ContextImpl::TrySemanticPatchCodeRange(uint64_t Start, uint64_t Length, const void* NewBytes, const char** Reason) {
#ifdef ARCHITECTURE_ppc64le
  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");

  if (!Config.SMCSemanticPatch()) {
    *Reason = "flag-off";
    return false;
  }
  if (Length == 0 || Length > 4) {
    // A store wider than the field itself cannot be contained by it; a
    // zero-length write is nonsense. Either way, not our case.
    *Reason = "width";
    return false;
  }

  // Two phases over every code buffer: plan everything first, apply only if no
  // buffer declined. A partially applied patch would leave one thread's copy of
  // the branch pointing at the old target.
  fextl::vector<FEXCore::SMC::WordPatch> Patches;
  bool AnyCandidate = false;

  {
    std::scoped_lock lk {CodeBufferListLock};
    auto it = CodeBufferList.begin();
    while (it != CodeBufferList.end()) {
      auto Strong = it->lock();
      if (!Strong) {
        it = CodeBufferList.erase(it);
        continue;
      }
      it++;

      auto rlk = Strong->LookupCache->AcquireReadLock();
      switch (Strong->LookupCache->PlanSemanticPatch(Start, Length, static_cast<const uint8_t*>(NewBytes), Patches, Reason, rlk)) {
      case GuestToHostMap::SemanticPatchPlan::NoCandidate: break;
      case GuestToHostMap::SemanticPatchPlan::Planned: AnyCandidate = true; break;
      case GuestToHostMap::SemanticPatchPlan::Decline: return false;
      }
    }
  }

  if (!AnyCandidate) {
    // Nothing compiled claims this write as a branch immediate. It may not even
    // overlap code -- the SMCStoreEmulation fast path above us handles that
    // case; here it just means "not a recognised patch".
    *Reason = "no-claiming-block";
    return false;
  }

  // Publish. Each entry is one naturally-aligned instruction word plus the
  // tree's existing code-publication sequence.
  for (const auto& Patch : Patches) {
    FEXCore::SMC::ApplyWordPatch(Patch);
  }
  return true;
#else
  (void)Start;
  (void)Length;
  (void)NewBytes;
  *Reason = "not-ppc64le";
  return false;
#endif
}

// Cheap compile tier (FEX_SMCCHEAPTIER); see the comment on SMCPageCounters.
namespace {
// An invalidation this large is a mapping being torn down or replaced, not
// arena churn. Counting every page of it would flood the table and drag
// unrelated code into the cheap tier.
constexpr uint64_t SMCMaxCountedInvalidationSize = 1 * 1024 * 1024;
} // namespace

void FEXCore::Context::ContextImpl::RecordCodeRangeInvalidation(uint64_t Start, uint64_t Length) {
  if (!Config.SMCCheapTier() || Length > SMCMaxCountedInvalidationSize) {
    return;
  }

  const uint64_t Base = Start & FEXCore::Utils::FEX_PAGE_MASK;
  const uint64_t Top = FEXCore::AlignUp(Start + std::max<uint64_t>(Length, 1), FEXCore::Utils::FEX_PAGE_SIZE);

  for (uint64_t Page = Base; Page < Top; Page += FEXCore::Utils::FEX_PAGE_SIZE) {
    auto& Slot = SMCPageCounters[(Page >> FEXCore::Utils::FEX_PAGE_SHIFT) & (SMCPageCounterSlots - 1)];
    if (Slot.Page.load(std::memory_order_relaxed) != Page) {
      // Steal the slot from whichever page held it.
      Slot.Page.store(Page, std::memory_order_relaxed);
      Slot.Count.store(1, std::memory_order_relaxed);
    } else {
      // Saturate rather than wrap: a page that crossed the threshold must not
      // fall back out of the cheap tier after 2^32 more invalidations.
      const uint32_t Count = Slot.Count.load(std::memory_order_relaxed);
      if (Count != ~0u) {
        Slot.Count.store(Count + 1, std::memory_order_relaxed);
      }
    }
  }
}

bool FEXCore::Context::ContextImpl::ShouldUseCheapTier(uint64_t GuestRIP) {
  if (!Config.SMCCheapTier()) {
    return false;
  }

  const uint64_t Page = GuestRIP & FEXCore::Utils::FEX_PAGE_MASK;
  const auto& Slot = SMCPageCounters[(Page >> FEXCore::Utils::FEX_PAGE_SHIFT) & (SMCPageCounterSlots - 1)];
  if (Slot.Page.load(std::memory_order_relaxed) != Page) {
    return false;
  }
  return Slot.Count.load(std::memory_order_relaxed) >= Config.SMCCheapTierThreshold();
}
} // namespace FEXCore::Context
