// SPDX-License-Identifier: MIT
/*
$info$
meta: ir|opts ~ IR to IR Optimization
tags: ir|opts
desc: Defines which passes are run, and runs them
$end_info$
*/

#include "Interface/Context/Context.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Profiler.h>

namespace FEXCore::IR {
class IREmitter;

void PassManager::Finalize() {
  if (!PassManagerDumpIR()) {
    // Not configured to dump any IR, just return.
    return;
  }

  auto it = Passes.begin();
  // Walk the passes and add them where asked.
  if (PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::BEFOREOPT) {
    // Insert at the start.
    it = InsertAt(it, Debug::CreateIRDumper());
    ++it; // Skip what we inserted.
  }

  if ((PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::BEFOREPASS) ||
      (PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::AFTERPASS)) {

    bool SkipFirstBefore = PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::BEFOREOPT;
    for (; it != Passes.end();) {
      if (PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::BEFOREPASS) {
        if (SkipFirstBefore) {
          // If we need to skip the first one, then continue.
          SkipFirstBefore = false;
          ++it;
          continue;
        }

        // Insert before
        it = InsertAt(it, Debug::CreateIRDumper());
        ++it; // Skip what we inserted.
      }

      ++it; // Skip current pass.
      if (PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::AFTERPASS) {
        // Insert after
        it = InsertAt(it, Debug::CreateIRDumper());
        ++it; // Skip what we inserted.
      }
    }
  }
  if (PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::AFTEROPT) {
    if (!(PassManagerDumpIR() & FEXCore::Config::PassManagerDumpIR::AFTERPASS)) {
      // Insert final IRDumper.
      InsertAt(Passes.end(), Debug::CreateIRDumper());
    }
  }
}

void PassManager::AddDefaultPasses(FEXCore::Context::ContextImpl* ctx) {
  FEX_CONFIG_OPT(DisablePasses, O0);

  if (!DisablePasses()) {
    InsertPass(CreateX87StackOptimizationPass(ctx->HostFeatures, ctx->Config.Is64BitMode ? IR::OpSize::i64Bit : IR::OpSize::i32Bit));
    // PPC64LE: DeadFlagCalculationElimination is disabled for both 32-bit and
    // 64-bit guests. The pass's Replacement branch (e.g. SubWithFlags → Sub)
    // mutates IROp tags in place and leaves stale operand-class metadata that
    // the subsequent RA mis-resolves to a wrong SRA slot.
    //
    // 32-bit symptom: ld.so trips 'rpo_head == rpo' inside _dl_sort_maps_dfs
    //   at block sizes ≥ 9 instructions.
    // 64-bit symptom: bash's setup_variables function entry SEGVs on a host
    //   `lwzx r7, r24, r0` whose base register was supposed to be guest R11
    //   but RA bound it to guest R14 (host r22), which holds an unrelated
    //   8-byte ASCII slice from earlier in the block.
    //
    // The pass is purely a perf optimization; disabling costs cycles but not
    // correctness. The ASM suites are unaffected (those don't reach dense
    // flag-producing 9+-instruction blocks). The bash ASM patterns that
    // trigger the 64-bit case are dense hash-table walks in glibc / bash
    // internals.
    //
    // TODO: root-cause the RA/Replacement interaction and re-enable. Likely
    // the right fix is to invalidate the post-RA-merge candidate cache when
    // the pass rewrites an op's Op tag, or to do the rewrite after RA.
  }
}

void PassManager::AddDefaultValidationPasses() {
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  InsertValidationPass(Validation::CreateIRValidation(), "IRValidation");
#endif
}

void PassManager::InsertRegisterAllocationPass(FEXCore::Context::ContextImpl* ctx) {
  InsertPass(IR::CreateRegisterAllocationPass(&ctx->CPUID), "RA");
}

void PassManager::Run(IREmitter* IREmit) {
  FEXCORE_PROFILE_SCOPED("PassManager::Run");

  for (const auto& Pass : Passes) {
    Pass->Run(IREmit);
  }

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  for (const auto& Pass : ValidationPasses) {
    Pass->Run(IREmit);
  }
#endif
}
} // namespace FEXCore::IR
