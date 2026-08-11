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
  FEX_CONFIG_OPT(DisableDFCE, DISABLEDFCE);

  if (!DisablePasses()) {
    InsertPass(CreateX87StackOptimizationPass(ctx->HostFeatures, ctx->Config.Is64BitMode ? IR::OpSize::i64Bit : IR::OpSize::i32Bit));

    // DeadFlagCalculationElimination was disabled on PPC64LE from 2026-05-11
    // (8774c7dda) to 2026-08-05. The diagnosis recorded at the time -- "the
    // Replacement rewrite leaves stale operand-class metadata that RA
    // mis-resolves" -- was wrong. The actual defect was in the pass itself:
    // its ProcessBlock Remove site dropped nodes whose flag writes were dead
    // WITHOUT checking IR::HasSideEffects(), so side-effecting flag writers
    // (StoreNZCV/StorePF/StoreAF/InvalidateFlags/...) were deleted outright
    // rather than falling through to the in-place Replacement rewrite. That
    // was guarded from 2026-08-05 to 2026-08-10; the guard is now a runtime
    // knob (FEX_DISABLEDFCESTOREELIM, default off) after the reproducers were
    // re-verified clean with the Remove arm active. See the comment at the
    // Remove site in Passes/RedundantFlagCalculationElimination.cpp.
    //
    // The pass is a pure IR transform with no correctness mandate, and a
    // wrong flag elimination surfaces as a wrong conditional branch --
    // silent and data-dependent. So it gets its own persistent kill switch
    // rather than relying on FEX_O0 (which would also drop
    // X87StackOptimization and change x87 behaviour):
    //     FEX_DISABLEDFCE=1
    // turns just this pass off at runtime, no rebuild.
    if (!DisableDFCE()) {
      InsertPass(CreateDeadFlagCalculationEliminination());
    }
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
