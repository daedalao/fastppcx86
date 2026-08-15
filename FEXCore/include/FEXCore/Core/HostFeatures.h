// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/fextl/vector.h>
#include <cstdint>

namespace FEXCore {
struct HostFeatures {
  /**
   * @brief Backend features that change how codegen is generated from IR
   *
   * Specifically things that affect the IR->Codegen process
   * Not the x86->IR process
   */
  uint32_t DCacheLineSize {};
  uint32_t ICacheLineSize {};
  bool SupportsCacheMaintenanceOps {};
  bool SupportsAES {};
  bool SupportsCRC {};
  bool SupportsCLZERO {};
  bool SupportsAtomics {};
  bool SupportsRCPC {};
  bool SupportsTSOImm9 {};
  // Host can fold a full signed 16-bit displacement into a TSO GPR access.
  // Set on PPC64LE: the TSO barrier (lwsync) is a separate instruction, so the
  // access itself may use any addressing form — the LDAPUR-style SIMM9
  // restriction behind SupportsTSOImm9 is an ARM artifact. Never set on ARM64.
  bool SupportsTSODisp16 {};
  bool SupportsRAND {};
  bool SupportsAVX {};
  bool SupportsSVE128 {};
  bool SupportsSVE256 {};
  bool SupportsSHA {};
  bool SupportsPMULL_128Bit {};
  bool SupportsCSSC {};
  bool SupportsFCMA {};
  bool SupportsFlagM {};
  bool SupportsFlagM2 {};
  // Backend implements the fused FCmpX86 op (FCmp+AXFLAG+PF in one lowering).
  // Set only by backends where the split path is expensive (PPC64LE: two
  // serializing XER round-trips plus a CR1 projection per float compare).
  bool SupportsFCmpX86 {};
  bool SupportsRPRES {};
  bool SupportsPreserveAllABI {};
  bool SupportsAES256 {};
  bool SupportsSVEBitPerm {};
  bool SupportsCPUIndexInTPIDRRO {};
  bool SupportsFRINTTS {};
  bool SupportsECV {};
  bool SupportsWFXT {};
  bool Supports3DNow {};
  bool SupportsSSE4a {};
  bool SupportsMOPS {};

  // Power ISA v3.0 (POWER9 and later). Named by ISA level rather than by chip:
  // PPC_FEATURE2_ARCH_3_00 is also set on POWER10, so SupportsPOWER9 would be wrong there.
  // Gates every ISA 3.0 codegen path in the PPC64LE backend so a POWER8 host takes the older
  // sequence rather than SIGILLing. Force off with FEX_HOSTFEATURES=disableisa30 to exercise the
  // POWER8 path on POWER9 hardware — the only way the pre-3.0 paths stay tested.
  bool SupportsISA30 {};

  // The backend implements OP_CONDJUMP with VCmpElementSize != iInvalid: a
  // conditional branch whose condition is "did any lane of Cmp1 == Cmp2"
  // evaluated straight out of a record-form vector compare's condition field,
  // with no lane mask ever reaching a GPR. Only the PPC64LE backend does
  // (vcmpequ{b,h,w}. -> CR6 -> bc); the frontend's glibc vector-scan fusion is
  // gated on this so no other backend can be handed an IR shape it will not
  // recognise. There is deliberately no FEX_HOSTFEATURES toggle for it: the
  // A/B knob lives one level up as FEX_VCMPFUSION=0, which leaves the backend
  // capable but stops the frontend from ever forming the pattern, so the two
  // sides of a measurement differ in exactly one thing.
  bool SupportsVCmpFlagBranch {};

  // The backend lowers the Select-class ImplicitFlagClobber ops — Select,
  // VFMinScalarInsert/VFMaxScalarInsert, MaskGenerateFromBitWidth — without
  // writing any host flag state, so the frontend's SaveNZCV may skip the
  // save/restore round-trip for them. ImplicitFlagClobber in IR.json models
  // the ARM64 lowerings (csel/fcmp/bit-mask sequences that trash host NZCV);
  // a backend whose guest-NZCV storage survives these ops sets this instead
  // of un-marking the ops, keeping the IR metadata host-neutral. Like
  // SupportsVCmpFlagBranch this is a *backend capability* flag, not a CPU
  // feature, and is false everywhere but PPC64LE.
  bool SupportsFlagTransparentSelect {};

  // Float exception behaviour
  bool SupportsAFP {};
  bool SupportsFloatExceptions {};

  // Flag if this is InstCountCI
  bool IsInstCountCI {};

  // MIDR information
  // Also used for determining number of CPU cores for CPUID
  fextl::vector<uint32_t> CPUMIDRs;
};
} // namespace FEXCore
