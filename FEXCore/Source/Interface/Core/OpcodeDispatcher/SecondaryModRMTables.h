// SPDX-License-Identifier: MIT
#pragma once
#include "Interface/Core/OpcodeDispatcher.h"

namespace FEXCore::IR {
constexpr DispatchTableEntry OpDispatch_SecondaryModRMTables[] = {
  // REG /1
  {((0 << 3) | 0), 1, &OpDispatchBuilder::UnimplementedOp},
  {((0 << 3) | 1), 1, &OpDispatchBuilder::UnimplementedOp},

  // REG /2
  {((1 << 3) | 0), 1, &OpDispatchBuilder::XGetBVOp},
  {((1 << 3) | 5), 1, &OpDispatchBuilder::XEndOp},   // XEND (0F 01 /2 /5)
  {((1 << 3) | 6), 1, &OpDispatchBuilder::XTestOp},  // XTEST (0F 01 /2 /6)

  // REG /3
  {((2 << 3) | 7), 1, &OpDispatchBuilder::PermissionRestrictedOp},

  // REG /7
  {((3 << 3) | 0), 1, &OpDispatchBuilder::PermissionRestrictedOp},
  {((3 << 3) | 1), 1, &OpDispatchBuilder::RDTSCPOp},
  {((3 << 3) | 4), 1, &OpDispatchBuilder::CLZeroOp},
};

} // namespace FEXCore::IR
