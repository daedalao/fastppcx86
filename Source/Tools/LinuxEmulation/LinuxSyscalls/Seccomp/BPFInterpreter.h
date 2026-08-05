// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/
#pragma once

#include <linux/filter.h>
#include <linux/seccomp.h>

#include <cstdint>

struct sock_fprog;
struct sock_filter;

namespace FEX::HLE {
/**
 * @brief Classic-BPF (cBPF) interpreter for guest seccomp filters.
 *
 * This replaces the previous ARM64 JIT. A filter runs at most once per guest syscall, which is already a slow path, so interpretation
 * cost is irrelevant next to the requirement that this works on every host architecture FEX targets. The JIT emitted AArch64
 * instructions unconditionally, so on any non-ARM64 host a guest that installed a filter executed illegal instructions.
 *
 * Filters are consequently stored as their `sock_filter` program rather than as executable memory. Nothing outside of this class may
 * assume a filter is callable code.
 */
class BPFInterpreter final {
public:
  /// Layout the interpreter operates over. `Data` is what BPF_ABS loads see, `ScratchMemory` backs BPF_MEM/BPF_ST/BPF_STX.
  struct WorkingBuffer {
    struct seccomp_data Data;
    uint32_t ScratchMemory[BPF_MEMWORDS]; // Defined as 16 words.
  };

  /**
   * @brief Checks a guest program against everything the interpreter is willing to execute.
   *
   * Mirrors the kernel's two-stage acceptance: `seccomp_check_filter` (kernel/seccomp.c) whitelists the instruction encodings a seccomp
   * filter may contain, and `bpf_check_classic` (net/core/filter.c) enforces jump bounds, scratch-slot bounds and the trailing RET.
   * Executing a program that did not pass this is not defined.
   *
   * @return 0 when accepted, -EINVAL otherwise.
   */
  static uint64_t ValidateProgram(const sock_fprog* prog);

  /**
   * @brief Runs a program that ValidateProgram accepted.
   *
   * @return The raw 32-bit filter return value, split by the caller into SECCOMP_RET_ACTION_FULL and SECCOMP_RET_DATA.
   */
  static uint32_t Execute(const sock_filter* Program, uint32_t NumInsts, WorkingBuffer* Buffer);
};

} // namespace FEX::HLE
