// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/

#include "LinuxSyscalls/Seccomp/BPFInterpreter.h"

#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <bit>
#include <cerrno>
#include <cstring>

namespace FEX::HLE {
namespace {
  // BPF_ABS loads read raw 32-bit words out of seccomp_data at guest-chosen byte offsets, so the host must lay that struct out the same
  // way the guest expects. Both x86 guests and every host FEX targets are little-endian; a big-endian host would need byteswapping here.
  static_assert(std::endian::native == std::endian::little, "seccomp_data is accessed as raw little-endian words");

  constexpr uint32_t SECCOMP_DATA_SIZE = sizeof(struct seccomp_data);

  // The accumulator and index registers are 32-bit and every ALU operation wraps, matching the kernel's classic-BPF interpreter where
  // both live in u32s.
  struct State {
    uint32_t A {};
    uint32_t X {};
  };
} // namespace

uint64_t BPFInterpreter::ValidateProgram(const sock_fprog* prog) {
  const uint32_t NumInsts = prog->len;

  for (uint32_t i = 0; i < NumInsts; ++i) {
    const sock_filter* Inst = &prog->filter[i];
    const uint16_t Code = Inst->code;

    switch (BPF_CLASS(Code)) {
    case BPF_LD:
    case BPF_LDX: {
      // seccomp_check_filter only whitelists word-sized loads; there is no packet to read halfwords or bytes out of.
      if (BPF_SIZE(Code) != BPF_W) {
        return -EINVAL;
      }

      switch (BPF_MODE(Code)) {
      case BPF_IMM: break;
      case BPF_ABS:
        // kernel/seccomp.c: "32-bit aligned and not out of bounds". An out-of-range or misaligned offset is rejected at install time
        // rather than faulting or returning zero at run time, which is also what the JIT this replaces did.
        if ((Inst->k & 0b11) != 0 || Inst->k >= SECCOMP_DATA_SIZE) {
          return -EINVAL;
        }
        break;
      case BPF_MEM:
        // Scratch memory is BPF_MEMWORDS words and nothing else is addressable.
        if (Inst->k >= BPF_MEMWORDS) {
          return -EINVAL;
        }
        break;
      case BPF_LEN: break;
      case BPF_IND:
      case BPF_MSH:
      default:
        // BPF_IND and BPF_MSH index a packet buffer, which seccomp does not have. seccomp_check_filter's whitelist omits both, so a
        // filter using them cannot be installed on a real kernel either.
        return -EINVAL;
      }
      break;
    }
    case BPF_ST:
    case BPF_STX:
      if (BPF_SIZE(Code) != BPF_W) {
        return -EINVAL;
      }
      if (Inst->k >= BPF_MEMWORDS) {
        return -EINVAL;
      }
      break;

    case BPF_ALU:
      switch (BPF_OP(Code)) {
      case BPF_ADD:
      case BPF_SUB:
      case BPF_MUL:
      case BPF_DIV:
      case BPF_OR:
      case BPF_AND:
      case BPF_LSH:
      case BPF_RSH:
      case BPF_MOD:
      case BPF_XOR: break;
      case BPF_NEG:
        // NEG has no source operand; the source bit must be clear.
        if (BPF_SRC(Code) != BPF_K) {
          return -EINVAL;
        }
        break;
      default: return -EINVAL;
      }
      break;

    case BPF_JMP:
      switch (BPF_OP(Code)) {
      case BPF_JA: {
        if (BPF_SRC(Code) != BPF_K) {
          return -EINVAL;
        }

        // Jumps are forward-only and must land inside the program: loops are explicitly disallowed so a filter cannot be used to hang
        // the process. The 64-bit arithmetic keeps a large k from wrapping into a valid-looking target.
        const uint64_t Target = static_cast<uint64_t>(i) + Inst->k + 1;
        if (Target >= NumInsts) {
          return -EINVAL;
        }
        break;
      }
      case BPF_JEQ:
      case BPF_JGT:
      case BPF_JGE:
      case BPF_JSET: {
        // jt/jf are unsigned byte counts of instructions, so these are forward-only by construction.
        const uint64_t TargetTrue = static_cast<uint64_t>(i) + Inst->jt + 1;
        const uint64_t TargetFalse = static_cast<uint64_t>(i) + Inst->jf + 1;
        if (TargetTrue >= NumInsts || TargetFalse >= NumInsts) {
          return -EINVAL;
        }
        break;
      }
      default: return -EINVAL;
      }
      break;

    case BPF_RET:
      switch (BPF_RVAL(Code)) {
      case BPF_K:
      case BPF_X:
      case BPF_A: break;
      default: return -EINVAL;
      }
      break;

    case BPF_MISC:
      switch (BPF_MISCOP(Code)) {
      case BPF_TAX:
      case BPF_TXA: break;
      default: return -EINVAL;
      }
      break;

    default: return -EINVAL;
    }
  }

  // bpf_check_classic: the last instruction must be a RET. The JIT this replaces omitted the check and would have run off the end of the
  // emitted code into its constant pool; the interpreter needs the guarantee to terminate.
  if (BPF_CLASS(prog->filter[NumInsts - 1].code) != BPF_RET) {
    return -EINVAL;
  }

  return 0;
}

uint32_t BPFInterpreter::Execute(const sock_filter* Program, uint32_t NumInsts, WorkingBuffer* Buffer) {
  // Classic BPF starts with both registers zeroed. Scratch memory is zeroed by the caller, once per syscall rather than once per filter
  // chain, because each filter in the chain gets a fresh scratch space.
  State S {};

  const auto* DataBytes = reinterpret_cast<const uint8_t*>(&Buffer->Data);

  // Every instruction either falls through or jumps forward, and the program ends in a RET, so this terminates in at most NumInsts steps.
  for (uint32_t IP = 0; IP < NumInsts; ++IP) {
    const sock_filter* Inst = &Program[IP];
    const uint16_t Code = Inst->code;
    const uint32_t k = Inst->k;

    switch (BPF_CLASS(Code)) {
    case BPF_LD:
    case BPF_LDX: {
      uint32_t Value {};
      switch (BPF_MODE(Code)) {
      case BPF_IMM: Value = k; break;
      case BPF_ABS:
        // Validation guarantees the offset is aligned and in-range. memcpy because seccomp_data's members are not all 4-byte sized.
        memcpy(&Value, DataBytes + k, sizeof(Value));
        break;
      case BPF_MEM: Value = Buffer->ScratchMemory[k]; break;
      case BPF_LEN:
        // seccomp_check_filter rewrites BPF_LEN into an immediate load of sizeof(struct seccomp_data).
        Value = SECCOMP_DATA_SIZE;
        break;
      default:
        // Unreachable for validated programs. Fail closed.
        return 0;
      }

      if (BPF_CLASS(Code) == BPF_LD) {
        S.A = Value;
      } else {
        S.X = Value;
      }
      break;
    }

    case BPF_ST:
      // BPF_ST stores the accumulator, BPF_STX stores the index register. The JIT this replaces tested for BPF_CLASS() == BPF_LD here,
      // which is never true for a store, so it wrote X for both encodings.
      Buffer->ScratchMemory[k] = S.A;
      break;
    case BPF_STX: Buffer->ScratchMemory[k] = S.X; break;

    case BPF_ALU: {
      const uint32_t Src = BPF_SRC(Code) == BPF_X ? S.X : k;
      switch (BPF_OP(Code)) {
      case BPF_ADD: S.A += Src; break;
      case BPF_SUB: S.A -= Src; break;
      case BPF_MUL: S.A *= Src; break;
      case BPF_DIV:
        // Classic BPF terminates the program with a return value of 0 on division by zero. For seccomp a zero return is
        // SECCOMP_RET_KILL_THREAD, so this fails closed. (The kernel additionally rejects a zero immediate divisor at install time in
        // bpf_check_classic; handling it here covers both source forms.)
        if (Src == 0) {
          return 0;
        }
        S.A /= Src;
        break;
      case BPF_MOD:
        if (Src == 0) {
          return 0;
        }
        S.A %= Src;
        break;
      case BPF_OR: S.A |= Src; break;
      case BPF_AND: S.A &= Src; break;
      case BPF_XOR: S.A ^= Src; break;
      // Shift counts are masked to the register width. C would make an over-wide shift undefined, and the masking matches what both the
      // kernel's JITs and the AArch64 JIT this replaces did with a variable shift.
      case BPF_LSH: S.A <<= (Src & 31); break;
      case BPF_RSH: S.A >>= (Src & 31); break;
      case BPF_NEG: S.A = -S.A; break;
      default: return 0;
      }
      break;
    }

    case BPF_JMP: {
      const uint32_t Src = BPF_SRC(Code) == BPF_X ? S.X : k;
      switch (BPF_OP(Code)) {
      // The loop's own increment supplies the +1, so the jump distance is added directly to IP. Validation already proved every target
      // is in-range.
      case BPF_JA: IP += k; break;
      // Comparisons are unsigned, as in the kernel.
      case BPF_JEQ: IP += (S.A == Src) ? Inst->jt : Inst->jf; break;
      case BPF_JGT: IP += (S.A > Src) ? Inst->jt : Inst->jf; break;
      case BPF_JGE: IP += (S.A >= Src) ? Inst->jt : Inst->jf; break;
      case BPF_JSET: IP += ((S.A & Src) != 0) ? Inst->jt : Inst->jf; break;
      default: return 0;
      }
      break;
    }

    case BPF_RET:
      switch (BPF_RVAL(Code)) {
      case BPF_K: return k;
      case BPF_X: return S.X;
      case BPF_A: return S.A;
      default: return 0;
      }

    case BPF_MISC:
      switch (BPF_MISCOP(Code)) {
      case BPF_TAX: S.X = S.A; break;
      case BPF_TXA: S.A = S.X; break;
      default: return 0;
      }
      break;

    default: return 0;
    }
  }

  // Validation guarantees a trailing RET, so falling out of the loop means the program was never validated. Fail closed with
  // SECCOMP_RET_KILL_THREAD.
  return 0;
}

} // namespace FEX::HLE
