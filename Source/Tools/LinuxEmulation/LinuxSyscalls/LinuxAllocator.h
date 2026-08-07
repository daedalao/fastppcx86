// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/fextl/memory.h>

#include <cstdint>
#include <memory>

namespace FEX::HLE {
constexpr uint32_t X86_64_MAP_32BIT = 0x40;

class MemAllocator {
public:
  virtual ~MemAllocator() = default;
  virtual void* Mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) = 0;
  virtual int Munmap(void* addr, size_t length) = 0;
  virtual void* Mremap(void* old_address, size_t old_size, size_t new_size, int flags, void* new_address) = 0;
  virtual uint64_t Shmat(int shmid, const void* shmaddr, int shmflg, uint32_t* ResultAddress) = 0;
  virtual uint64_t Shmdt(const void* shmaddr) = 0;

  /**
   * Register a host-owned range that lives inside the guest's 32-bit address
   * space — currently the two thunk trampoline pools, which must sit below
   * 4 GiB so their addresses survive being stored in guest pointer slots.
   *
   * These pages hold *host* instructions that the host branches to. If a guest
   * MAP_FIXED, munmap or MREMAP_FIXED replaces them, the host then executes
   * whatever the guest put there. Marking them used in the allocator's bitmap
   * is not enough: the explicit-address paths honour the guest's request
   * without consulting the bitmap at all, which is the whole point of
   * MAP_FIXED. So track them separately and refuse to service a guest request
   * that would destroy one.
   *
   * No-op for the passthrough allocator, where no such aliasing exists.
   */
  virtual void ReserveHostRange(uintptr_t Base, size_t Length) {}
};

fextl::unique_ptr<FEX::HLE::MemAllocator> Create32BitAllocator();
fextl::unique_ptr<FEX::HLE::MemAllocator> CreatePassthroughAllocator();
} // namespace FEX::HLE
