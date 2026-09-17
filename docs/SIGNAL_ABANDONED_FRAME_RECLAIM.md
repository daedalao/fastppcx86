# Signal handlers that never return: abandoned-frame reclaim

**Status:** landed 2026-09-17. Test: `unittests/FEXLinuxTests/tests/signal/siglongjmp_handler.cpp`.
Code: `SignalDelegator.cpp` ("Abandoned-frame reclaim" comment above `StoreThreadState`),
`SignalDelegator/GuestFramesManagement.cpp` (`LayoutFrame_*`), `ThreadManager.h`
(`SignalInfo.OutstandingBackups`).

## The defect

A guest signal delivery copies the interrupted host context into a `ContextBackup`
carved out of the **host** stack under the interrupted SP, and lowers the SP under it
so the dispatcher runs the guest handler beneath the saved context. The handler's
`rt_sigreturn` restores the SP. A handler the guest leaves any other way, `siglongjmp`
out of it, a `swapcontext` that never returns, a managed-exception unwind, never
sigreturns, so the host SP stays lowered by one backup (several KB on ppc64le:
ucontext, VMX/VSX, the full guest `CPUState`) for the rest of the thread's life.
About 2,500 such handlers exhaust an 8 MB host stack; intermittent crashes come
earlier because deep host frames (compiler, syscalls) hit the lowered region first.
Upstream FEX has the same structure. Reported by the co-dev from a `callret.c` test
against a Raspberry Pi oracle.

## The rule

The kernel has no such problem: its frame lives on the *user* stack, so a frame the
program has reused is simply gone. FEX now applies the same rule to the host copy.

Every tracked delivery records `{backup address, interrupted host SP, guest slot
address, cookie}` in the thread's `OutstandingBackups` (a fixed array, oldest first)
and writes `{backup, cookie}` into the guest frame's host-stack slot (widened from 8 to
16 bytes; it sits above the fpstate, below the guest red zone, invisible to the guest).
A backup is **abandoned** when its slot no longer holds the pair (read with
`process_vm_readv`, which never faults and works with `SIGSEGV` blocked), or when the
slot lies inside the extent of the frame about to be built (same-address rebuilds, e.g.
every alternate-stack delivery). A sigreturn on such a frame would already be
undefined on Linux, so the backup's host region is dead.

`StoreThreadState` then places the new backup *inside* the newest run of abandoned
regions instead of under the current SP, once the geometry is the one delivery builds
(each entry under its predecessor, the current SP at or under the newest entry). A
host-side unwind (FexBridge nested run, thunk callback) breaks that geometry and the
code falls back to the classic placement, which is always safe. `ReclaimSlack` (160
bytes under every backup) is what makes a single abandoned region large enough for its
successor, so a storm of longjmp'd handlers oscillates inside one backup's worth of
stack.

`RestoreThreadState` matches the returning frame's `{backup, cookie}` against the list
and drops every newer entry (a nested handler that has not returned when its outer one
does was abandoned; its backup is below and is being unwound). An untracked frame (list
overflow at 128 entries, or a frame the guest resurrected after reclaim) keeps the old
behaviour of trusting the slot pointer, with a `FEX_SIGTRACE` line.

`SignalHandlerRefCounter` is balanced for reclaimed and dropped entries; it is
diagnostic-only in this tree.

## Delivery order change

`SpillSRA` now runs *before* `StoreThreadState` in `HandleDispatcherGuestSignal`: the
frame layout starts from the guest RSP, which a mid-block interrupt only has in a host
register until the spill commits it, and the backup captures the spilled state directly
(the post-spill re-capture is gone). The bogus-RSP bail-out now happens before any
host state is modified.

## Cost

A program whose handlers return pays one loop over an empty list per delivery. Probes
run only while handlers are nested or abandoned, one `process_vm_readv` per candidate
entry.
