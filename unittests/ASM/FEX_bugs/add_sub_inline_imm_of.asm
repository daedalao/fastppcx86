%ifdef CONFIG
{
  "RegData": {
    "R8":  "1",
    "R9":  "0",
    "R10": "1",
    "R11": "1",
    "R12": "0",
    "R13": "1",
    "RAX": "1"
  }
}
%endif

; PPC64LE backend: 64-bit ADD/SUB/CMP with a small inline immediate leaves
; XER.OV stale, so x86 OF retains its previous value instead of being updated.
;
; Mechanism (FEXCore/Source/Interface/Core/JIT/PPC64LE/ALUOps.cpp):
;   AddWithFlags (:1524-1526) and SubWithFlags (:1579-1580) take an
;   addic_ / subfic fast path when the immediate fits in int16. PPC's addic.
;   sets CA and CR0 but *not* OV — the in-tree comment says so explicitly.
;   The 8/16-bit paths use the shift-up trick and the 32-bit path repeats the
;   operation with addco_ to fix CA/OV, but the 64-bit path falls straight
;   through with no OV write. LoadNZCV (:3318) then reads x86 OF from XER.OV,
;   so the stale bit is observable at SETO.
;
; Reachability: this tree inlines constants at emission (ConstProp was dropped
; in 40beef061). AddWithFlags/SubWithFlags declare "Inline": ["", "LargeAddSub"]
; and DEF_INLINE(LargeAddSub, ...) admits IsImmAddSub at Size >= i32Bit, so the
; immediate 1 is inlined at i64 and lands in the addic_ range. For SUB the
; negated constant is -1, which is non-zero and so does not take the
; subfco_-forcing special case for C2 == 0.
;
; Operand values load from memory so nothing can fold the operation away.
;
; PRIMING: each probe sets OF to a known value with a register-register ADD,
; which goes through addco_ and does write OV. The `seto r14b` after each
; priming add is load-bearing, not decorative: RedundantFlagCalculationElimination
; (:208-213) demotes AddWithFlags to a plain OP_ADD when its NZCV result is
; never read, which would delete the addco_ and leave OF holding whatever it
; had at block entry. Reading V keeps the flag calculation alive. r14 is scratch
; and is reloaded before every use; r15 must NOT be used for this, because in
; the R13 block it is loaded before the priming and would be clobbered.
;
; CONTROLS. Two probes are expected to pass with or without the bug, and exist
; to localise a failure rather than to test the feature:
;   R13 — register-operand ADD, which uses addco_ unconditionally.
;   RAX — 32-bit inline-immediate ADD, where the i32 path redoes the operation
;         with addco_ (:1534-1543) and so fixes OV.
; If either control fails, suspect this test's priming or capture, not the
; inline-immediate path.
;
; NOT COVERED: the i64 inline-immediate paths of AddNZCV (:1645) and SubNZCV
; (:1686). CMP at 64-bit lowers through SubWithFlags, not SubNZCV
; (Flags.cpp:347-351 selects SubWithFlags for SrcSize >= i32Bit), so R11
; exercises the same path as R10. The NZCV variants carry the same addic_ fast
; path and are very likely to have the same defect, but a green run here does
; not establish that.

; ---- R8: inline-immediate ADD must SET OF (prior OF=0) ----
mov rax, [rel .int64_max]
mov r14, [rel .one]
add r14, r14                ; register path -> OF = 0
seto r14b                   ; keep the flag calculation live
add rax, 1                  ; 0x7FFF..FF + 1 overflows: x86 OF = 1
seto r8b
movzx r8d, r8b

; ---- R9: inline-immediate ADD must CLEAR OF (prior OF=1) ----
mov rbx, [rel .zero]
mov r14, [rel .int64_max]
add r14, r14                ; INT64_MAX + INT64_MAX overflows -> OF = 1
seto r14b
add rbx, 1                  ; 0 + 1 does not overflow: x86 OF = 0
seto r9b
movzx r9d, r9b

; ---- R10: inline-immediate SUB must SET OF (prior OF=0) ----
mov rcx, [rel .int64_min]
mov r14, [rel .one]
add r14, r14                ; OF = 0
seto r14b
sub rcx, 1                  ; 0x8000..00 - 1 overflows: x86 OF = 1
seto r10b
movzx r10d, r10b

; ---- R11: inline-immediate CMP must SET OF (prior OF=0) ----
mov rdx, [rel .int64_min]
mov r14, [rel .one]
add r14, r14                ; OF = 0
seto r14b
cmp rdx, 1                  ; INT64_MIN - 1 overflows: x86 OF = 1
seto r11b
movzx r11d, r11b

; ---- R12: inline-immediate SUB must CLEAR OF (prior OF=1) ----
mov rsi, [rel .zero]
mov r14, [rel .int64_max]
add r14, r14                ; OF = 1
seto r14b
sub rsi, 1                  ; 0 - 1 = -1, no signed overflow: x86 OF = 0
seto r12b
movzx r12d, r12b

; ---- R13: CONTROL. Register-operand ADD, uses addco_ and sets OV ----
mov rdi, [rel .int64_max]
mov r15, [rel .one]
mov r14, [rel .one]
add r14, r14                ; OF = 0
seto r14b
add rdi, r15                ; register path: x86 OF = 1, expected correct today
seto r13b
movzx r13d, r13b

; ---- RAX: CONTROL. 32-bit inline-immediate ADD, i32 path redoes with addco_ ----
mov ecx, [rel .int32_max]
mov r14, [rel .one]
add r14, r14                ; OF = 0
seto r14b
add ecx, 1                  ; 0x7FFFFFFF + 1 overflows: x86 OF = 1
seto al
movzx eax, al

hlt

align 4096
.int64_max:
dq 0x7FFFFFFFFFFFFFFF

.int64_min:
dq 0x8000000000000000

.one:
dq 1

.zero:
dq 0

.int32_max:
dd 0x7FFFFFFF
