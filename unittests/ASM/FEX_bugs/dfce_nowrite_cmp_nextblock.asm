%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x155",
    "RBX": "0x15"
  }
}
%endif

; The exact ReplacementNoWrite shape, CMP flavour (DFCE gating test for the
; 64-bit-only enable of 2026-08-13).
;
;     cmp  r8, r9        ; SubWithFlags: value feeds only StorePF
;     jmp  next          ; block boundary (unconditional edge)
;   next:
;     jcc  taken         ; flag consumer in the NEXT block
;     ...
;     xor  r15, r15      ; kills NZCV+PF+AF on every path before exit
;
; Under jit_500_m, DFCE's converged liveness sees PF dead (the trailing xor
; covers every path), removes the StorePF, and the SubWithFlags is left with
; zero SSA uses but a live NZCV write -- ReplacementNoWrite rewrites it to
; SubNZCV in place. CompareBranchFusion cannot intercept: the consumer is in
; a different block. Under jit_1/jit_500 the flags cross the block boundary
; through CPUState instead and exit-block FLAG_ALL conservatism keeps the
; write; the architectural results below are identical in all three configs.
;
; What this pins:
;  * SubNZCV produced by the rewrite must deliver ALL FOUR NZCV bits
;    correctly across the block boundary: each condition is tested in BOTH
;    polarities, so if the flag write is wrongly eliminated (or the rewrite
;    miscomputes a bit) the two legs of a pair read the SAME stale state and
;    at least one bit of the accumulator flips.
;  * The 32-bit legs pin the shifted subfco_ path of the PPC64LE SubNZCV
;    lowering, including size handling: leg M5 plants DIFFERENT garbage in
;    the high 32 bits of equal 32-bit operands, so a size-confused compare
;    (64-bit instead of 32) reports not-equal and fails.
;
; 64-bit legs into RAX (bit set iff taken):
;   bit0 jb  (2,5)  CF=1 -> taken     bit1 jb  (5,2)  CF=0 -> not
;   bit2 je  (7,7)  ZF=1 -> taken     bit3 je  (7,9)  ZF=0 -> not
;   bit4 js  (1,3)  SF=1 -> taken     bit5 js  (3,1)  SF=0 -> not
;   bit6 jo  (INT64_MIN,1) OF=1 -> taken
;   bit7 jo  (5,1)  OF=0 -> not
;   bit8 jae (5,2)  CF=0 -> taken
; Expected RAX = 0b1_0101_0101 = 0x155.
;
; 32-bit legs into RBX:
;   bit0 jb (2,5) -> taken            bit1 jb (5,2) -> not
;   bit2 jo (INT32_MIN,1) -> taken    bit3 jo (5,1) -> not
;   bit4 je equal low halves, DIFFERENT garbage high halves -> taken
; Expected RBX = 0b1_0101 = 0x15.

%macro CLEG 4   ; %1 = RAX bit, %2 = jcc, %3/%4 = 64-bit cmp operands
  mov r8, %3
  mov r9, %4
  cmp r8, r9
  jmp %%next
%%next:
  %2 %%taken
  jmp %%merge
%%taken:
  or rax, %1
%%merge:
  xor r15, r15
%endmacro

%macro CLEG32 4 ; %1 = RBX bit, %2 = jcc, %3/%4 = full 64-bit loads, cmp is 32-bit
  mov r8, %3
  mov r9, %4
  cmp r8d, r9d
  jmp %%next
%%next:
  %2 %%taken
  jmp %%merge
%%taken:
  or rbx, %1
%%merge:
  xor r15, r15
%endmacro

xor rax, rax
xor rbx, rbx

CLEG 0x001, jb,  2, 5
CLEG 0x002, jb,  5, 2
CLEG 0x004, je,  7, 7
CLEG 0x008, je,  7, 9
CLEG 0x010, js,  1, 3
CLEG 0x020, js,  3, 1
CLEG 0x040, jo,  0x8000000000000000, 1
CLEG 0x080, jo,  5, 1
CLEG 0x100, jae, 5, 2

CLEG32 0x01, jb, 2, 5
CLEG32 0x02, jb, 5, 2
CLEG32 0x04, jo, 0x80000000, 1
CLEG32 0x08, jo, 5, 1
CLEG32 0x10, je, 0xAAAAAAAA11223344, 0xBBBBBBBB11223344

hlt
