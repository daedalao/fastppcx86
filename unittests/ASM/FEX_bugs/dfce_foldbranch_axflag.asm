%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x6",
    "RBX": "0x4",
    "RDX": "0x9",
    "RSI": "0xB",
    "RDI": "0xA"
  },
  "MemoryRegions": {
    "0xe0000000": "4096"
  }
}
%endif

; DeadFlagCalculationElimination::FoldBranch, AXFLAG arm.
;
; When NZCV is dead after a CondJump that reads NZCV, FoldBranch pattern
; matches the instruction feeding it. If that is an AXFLAG, the AXFLAG node is
; DELETED and the branch condition is remapped through X86ToArmFloatCond --
; i.e. the branch is re-expressed against the RAW Arm FCMP flag layout
; (N=less, Z=equal, C=!less, V=unordered) instead of the x86-mapped layout
; AXFLAG would have produced.
;
; STATUS: the AXFLAG arm of FoldBranch is explicitly DISABLED (see the comment
; in RedundantFlagCalculationElimination.cpp). It was already unreachable on
; ppc64le -- a GuestOpcode marker is emitted before every guest instruction, so
; FoldBranch's predecessor walk never sees the AXFLAG -- and when that walk was
; temporarily taught to skip the marker, this file failed under jit_500_m:
;   RAX (jae) = 0xE, expected 0x6   branch taken on UNORDERED
;   RDI (jle) = 0xB, expected 0xA   branch taken on ordered LESS
; i.e. two of the five remappable conditions are wrong. This file therefore
; documents the correct x86 answers and is the acceptance test for anyone who
; wants to re-enable the fold; today it passes via the ordinary
; FCmp+AXFlag+CondJump path, which is itself worth pinning.
;
; The fold makes the backend's MapNZCVCC responsible for conditions (FGE, and
; in principle FLU) that nothing else in the tree produces, evaluated against
; CR0/XER as written by DEF_OP(FCmp) -- which lifts CR0.SO into XER.OV and
; !CR0.LT into XER.CA precisely so the Arm NZCV layout holds. MapNZCVCC maps
; FGE to PPC CC_GE ("CR0.LT clear"), which is true for NaN; Arm GE is N==V,
; which is not. That is defect 1. Defect 2 is in the shared mapping table:
; X86ToArmFloatCond maps SLE to SLE unchanged, but x86 `jle` after comiss means
; "equal or unordered" (comiss forces SF=OF=0 and AXFLAG sets Z=Z|V) while Arm
; LE on the raw fcmp flags is "equal or less or unordered".
;
; `comiss` + jcc is the only shape that reaches it: the dispatcher emits
; FCmp, StorePF, StoreAF, AXFlag in that order, and FoldBranch's predecessor
; walk skips StorePF/StoreAF/StoreRegister, so the AXFLAG is adjacent to the
; jump.
;
; Each of the five conditions X86ToArmFloatCond can remap is tested against
; all four comiss outcomes. Results are bitmasks over the outcome:
;   bit0 = less, bit1 = equal, bit2 = greater, bit3 = unordered
; A bit is set iff the branch was TAKEN for that outcome. comiss sets
; ZF/PF/CF = 111 unordered, 100 equal, 001 less, 000 greater, and always
; clears OF/SF/AF, which gives:
;   jae (CF=0)           -> equal|greater             = 0x6
;   ja  (CF=0 && ZF=0)   -> greater                   = 0x4
;   jb  (CF=1)           -> less|unordered            = 0x9
;   jbe (CF=1 || ZF=1)   -> less|equal|unordered      = 0xB
;   jle (ZF=1, SF==OF=0) -> equal|unordered           = 0xA
;
; The `xor r15, r15` at each merge point (and the `or` on the taken path) is
; what makes NZCV dead after the branch, which is what enables the fold. Both
; successors of every CondJump must write NZCV before reading it or the fold
; does not fire and the subtest degenerates into an ordinary AXFLAG test.

%macro CHK 4      ; %1 = dest reg, %2 = jcc, %3 = outcome bit, %4 = operand offset
  movss xmm0, [r14 + %4]
  movss xmm1, [r14 + 16]
  comiss xmm0, xmm1
  %2 %%taken
  jmp %%done
%%taken:
  or %1, %3
%%done:
  xor r15, r15
%endmacro

%macro CHKALL 2   ; %1 = dest reg, %2 = jcc
  CHK %1, %2, 1, 0    ; 1.0 vs 2.0 -> less
  CHK %1, %2, 2, 4    ; 2.0 vs 2.0 -> equal
  CHK %1, %2, 4, 8    ; 3.0 vs 2.0 -> greater
  CHK %1, %2, 8, 12   ; NaN vs 2.0 -> unordered
%endmacro

mov r14, 0xe0000000
mov dword [r14 +  0], 0x3F800000   ; 1.0f
mov dword [r14 +  4], 0x40000000   ; 2.0f
mov dword [r14 +  8], 0x40400000   ; 3.0f
mov dword [r14 + 12], 0x7FC00000   ; QNaN
mov dword [r14 + 16], 0x40000000   ; 2.0f (right-hand operand for every compare)

xor rax, rax
xor rbx, rbx
xor rdx, rdx
xor rsi, rsi
xor rdi, rdi

CHKALL rax, jae    ; UGE -> FGE
CHKALL rbx, ja     ; UGT -> FGT
CHKALL rdx, jb     ; ULT -> SLT
CHKALL rsi, jbe    ; ULE -> SLE
CHKALL rdi, jle    ; SLE -> SLE (identity remap; AXFLAG still deleted)

hlt
