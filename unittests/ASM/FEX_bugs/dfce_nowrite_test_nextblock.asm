%ifdef CONFIG
{
  "RegData": {
    "RAX": "0xB5"
  }
}
%endif

; The exact ReplacementNoWrite shape, TEST flavour (DFCE gating test for the
; 64-bit-only enable of 2026-08-13), plus the TestNZ -> TestZ demotion that
; only the ReplacementNoWrite arm can revive.
;
;     test r8, r9        ; AndWithFlags: value feeds only StorePF
;     jmp  next
;   next:
;     jcc  taken         ; flag consumer in the NEXT block
;     ...
;     xor  r15, r15      ; kills NZCV+PF+AF on every path
;
; Under jit_500_m, PF is dead across the join, StorePF goes away, and the
; value-dead AndWithFlags with a live NZCV write is rewritten to TestNZ.
; DFCE's follow-up demotion (TestNZ -> TestZ, sub-32-bit only) then fires
; IFF neither N nor C is live -- per the converged CROSS-BLOCK liveness.
;
; What this pins:
;  * TestNZ produced by the rewrite delivers Z and N across the block
;    boundary, both polarities each (a wrong elimination makes a pair's two
;    legs agree, flipping a bit of RAX).
;  * TestNZ must CLEAR carry (x86 TEST: CF=0). On PPC64LE that is the
;    OE=1 addco XER-clear in DEF_OP(TestNZ) -- the and./andi. alone leaves
;    XER.CA stale. The jnc leg makes a PRIOR CF=1 unremovable (its stc is
;    consumed by a jc whose two edges land on the same label), so a missing
;    clear reads CF=1 and the leg fails.
;  * The 16-bit js legs pin the demotion GATE: N is consumed cross-block,
;    so demotion to TestZ (which does not produce a valid N for the
;    operand size) must NOT fire. If cross-block N-liveness under-reports,
;    demotion produces TestZ and the sign legs read garbage. High bits of
;    the sources are poisoned so a size-confused (64-bit) sign or zero
;    check also fails: L6/L7 have nonzero high-garbage AND, L8 has sign64=0
;    where sign16=1, L9 has sign64=1 where sign16=0.
;  * The 16-bit jz legs pin the demotion RESULT: only Z live -> TestZ(i16)
;    must honour the 16-bit width (extsh_-class refinement).
;
; Legs into RAX (bit set iff taken):
;   bit0 jz  64-bit (5,2)        AND=0      -> taken
;   bit1 jz  64-bit (3,1)        AND=1      -> not
;   bit2 js  64-bit (MIN64,-1)   sign=1     -> taken
;   bit3 js  64-bit (1,3)        AND=1      -> not
;   bit4 jnc 64-bit after live stc          -> taken (TEST cleared CF)
;   bit5 jz  16-bit 0x0F00&0x00F0=0         -> taken (garbage high bits)
;   bit6 jz  16-bit 0x0F00&0x0700=0x700     -> not
;   bit7 js  16-bit 0x8000&0x8000, sign16=1 -> taken (sign64 would be 0)
;   bit8 js  16-bit 0x4000&0x4000, sign16=0 -> not   (sign64 would be 1)
; Expected RAX = 0b1011_0101 = 0xB5.

%macro TLEG 4   ; %1 = RAX bit, %2 = jcc, %3/%4 = 64-bit test operands
  mov r8, %3
  mov r9, %4
  test r8, r9
  jmp %%next
%%next:
  %2 %%taken
  jmp %%merge
%%taken:
  or rax, %1
%%merge:
  xor r15, r15
%endmacro

%macro TLEG16 4 ; %1 = RAX bit, %2 = jcc, %3/%4 = full 64-bit loads, test is 16-bit
  mov r8, %3
  mov r9, %4
  test r8w, r9w
  jmp %%next
%%next:
  %2 %%taken
  jmp %%merge
%%taken:
  or rax, %1
%%merge:
  xor r15, r15
%endmacro

xor rax, rax

TLEG 0x01, jz, 5, 2
TLEG 0x02, jz, 3, 1
TLEG 0x04, js, 0x8000000000000000, -1
TLEG 0x08, js, 1, 3

; jnc leg: the stc below cannot be eliminated -- its carry is consumed by the
; jc, whose taken and fall-through edges both land on the same label, so the
; leg proceeds with an architecturally guaranteed CF=1 into the TEST.
mov r8, 0xF0
mov r9, 0x0F
stc
jc cf_live_in
cf_live_in:
test r8, r9
jmp cf_next
cf_next:
jnc cf_taken
jmp cf_merge
cf_taken:
or rax, 0x10
cf_merge:
xor r15, r15

TLEG16 0x020, jz, 0xFFFFFFFFFFFF0F00, 0xEEEEEEEEEEEE00F0
TLEG16 0x040, jz, 0xFFFFFFFFFFFF0F00, 0xEEEEEEEEEEEE0700
TLEG16 0x080, js, 0x0000000000008000, 0x7FFFFFFFFFFF8000
TLEG16 0x100, js, 0x8000000000004000, 0xFFFFFFFFFFFF4000

hlt
