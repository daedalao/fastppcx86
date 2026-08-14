%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x5"
  }
}
%endif

; Cross-block flag liveness through a JOIN, both paths (DFCE gating test).
;
; Shape: flags are DEFINED in block A, CONDITIONALLY CLOBBERED in block B,
; and CONSUMED in block C after the join:
;
;     A:  cmp  r8, r9        ; NZCV def; value-dead (PF killed at the merge)
;         jne  join          ; reads only Z; carry NOT consumed in A
;     B:  cmp  r10, r11      ; full clobber, executed only when r8 == r9
;     join (C):
;         jc   taken         ; consumes CARRY: from A (direct) or B (clobber)
;
; What this pins in DeadFlagCalculationElimination (jit_500_m):
;  * A's carry write is live ONLY via the cross-block A->C edge (A's own exit
;    reads just Z, and B overwrites everything). Liveness at A's exit must be
;    the UNION over successors -- treating B's clobber as a must-kill (or
;    intersecting at the join) deems A's carry dead, the value-dead cmp takes
;    the fully-dead Replacement/Remove path instead of ReplacementNoWrite,
;    and the direct-path legs read stale carry -> wrong branch -> wrong RAX.
;  * B's cmp is itself value-dead with only C live downstream (the exact
;    ReplacementNoWrite shape, SubWithFlags -> SubNZCV); leg 3 chooses A/B
;    operands with OPPOSITE carry so dropping B's write is also visible.
;  * Both polarities of both paths are tested, so ANY wrongly-eliminated
;    flag write flips at least one leg regardless of what stale state the
;    consumer then reads.
;
; Legs (bit set iff jc taken):
;   bit0: direct path (1 != 2), A carry = 1          -> taken
;   bit1: direct path (9 != 7), A carry = 0          -> not taken
;   bit2: clobber path (4 == 4), B carry = 1 (3 < 5) -> taken (A carry = 0!)
;   bit3: clobber path (4 == 4), B carry = 0 (5 > 3) -> not taken
; Expected RAX = 0b0101 = 0x5.

%macro JLEG 5   ; %1 = result bit, %2/%3 = A operands, %4/%5 = B operands
  mov r8, %2
  mov r9, %3
  mov r10, %4
  mov r11, %5
  cmp r8, r9
  jne %%join
  cmp r10, r11
%%join:
  jc %%taken
  jmp %%merge
%%taken:
  or rax, %1
%%merge:
  xor r15, r15      ; kill NZCV+PF+AF: makes both cmps value- and PF-dead
%endmacro

xor rax, rax

; B operands on the direct-path legs are chosen to yield the OPPOSITE carry,
; so wrong-path execution or wrong-flag propagation flips the result.
JLEG 1, 1, 2, 5, 3
JLEG 2, 9, 7, 3, 5
JLEG 4, 4, 4, 3, 5
JLEG 8, 4, 4, 5, 3

hlt
