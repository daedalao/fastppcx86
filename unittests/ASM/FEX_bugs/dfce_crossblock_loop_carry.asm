%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x5"
  }
}
%endif

; Cross-block flag liveness across a LOOP BACKEDGE (DFCE gating test).
;
; Shape: carry is DEFINED BEFORE the loop, the loop header writes every flag
; EXCEPT carry (dec), an in-loop compare CONDITIONALLY rewrites carry (it
; only executes on iterations where the body runs), and carry is CONSUMED
; after the loop exits:
;
;         cmp  r8, r9        ; pre-loop CF def; value-dead
;     top:
;         dec  rcx           ; ZF/SF/OF/AF/PF written, CF PRESERVED
;         jz   exit
;         cmp  rcx, r10      ; in-loop conditional CF write
;         jmp  top           ; backedge
;     exit:
;         jc   taken         ; CF: pre-loop def (count==1) or last body cmp
;
; What this pins in DeadFlagCalculationElimination (jit_500_m):
;  * The backedge fixpoint: carry liveness must propagate exit -> top ->
;    body -> top (around the backedge) and out to the pre-loop block. The
;    worklist re-processing of predecessors is exactly the machinery under
;    test; a broken fixpoint that under-approximates kills the pre-loop
;    cmp's carry (count==1 legs) or the in-loop cmp's carry (count==3 legs).
;  * dec's flag write set must stay partial (no C): if dec were classified
;    as writing C, the pre-loop def would be provably dead and legs 1/2
;    would read stale carry.
;  * Both polarities of both flag sources, so any wrong elimination flips
;    at least one leg regardless of the stale state left behind.
;
; Legs (bit set iff jc taken). The UNUSED source in each leg is chosen to
; carry the OPPOSITE polarity, so consuming the wrong def is visible:
;   bit0: count 1, pre-loop CF=1 (2<5); body never runs (r10=0 -> CF=0)   -> taken
;   bit1: count 1, pre-loop CF=0 (5>2); (r10=9 -> body CF would be 1)     -> not taken
;   bit2: count 3, last body cmp (1,9) CF=1; pre-loop CF=0 (5>2)          -> taken
;   bit3: count 3, last body cmp (1,0) CF=0; pre-loop CF=1 (2<5)          -> not taken
; Expected RAX = 0b0101 = 0x5.

%macro LLEG 5   ; %1 = result bit, %2/%3 = pre-loop cmp operands, %4 = count, %5 = in-loop compare operand
  mov r8, %2
  mov r9, %3
  mov rcx, %4
  mov r10, %5
  cmp r8, r9
%%top:
  dec rcx
  jz %%exit
  cmp rcx, r10
  jmp %%top
%%exit:
  jc %%taken
  jmp %%merge
%%taken:
  or rax, %1
%%merge:
  xor r15, r15      ; kill NZCV+PF+AF: both cmps above are value- and PF-dead
%endmacro

xor rax, rax

LLEG 1, 2, 5, 1, 0
LLEG 2, 5, 2, 1, 9
LLEG 4, 5, 2, 3, 9
LLEG 8, 2, 5, 3, 0

hlt
