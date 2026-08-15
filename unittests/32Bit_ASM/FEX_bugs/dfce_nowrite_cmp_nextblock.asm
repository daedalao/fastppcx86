%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x55"
  },
  "Mode": "32BIT"
}
%endif

; 32-bit twin of unittests/ASM/FEX_bugs/dfce_nowrite_cmp_nextblock.asm.
;
; DFCE's ReplacementNoWrite arm is enabled for 64-BIT GUESTS ONLY
; (2026-08-13): in 32-bit mode it stays off because enabling it corrupts
; i686 glibc's _dl_sort_maps_dfs ("rpo_head == rpo" assertion) -- root cause
; still open, see RedundantFlagCalculationElimination.cpp. This file pins
; the cross-block value-dead-CMP shape in 32-bit mode:
;  * today: guards the DISABLED-arm behaviour (SubWithFlags survives whole);
;  * later: becomes the first gate for anyone re-enabling the arm on 32-bit.
;
; Same self-checking structure as the 64-bit twin: every condition in both
; polarities, so a wrongly eliminated flag write makes a pair's two legs
; agree and flips at least one accumulator bit.
;
; Legs into EAX (bit set iff taken):
;   bit0 jb (2,5)  CF=1 -> taken     bit1 jb (5,2)  CF=0 -> not
;   bit2 je (7,7)  ZF=1 -> taken     bit3 je (7,9)  ZF=0 -> not
;   bit4 js (1,3)  SF=1 -> taken     bit5 js (3,1)  SF=0 -> not
;   bit6 jo (INT32_MIN,1) OF=1 -> taken
;   bit7 jo (5,1)  OF=0 -> not
; Expected EAX = 0b0101_0101 = 0x55.

%macro CLEG 4   ; %1 = EAX bit, %2 = jcc, %3/%4 = cmp operands
  mov esi, %3
  mov edi, %4
  cmp esi, edi
  jmp %%next
%%next:
  %2 %%taken
  jmp %%merge
%%taken:
  or eax, %1
%%merge:
  xor edx, edx      ; kill NZCV+PF+AF: the cmp above is value- and PF-dead
%endmacro

xor eax, eax

CLEG 0x01, jb, 2, 5
CLEG 0x02, jb, 5, 2
CLEG 0x04, je, 7, 7
CLEG 0x08, je, 7, 9
CLEG 0x10, js, 1, 3
CLEG 0x20, js, 3, 1
CLEG 0x40, jo, 0x80000000, 1
CLEG 0x80, jo, 5, 1

hlt
