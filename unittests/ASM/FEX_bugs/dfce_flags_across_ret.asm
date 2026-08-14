%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x5"
  }
}
%endif

; Flag liveness across CALL/RET boundaries -- exit-block FLAG_ALL
; conservatism (DFCE gating test).
;
; x86 flags survive CALL and RET. Inside FEX, both instructions end the
; compile unit with an indirect/exit terminator, so DFCE's CFG has no
; successor to consult and must assume FLAG_ALL live at the boundary. That
; conservatism is what keeps these flag writes alive; an "optimization" that
; assumes flags dead at RET (tempting -- ABIs say so) or at CALL breaks
; exactly this file.
;
; Two shapes, both polarities each:
;  * Legs 1/2: flags DEFINED IN THE CALLEE (value-dead cmp immediately
;    before ret), consumed by the caller after the call returns. The cmp's
;    NZCV write is live only through the RET boundary.
;  * Legs 3/4: flags defined BEFORE the call (value-dead cmp immediately
;    before call), callee is flag-neutral (mov only), consumed after the
;    return. The cmp's NZCV write is live only through the CALL boundary
;    and the callee round-trip.
;
; Legs (bit set iff jc taken):
;   bit0: callee cmp (2,5) CF=1 -> taken
;   bit1: callee cmp (5,2) CF=0 -> not taken
;   bit2: caller cmp (2,5) CF=1 -> taken
;   bit3: caller cmp (5,2) CF=0 -> not taken
; Expected RAX = 0b0101 = 0x5.

%macro RLEG_CALLEE 3  ; %1 = result bit, %2/%3 = operands for the CALLEE cmp
  mov r8, %2
  mov r9, %3
  call sub_cmp
  jc %%taken
  jmp %%merge
%%taken:
  or rax, %1
%%merge:
  xor r15, r15
%endmacro

%macro RLEG_CALLER 3  ; %1 = result bit, %2/%3 = operands for the pre-call cmp
  mov r8, %2
  mov r9, %3
  cmp r8, r9
  call sub_neutral
  jc %%taken
  jmp %%merge
%%taken:
  or rax, %1
%%merge:
  xor r15, r15
%endmacro

mov rsp, 0xe8000000   ; harness maps [0xe8000000 - page, 0xe8000000 + page)
xor rax, rax

RLEG_CALLEE 1, 2, 5
RLEG_CALLEE 2, 5, 2
RLEG_CALLER 4, 2, 5
RLEG_CALLER 8, 5, 2

hlt

sub_cmp:
cmp r8, r9
ret

sub_neutral:
mov r11, 7
ret
