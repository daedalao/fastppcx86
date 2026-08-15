%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x1B55"
  }
}
%endif

; Value-dead ADC/SBB with live flags -- the ReplacementNoWrite rewrites
; AdcWithFlags -> AdcNZCV and SbbWithFlags -> SbbNZCV (DFCE gating test for
; the 64-bit-only enable of 2026-08-13).
;
;     stc / clc          ; carry-in, LIVE (read by the adc/sbb itself)
;     adc  r10, r11      ; result register...
;     mov  r10, 0        ; ...overwritten in the SAME block: the register
;                        ; cache never materialises the first store, so the
;                        ; AdcWithFlags node's only SSA use is its StorePF
;     jmp  next
;   next:
;     jcc  taken         ; flag consumer in the NEXT block
;     ...
;     xor  r15, r15      ; kills NZCV+PF+AF -> StorePF dead -> uses drop to 0
;
; SIGNIFICANCE: the NoWrite arm is the ONLY producer of AdcNZCV/SbbNZCV in
; the whole tree -- before the 2026-08-13 enable, those PPC64LE lowerings had
; never executed. DEF_OP(AdcNZCV) carried inverted carry polarity on BOTH
; carry-in and carry-out in both size paths (same never-executed-handler
; class as the DEF_OP(Adc) polarity bug fixed earlier); it was fixed
; alongside the enable, and this file is the pin:
;  * carry-in polarity: legs A1..A6 pair stc/clc over operands where the
;    carry-in decides the visible outcome (0xFF..F + 0 + CF). A flipped
;    carry-in inverts CF/ZF results wholesale.
;  * carry-out storage convention (DIRECT, CFInverted=false after ADC):
;    the jc consumers read it in the next block; inverted storage flips
;    every jc leg.
;  * SBB's convention is deliberately OPPOSITE (CFInverted=true); the S legs
;    pin that the SbbNZCV path keeps it.
;  * The 32-bit legs exercise the i32 manual paths (zx32 + XER patch).
;
; Legs (bit set iff taken):
;   A1 0x0001 stc; adc 0xFF..F,0  ; jc -> CF-out=1        taken
;   A2 0x0002 clc; adc 5,7       ; jc -> CF-out=0         not
;   A3 0x0004 stc; adc 0xFF..F,0  ; jz -> sum=0            taken
;   A4 0x0008 clc; adc 0xFF..F,0  ; jz -> sum=0xFF..F      not
;   A5 0x0010 stc; adc INT64_MAX,0; jo -> overflow         taken
;   A6 0x0020 clc; adc INT64_MAX,0; jo -> no overflow      not
;   A7 0x0040 stc; adc32 0xFFFFFFFF,0; jc -> CF-out=1      taken
;   A8 0x0080 clc; adc32 0xFFFFFFFF,0; jc -> CF-out=0      not
;   A9 0x0100 stc; adc32 INT32_MAX,0 ; jo -> overflow      taken
;   S1 0x0200 stc; sbb 5,5       ; jc -> 5-5-1 borrows     taken
;   S2 0x0400 clc; sbb 5,5       ; jc -> no borrow         not
;   S3 0x0800 clc; sbb 5,5       ; jz -> result 0          taken
;   S4 0x1000 stc; sbb32 0,0     ; jc -> 0-0-1 borrows     taken
; Expected RAX = 0x1B55.

%macro ALEG 6   ; %1 = bit, %2 = stc/clc, %3 = adc/sbb, %4/%5 = operand loads, %6 = jcc
  mov r10, %4
  mov r11, %5
  %2
  %3 r10, r11
  mov r10, 0
  jmp %%next
%%next:
  %6 %%taken
  jmp %%merge
%%taken:
  or rax, %1
%%merge:
  xor r15, r15
%endmacro

%macro ALEG32 6 ; %1 = bit, %2 = stc/clc, %3 = adc/sbb (32-bit regs), %4/%5 = loads, %6 = jcc
  mov r10, %4
  mov r11, %5
  %2
  %3 r10d, r11d
  mov r10, 0
  jmp %%next
%%next:
  %6 %%taken
  jmp %%merge
%%taken:
  or rax, %1
%%merge:
  xor r15, r15
%endmacro

xor rax, rax

ALEG   0x0001, stc, adc, 0xFFFFFFFFFFFFFFFF, 0, jc
ALEG   0x0002, clc, adc, 5, 7, jc
ALEG   0x0004, stc, adc, 0xFFFFFFFFFFFFFFFF, 0, jz
ALEG   0x0008, clc, adc, 0xFFFFFFFFFFFFFFFF, 0, jz
ALEG   0x0010, stc, adc, 0x7FFFFFFFFFFFFFFF, 0, jo
ALEG   0x0020, clc, adc, 0x7FFFFFFFFFFFFFFF, 0, jo
ALEG32 0x0040, stc, adc, 0xFFFFFFFF, 0, jc
ALEG32 0x0080, clc, adc, 0xFFFFFFFF, 0, jc
ALEG32 0x0100, stc, adc, 0x7FFFFFFF, 0, jo
ALEG   0x0200, stc, sbb, 5, 5, jc
ALEG   0x0400, clc, sbb, 5, 5, jc
ALEG   0x0800, clc, sbb, 5, 5, jz
ALEG32 0x1000, stc, sbb, 0, 0, jc

hlt
