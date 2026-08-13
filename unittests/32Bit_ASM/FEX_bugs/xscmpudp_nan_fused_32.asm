%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x24656739",
    "RBX": "0x24656739",
    "RCX": "0x24656739",
    "RDX": "0x24656739",
    "RSI": "0x24656739",
    "RDI": "0x24656739"
  },
  "Mode": "32BIT"
}
%endif

; 32-BIT MODE FP compare NaN edges through the FUSED compare+branch and
; compare+cmov paths. Companion to the 64-bit
; ASM/FEX_bugs/xscmpudp_nan_fused_branch.asm / _cmov.asm -- same xscmpudp
; lowering, exercised through the 32-bit decoder/SRA path (the Steam client
; and most Wine titles are 32-bit).
;
; Per Intel SDM (UCOMISS/COMISS "Operation"):
;   unordered (any NaN operand): ZF,PF,CF=1,1,1
;   greater: 0,0,0   less: 0,0,1 (CF only)   equal: 1,0,0 (ZF only)
; QNaN and SNaN give identical flags (only masked #IA differs).
;
; Bit layout per accumulator (30 bits): operand pairs
;   p=0 (1.0,QNaN) unord, p=1 (SNaN,1.0) unord, p=2 (QNaN,QNaN) unord,
;   p=3 (1.0,2.0) less, p=4 (3.0,2.0) greater, p=5 (2.0,2.0) equal;
; bit(5p+0)=P cond, +1=NP, +2=A, +3=B, +4=E.
; Groups: unordered 0b11001, less 0b01010, greater 0b00110, equal 0b10010
; -> packed 0b10010<<25|0b00110<<20|0b01010<<15|0b11001<<10|0b11001<<5|0b11001
;    = 0x24656739 (same derivation as the 64-bit files).
;
; EAX=ucomiss/branch, EBX=ucomisd/branch, ECX=comiss/branch,
; EDX=comisd/branch, ESI=ucomiss/cmov, EDI=comisd/cmov.
; (Only two of the four instructions get the cmov treatment here -- the
; 32-bit register file runs out of accumulators; the 64-bit _cmov test
; covers all four. The two chosen span both precisions and both the
; quiet/signaling-exception instruction forms.)

; ---- cmov phase (runs first: uses eax/ebx as scratch) ----
; %1 cmp instr, %2 scalar mov, %3/%4 labels, %5 cmovcc, %6 bit, %7 accum
%macro CMOVCASE 7
  %2 xmm0, [%3]
  %2 xmm1, [%4]
  ; zero scratch BEFORE the compare (xor clobbers EFLAGS); the cmov must
  ; directly follow the compare to hit the fused-select path
  xor eax, eax
  %1 xmm0, xmm1
  %5 eax, ebx
  shl eax, %6
  or %7, eax
%endmacro

%macro CMOVGROUP 6
  CMOVCASE %1, %2, %3, %4, cmovp,  (%5+0), %6
  CMOVCASE %1, %2, %3, %4, cmovnp, (%5+1), %6
  CMOVCASE %1, %2, %3, %4, cmova,  (%5+2), %6
  CMOVCASE %1, %2, %3, %4, cmovb,  (%5+3), %6
  CMOVCASE %1, %2, %3, %4, cmove,  (%5+4), %6
%endmacro

%macro CMOVSET 4
  CMOVGROUP %1, %2, %3 %+ _one,   %3 %+ _qnan, 0,  %4
  CMOVGROUP %1, %2, %3 %+ _snan,  %3 %+ _one,  5,  %4
  CMOVGROUP %1, %2, %3 %+ _qnan,  %3 %+ _qnan, 10, %4
  CMOVGROUP %1, %2, %3 %+ _one,   %3 %+ _two,  15, %4
  CMOVGROUP %1, %2, %3 %+ _three, %3 %+ _two,  20, %4
  CMOVGROUP %1, %2, %3 %+ _two,   %3 %+ _two,  25, %4
%endmacro

mov ebx, 1
xor esi, esi
xor edi, edi
CMOVSET ucomiss, movss, f, esi
CMOVSET comisd, movsd, d, edi

; ---- branch phase (accumulates in ebp, results to eax..edx) ----
%macro BRCASE 6
  %2 xmm0, [%3]
  %2 xmm1, [%4]
  %1 xmm0, xmm1
  %5 %%taken
  jmp %%done
%%taken:
  bts ebp, %6
%%done:
%endmacro

%macro BRGROUP 5
  BRCASE %1, %2, %3, %4, jp,  (%5+0)
  BRCASE %1, %2, %3, %4, jnp, (%5+1)
  BRCASE %1, %2, %3, %4, ja,  (%5+2)
  BRCASE %1, %2, %3, %4, jb,  (%5+3)
  BRCASE %1, %2, %3, %4, je,  (%5+4)
%endmacro

%macro BRSET 3
  xor ebp, ebp
  BRGROUP %1, %2, %3 %+ _one,   %3 %+ _qnan, 0
  BRGROUP %1, %2, %3 %+ _snan,  %3 %+ _one,  5
  BRGROUP %1, %2, %3 %+ _qnan,  %3 %+ _qnan, 10
  BRGROUP %1, %2, %3 %+ _one,   %3 %+ _two,  15
  BRGROUP %1, %2, %3 %+ _three, %3 %+ _two,  20
  BRGROUP %1, %2, %3 %+ _two,   %3 %+ _two,  25
%endmacro

BRSET ucomiss, movss, f
mov eax, ebp

BRSET ucomisd, movsd, d
mov ebx, ebp

BRSET comiss, movss, f
mov ecx, ebp

BRSET comisd, movsd, d
mov edx, ebp

hlt

align 8
f_one:   dd 0x3F800000
f_two:   dd 0x40000000
f_three: dd 0x40400000
f_qnan:  dd 0x7FC00001
f_snan:  dd 0x7F800001
align 8
d_one:   dq 0x3FF0000000000000
d_two:   dq 0x4000000000000000
d_three: dq 0x4008000000000000
d_qnan:  dq 0x7FF8000000000001
d_snan:  dq 0x7FF0000000000001
