%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x24656739",
    "RBX": "0x24656739",
    "RCX": "0x24656739",
    "RDX": "0x24656739"
  }
}
%endif

; FP compare NaN edges through the FUSED compare+select (CMOVcc) path.
;
; Companion to xscmpudp_nan_fused_branch.asm: same xscmpudp lowering, but
; the consumer is CMOVcc, which the OpcodeDispatcher fuses into a select.
; The branch and select fusions take different code paths in the backend,
; so both need NaN coverage independently.
;
; Flag semantics per Intel SDM (UCOMISS/COMISS "Operation"):
;   unordered ZF,PF,CF=1,1,1; greater 0,0,0; less 0,0,1; equal 1,0,0.
; QNaN vs SNaN: identical flag results (only #IA differs, masked here).
;
; Identical bit layout and derivation as the branch test:
;   pairs p=0 (1.0,QNaN) / 1 (SNaN,1.0) / 2 (QNaN,QNaN) unordered,
;   p=3 (1.0,2.0) less, p=4 (3.0,2.0) greater, p=5 (2.0,2.0) equal;
;   bit(5p+0)=cmovp, +1=cmovnp, +2=cmova, +3=cmovb, +4=cmove.
;   groups: unordered 0b11001, less 0b01010, greater 0b00110,
;   equal 0b10010 -> packed 0x24656739 per instruction.
; RAX=ucomiss, RBX=ucomisd, RCX=comiss, RDX=comisd.

; %1 = compare instr, %2 = scalar mov, %3/%4 = operand labels,
; %5 = cmovcc, %6 = bit index. Accumulates into RSI. R9 holds constant 1.
%macro ONECASE 6
  %2 xmm0, [rel %3]
  %2 xmm1, [rel %4]
  ; zero the temp BEFORE the compare -- xor clobbers EFLAGS, and the
  ; cmov must directly follow the compare for the fused-select path
  xor r8, r8
  %1 xmm0, xmm1
  %5 r8, r9
  shl r8, %6
  or rsi, r8
%endmacro

%macro GROUP 5
  ONECASE %1, %2, %3, %4, cmovp,  (%5+0)
  ONECASE %1, %2, %3, %4, cmovnp, (%5+1)
  ONECASE %1, %2, %3, %4, cmova,  (%5+2)
  ONECASE %1, %2, %3, %4, cmovb,  (%5+3)
  ONECASE %1, %2, %3, %4, cmove,  (%5+4)
%endmacro

%macro INSTRSET 3
  xor rsi, rsi
  GROUP %1, %2, %3 %+ _one,   %3 %+ _qnan, 0
  GROUP %1, %2, %3 %+ _snan,  %3 %+ _one,  5
  GROUP %1, %2, %3 %+ _qnan,  %3 %+ _qnan, 10
  GROUP %1, %2, %3 %+ _one,   %3 %+ _two,  15
  GROUP %1, %2, %3 %+ _three, %3 %+ _two,  20
  GROUP %1, %2, %3 %+ _two,   %3 %+ _two,  25
%endmacro

mov r9, 1

INSTRSET ucomiss, movss, f
mov rax, rsi

INSTRSET ucomisd, movsd, d
mov rbx, rsi

INSTRSET comiss, movss, f
mov rcx, rsi

INSTRSET comisd, movsd, d
mov rdx, rsi

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
