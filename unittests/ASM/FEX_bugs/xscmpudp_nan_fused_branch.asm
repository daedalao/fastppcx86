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

; FP compare NaN edges through the FUSED compare+branch path.
;
; The PPC64LE backend recently moved ucomiss/ucomisd/comiss/comisd to
; xscmpudp and fuses the compare with an immediately-following Jcc in the
; OpcodeDispatcher (cmp fusion, vzero-vsx-and-cmp-fusion). The hazard: x86
; encodes "unordered" as ZF=PF=CF=1 while the PPC CR encoding from
; xscmpudp puts unordered in a separate CR bit -- the fused translation of
; each x86 condition must map NaN operands exactly like the unfused
; flag-materializing path did.
;
; Per Intel SDM (UCOMISS/COMISS "Operation"):
;   UNORDERED (either operand NaN): ZF,PF,CF = 1,1,1
;   GREATER_THAN:                   ZF,PF,CF = 0,0,0
;   LESS_THAN:                      ZF,PF,CF = 0,0,1
;   EQUAL:                          ZF,PF,CF = 1,0,0
; QNaN and SNaN produce identical FLAG results for both the ucomis* and
; comis* forms; they differ only in whether #IA is raised (masked here,
; MXCSR default), so the expected values below are exact for both.
;
; For each compare instruction we test 6 operand pairs x 5 branch
; conditions. The compare is re-executed before EVERY branch so each Jcc
; directly follows its compare and is eligible for fusion.
; Bit layout per instruction result (30 bits): pair index p in
;   p=0: (1.0, QNaN)   -> unordered
;   p=1: (SNaN, 1.0)   -> unordered
;   p=2: (QNaN, QNaN)  -> unordered
;   p=3: (1.0, 2.0)    -> less
;   p=4: (3.0, 2.0)    -> greater
;   p=5: (2.0, 2.0)    -> equal
; bit(5p+0)=jp taken, +1=jnp, +2=ja, +3=jb, +4=je.
; Derivation of the per-pair 5-bit groups from the flag table above:
;   unordered: jp=1 jnp=0 ja=0 (CF|ZF set) jb=1 (CF) je=1 (ZF) = 0b11001
;   less:      jp=0 jnp=1 ja=0 jb=1 je=0                       = 0b01010
;   greater:   jp=0 jnp=1 ja=1 jb=0 je=0                       = 0b00110
;   equal:     jp=0 jnp=1 ja=0 jb=0 je=1                       = 0b10010
; Packed: 0b11001 | 0b11001<<5 | 0b11001<<10 | 0b01010<<15
;         | 0b00110<<20 | 0b10010<<25 = 0x24656739
;
; RAX=ucomiss, RBX=ucomisd, RCX=comiss, RDX=comisd; all must be 0x24656739.
;
; NaN encodings: float QNaN 0x7FC00001 / SNaN 0x7F800001 (nonzero payload,
; MSB of fraction clear); double QNaN 0x7FF8000000000001 /
; SNaN 0x7FF0000000000001.

; %1 = compare instr, %2 = scalar mov, %3/%4 = operand labels,
; %5 = branch, %6 = bit index. Accumulates into RSI.
%macro ONECASE 6
  %2 xmm0, [rel %3]
  %2 xmm1, [rel %4]
  %1 xmm0, xmm1
  %5 %%taken
  jmp %%done
%%taken:
  bts rsi, %6
%%done:
%endmacro

; %1 = compare instr, %2 = scalar mov, %3/%4 = operand labels, %5 = base bit
%macro GROUP 5
  ONECASE %1, %2, %3, %4, jp,  (%5+0)
  ONECASE %1, %2, %3, %4, jnp, (%5+1)
  ONECASE %1, %2, %3, %4, ja,  (%5+2)
  ONECASE %1, %2, %3, %4, jb,  (%5+3)
  ONECASE %1, %2, %3, %4, je,  (%5+4)
%endmacro

; %1 = compare instr, %2 = scalar mov, %3 = data label prefix
%macro INSTRSET 3
  xor rsi, rsi
  GROUP %1, %2, %3 %+ _one,   %3 %+ _qnan, 0
  GROUP %1, %2, %3 %+ _snan,  %3 %+ _one,  5
  GROUP %1, %2, %3 %+ _qnan,  %3 %+ _qnan, 10
  GROUP %1, %2, %3 %+ _one,   %3 %+ _two,  15
  GROUP %1, %2, %3 %+ _three, %3 %+ _two,  20
  GROUP %1, %2, %3 %+ _two,   %3 %+ _two,  25
%endmacro

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
