%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x123456789ABCDF00",
    "RBX": "0x123456789ABCDF01",
    "RDX": "0xF0123456789ABCDE",
    "RSI": "0xF0123456789ABCDD",
    "RDI": "0x0123456789ABCDEF",
    "R13": "0x0123456789ABCDF0",
    "R8":  "0x0000000000000004",
    "R10": "0x000000000000000D",
    "R12": "0x0000000000000010"
  }
}
%endif

; Executes OP_ADC / OP_SBB / OP_ADCZERO in the PPC64LE backend.
;
; Those three DEF_OPs have exactly one producer: the in-place Replacement
; rewrite in DeadFlagCalculationElimination (AdcWithFlags -> Adc,
; SbbWithFlags -> Sbb, AdcZeroWithFlags -> AdcZero), which only fires when the
; instruction's NZCV write is provably dead. The pass was disabled on PPC64LE
; from 2026-05-11 to 2026-08-05, so for three months these handlers were
; unreachable and nothing in the suite could observe them. DEF_OP(Adc) was in
; fact wrong the entire time -- it consumed an INVERTED carry while its only
; producer, CalculateFlags_ADC, does RectifyCarryInvert(false) and leaves
; XER.CA holding x86 CF directly, so it computed S1 + S2 + !CF. All three also
; lacked the i32 zero-extending writeback that every sibling op has.
;
; Every subtest is followed by `add r15, r15`, whose own NZCV write kills the
; preceding instruction's NZCV. That is what makes the Replacement fire; drop
; it and the flag writes stay live, the WithFlags form survives, and the
; subtest silently stops testing anything. The test therefore only has teeth
; with the pass ENABLED (FEX_DISABLEDFCE unset / 0) -- with the pass off it
; still passes, exercising the WithFlags handlers instead.
;
; `adc reg, 0` is deliberately spelled with a literal zero: the dispatcher
; routes a literal-0 source of size >= 32 to _AdcZeroWithFlags, an entirely
; different op from _AdcWithFlags. Non-zero sources are required to reach
; OP_ADC at all.
;
; The CF=0 / CF=1 pairs are the polarity check: each pair must differ by
; exactly 1 in the correct direction. Under the old inverted-carry Adc the
; two results were swapped, so both halves of the pair fail.

xor r15, r15

; ---- 64-bit ADC, CF = 0 ----
mov rax, 0x0123456789ABCDEF
mov rcx, 0x1111111111111111
clc
adc rax, rcx
add r15, r15

; ---- 64-bit ADC, CF = 1 (must be exactly the CF=0 result + 1) ----
mov rbx, 0x0123456789ABCDEF
mov rcx, 0x1111111111111111
stc
adc rbx, rcx
add r15, r15

; ---- 64-bit SBB, CF = 0 ----
mov rdx, 0x0123456789ABCDEF
mov rcx, 0x1111111111111111
clc
sbb rdx, rcx
add r15, r15

; ---- 64-bit SBB, CF = 1 (must be exactly the CF=0 result - 1) ----
mov rsi, 0x0123456789ABCDEF
mov rcx, 0x1111111111111111
stc
sbb rsi, rcx
add r15, r15

; ---- 64-bit ADC reg,0 -> AdcZero, CF = 0 (value unchanged) ----
mov rdi, 0x0123456789ABCDEF
clc
adc rdi, 0
add r15, r15

; ---- 64-bit ADC reg,0 -> AdcZero, CF = 1 (value + 1) ----
mov r13, 0x0123456789ABCDEF
stc
adc r13, 0
add r15, r15

; ---- 32-bit ADC with garbage in the upper halves of BOTH sources ----
; 1 + 2 + CF(1) = 4, and the write back to r8 must zero-extend, not leave
; 0xDEADBEEF (or an OR of the two garbage halves) in the top 32 bits.
mov r8, 0xDEADBEEF00000001
mov r9, 0xCAFEBABE00000002
stc
adc r8d, r9d
add r15, r15

; ---- 32-bit SBB with garbage in the upper halves of BOTH sources ----
; 0x10 - 2 - CF(1) = 0xD, zero-extended.
mov r10, 0xDEADBEEF00000010
mov r11, 0xCAFEBABE00000002
stc
sbb r10d, r11d
add r15, r15

; ---- 32-bit ADC reg,0 -> AdcZero, garbage upper ----
; 0xF + CF(1) = 0x10, zero-extended.
mov r12, 0xDEADBEEF0000000F
stc
adc r12d, 0
add r15, r15

hlt
