%ifdef CONFIG
{
  "RegData": {
    "XMM0":  ["0x4000000042C80000", "0x4080000040400000"],
    "XMM1":  ["0x40C0000040A00000", "0x4100000040E00000"],
    "XMM2":  ["0x4000000042C80000", "0x4080000040400000"],
    "XMM3":  ["0x400000003F800000", "0x43C8000040400000"],
    "XMM4":  ["0x400000003F800000", "0x4080000040400000"],
    "XMM5":  ["0x434800003F800000", "0x4080000040400000"],
    "XMM6":  ["0x400000003F800000", "0x4080000043960000"],
    "XMM7":  ["0x4058E00000000000", "0x4004000000000000"]
  }
}
%endif

; VInsElement backend fast path (VectorOps.cpp DEF_OP(VInsElement)): i32
; same-index insert at LE element 0 or 3 collapses from a 14-instruction
; vperm-with-inline-control to a 2-instruction xxsldwi pair. This is the
; movss/blendps reg-reg path: MOVScalarOpImpl emits VInsElement(i32,
; DestIdx=0, SrcIdx=0) for `movss xmm,xmm`; VectorBlend's imm8 bit0/bit3
; selectors emit the (0,0) and (3,3) cases for `blendps`. imm8 bit1/bit2
; (DestIdx=SrcIdx=1 or 2) have no such 2-instruction form and stay on the
; untouched generic vperm path -- included here as a regression check that
; the new fast path's added condition didn't also (mis-)catch them.
;
; A = {1.0, 2.0, 3.0, 4.0}, B = {100.0, 200.0, 300.0, 400.0} (packed f32,
; elem0 in the low dword of each qword below). C = {5.0, 6.0, 7.0, 8.0}.
; D = {1.5, 2.5}, E = {99.5, 88.5} (packed f64).
;
; XMM0: movss xmm0(A), xmm8(B)       -> {B0, A1, A2, A3}      (0,0), dest!=src
; XMM1: movss xmm1(C), xmm1(C)       -> {C0, C1, C2, C3}      (0,0), self-alias (unchanged)
; XMM2: blendps xmm2(A),xmm8(B),0x1  -> {B0, A1, A2, A3}      (0,0) via VectorBlend
; XMM3: blendps xmm3(A),xmm8(B),0x8  -> {A0, A1, A2, B3}      (3,3), new fast path
; XMM4: blendps xmm4(A),xmm4(A),0x8  -> {A0, A1, A2, A3}      (3,3), self-alias (unchanged)
; XMM5: blendps xmm5(A),xmm8(B),0x2  -> {A0, B1, A2, A3}      (1,1), untouched vperm path
; XMM6: blendps xmm6(A),xmm8(B),0x4  -> {A0, A1, B2, A3}      (2,2), untouched vperm path
; XMM7: movsd xmm7(D), xmm8(E)       -> {E0, D1}              i64 path, unchanged code (sanity)

lea r15, [rel .data]

movaps xmm0, [r15 + 16*0]   ; A
movaps xmm8, [r15 + 16*1]   ; B
movss  xmm0, xmm8           ; XMM0

movaps xmm1, [r15 + 16*2]   ; C
movss  xmm1, xmm1           ; XMM1 (self-alias)

movaps xmm2, [r15 + 16*0]   ; A
movaps xmm8, [r15 + 16*1]   ; B
blendps xmm2, xmm8, 0x1     ; XMM2

movaps xmm3, [r15 + 16*0]   ; A
movaps xmm8, [r15 + 16*1]   ; B
blendps xmm3, xmm8, 0x8     ; XMM3

movaps xmm4, [r15 + 16*0]   ; A
blendps xmm4, xmm4, 0x8     ; XMM4 (self-alias)

movaps xmm5, [r15 + 16*0]   ; A
movaps xmm8, [r15 + 16*1]   ; B
blendps xmm5, xmm8, 0x2     ; XMM5

movaps xmm6, [r15 + 16*0]   ; A
movaps xmm8, [r15 + 16*1]   ; B
blendps xmm6, xmm8, 0x4     ; XMM6

movapd xmm7, [r15 + 16*3]   ; D
movapd xmm8, [r15 + 16*4]   ; E
movsd  xmm7, xmm8           ; XMM7

hlt

align 16
.data:
dd 0x3F800000, 0x40000000, 0x40400000, 0x40800000   ; A = {1.0,2.0,3.0,4.0}
dd 0x42C80000, 0x43480000, 0x43960000, 0x43C80000   ; B = {100.0,200.0,300.0,400.0}
dd 0x40A00000, 0x40C00000, 0x40E00000, 0x41000000   ; C = {5.0,6.0,7.0,8.0}
dq 0x3FF8000000000000, 0x4004000000000000            ; D = {1.5, 2.5}
dq 0x4058E00000000000, 0x4056200000000000            ; E = {99.5, 88.5}
