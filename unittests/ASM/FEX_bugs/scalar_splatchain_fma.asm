%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM0":  ["0x4000000041700000", "0x4080000040400000"],
    "XMM3":  ["0x42480000BF800000", "0x428C000042700000"],
    "XMM4":  ["0x424C00003F800000", "0x428E000042740000"],
    "XMM5":  ["0x42500000C1300000", "0x4290000042780000"],
    "XMM6":  ["0x4000000040E00000", "0x4080000040400000"],
    "XMM7":  ["0x4004000000000000", "0x400C000000000000"],
    "XMM10": ["0x4000000141700001", "0x4080000140400001"],
    "XMM11": ["0x0000000041700000", "0x0000000000000000"],
    "XMM12": ["0x42B4000041700000", "0x42B8000042B60000"],
    "XMM13": ["0x42A0000040C00000", "0x42A4000042A20000"],
    "XMM14": ["0x40A0000041E00000", "0x40E0000040C00000"]
  }
}
%endif

; ScalarSplatChain FMA-family coverage (IR/Passes/ScalarSplatChain.cpp): the
; four VF{,N}ML{A,S}ScalarInsert ops now join the pass as both producers and
; elem0-only consumers. Invariant under test, same as scalar_splatchain_sound:
; the guest XMM's UPPER elements stay ARCHITECTURAL at every observation
; point, while element 0 carries the exact chain arithmetic.
;
; XMM0:  vfmadd231ss accumulator chain crossing into an arith link (addss),
;        LIVE OUT. e0 = ((2*3)+1, +6, +2) = 15.0, uppers {2.0, 3.0, 4.0}.
; XMM6:  movaps duplicate MID-CHAIN after the first FMA: {7.0, 2.0, 3.0, 4.0}.
; XMM3/4/5: the other three FMA forms as lone links, uppers preserved:
;        vfnmadd -(6)+5 = -1.0; vfmsub 6-5 = 1.0; vfnmsub -(6)-5 = -11.0.
; XMM10: paddd full-width integer read of the finished chain: exact bits +1.
; XMM12: minss consuming the chain result as Vector2: min(21,15) = 15.0.
; XMM11: chain result stored narrow (movss [mem]) and reloaded into a zeroed
;        register: {15.0, 0, 0, 0}.
; XMM13/14: arith link (addss) feeding an FMA multiplicand: 4+2 = 6.0 live
;        out in XMM13; XMM14 e0 = 6*3+10 = 28.0, uppers {5.0, 6.0, 7.0}.
; XMM7:  f64 FMA chain, two vfmadd231sd links: 0.25*2+1.5 = 2.0, then
;        0.5+2.0 = 2.5; elem1 stays 3.5.

lea r15, [rel .data]

movaps xmm0,  [r15 + 0x00]   ; {1.0, 2.0, 3.0, 4.0}
movaps xmm1,  [r15 + 0x10]   ; {2.0, 20.0, 30.0, 40.0}
movaps xmm2,  [r15 + 0x20]   ; {3.0, 200.0, 300.0, 400.0}
movaps xmm3,  [r15 + 0x30]   ; {5.0, 50.0, 60.0, 70.0}
movaps xmm4,  [r15 + 0x40]   ; {5.0, 51.0, 61.0, 71.0}
movaps xmm5,  [r15 + 0x50]   ; {5.0, 52.0, 62.0, 72.0}
movapd xmm7,  [r15 + 0x60]   ; {1.5, 3.5} f64
movapd xmm8,  [r15 + 0x70]   ; {0.25, 9.0} f64
movapd xmm9,  [r15 + 0x80]   ; {2.0, 8.0} f64
movaps xmm10, [r15 + 0x90]   ; {1, 1, 1, 1} i32
movaps xmm12, [r15 + 0xA0]   ; {21.0, 90.0, 91.0, 92.0}
movaps xmm13, [r15 + 0xB0]   ; {4.0, 80.0, 81.0, 82.0}
movaps xmm14, [r15 + 0xC0]   ; {10.0, 5.0, 6.0, 7.0}

; f32 FMA accumulator chain with a mid-chain full-width observation, then a
; cross-family link into addss.
vfmadd231ss xmm0, xmm1, xmm2   ; e0 = 2*3 + 1 = 7.0
movaps xmm6, xmm0              ; architectural duplicate mid-chain
vfmadd231ss xmm0, xmm1, xmm2   ; e0 = 6 + 7 = 13.0
addss xmm0, xmm1               ; e0 = 15.0

; the other three FMA forms, each a lone link.
vfnmadd231ss xmm3, xmm1, xmm2  ; e0 = -(2*3) + 5 = -1.0
vfmsub231ss  xmm4, xmm1, xmm2  ; e0 =  (2*3) - 5 =  1.0
vfnmsub231ss xmm5, xmm1, xmm2  ; e0 = -(2*3) - 5 = -11.0

; consumers of the finished chain value.
paddd xmm10, xmm0              ; full-width integer read
minss xmm12, xmm0              ; element-0-only read as Vector2
movss [r15 + 0xD0], xmm0       ; narrow store of splat-form-producing value
xorps xmm11, xmm11
movss xmm11, [r15 + 0xD0]      ; reload: {15.0, 0, 0, 0}

; arith link feeding an FMA multiplicand.
addss xmm13, xmm1              ; e0 = 4 + 2 = 6.0
vfmadd231ss xmm14, xmm13, xmm2 ; e0 = 6*3 + 10 = 28.0

; f64 FMA chain.
vfmadd231sd xmm7, xmm8, xmm9   ; e0 = 0.25*2.0 + 1.5 = 2.0
vfmadd231sd xmm7, xmm8, xmm9   ; e0 = 0.5 + 2.0 = 2.5

hlt

align 16
.data:
dd 1.0, 2.0, 3.0, 4.0
dd 2.0, 20.0, 30.0, 40.0
dd 3.0, 200.0, 300.0, 400.0
dd 5.0, 50.0, 60.0, 70.0
dd 5.0, 51.0, 61.0, 71.0
dd 5.0, 52.0, 62.0, 72.0
dq 1.5, 3.5
dq 0.25, 9.0
dq 2.0, 8.0
dd 1, 1, 1, 1
dd 21.0, 90.0, 91.0, 92.0
dd 4.0, 80.0, 81.0, 82.0
dd 10.0, 5.0, 6.0, 7.0
dd 0, 0, 0, 0
