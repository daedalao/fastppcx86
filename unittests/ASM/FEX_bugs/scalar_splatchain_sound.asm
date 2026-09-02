%ifdef CONFIG
{
  "RegData": {
    "XMM0":  ["0x4000000041880000", "0x4080000040400000"],
    "XMM4":  ["0x0000000042DC0000", "0x0000000000000000"],
    "XMM5":  ["0x42B4000041880000", "0x42B8000042B60000"],
    "XMM6":  ["0x4000000041300000", "0x4080000040400000"],
    "XMM7":  ["0x3FDC000000000000", "0x4004000000000000"],
    "XMM9":  ["0x0000000041880000", "0x0000000000000000"],
    "XMM10": ["0x4000000141880001", "0x4080000140400001"],
    "XMM11": ["0x40E0000042000000", "0x4110000041000000"]
  }
}
%endif

; ScalarSplatChain sound-rework coverage (IR/Passes/ScalarSplatChain.cpp,
; 2026-09-01): scalar-SSE chains now compute in splat domain with an explicit
; VInsElement lane merge feeding every StoreRegister. The invariant under test
; is the one the old rule-(d) form broke: the guest XMM's UPPER elements stay
; ARCHITECTURAL at every observation point -- after live-out chains, through a
; mid-chain movaps duplication, into a full-width integer consumer, and out
; through a narrow store.
;
; XMM0:  addss/mulss/subss accumulator chain, LIVE OUT at block end (the exact
;        shape the old pass could never mark). elem0 = ((1+10)*2)-5 = 17.0,
;        elems 1..3 must remain {2.0, 3.0, 4.0}.
; XMM6:  movaps duplicate taken MID-CHAIN (after the addss): full 128-bit
;        architectural value {11.0, 2.0, 3.0, 4.0}.
; XMM10: paddd of the finished chain value -- a full-width integer reader of a
;        chain result, must see exact bits of {17.0, 2.0, 3.0, 4.0} + 1/lane.
; XMM5:  minss consuming the chain result as its second source (element-0-only
;        reader): min(21.0, 17.0) = 17.0, own uppers preserved.
; XMM9:  the chain result stored narrow (movss [mem]) and reloaded into a
;        zeroed register: {17.0, 0, 0, 0}.
; XMM4:  a load-fed chain link (movss-load zeroes uppers): 100.0+10.0 = 110.0.
; XMM7:  f64 chain: (1.5+0.25)*0.25 = 0.4375, elem1 stays 2.5.
; XMM11: divss coverage: {64/2 = 32.0, uppers 7.0 8.0 9.0}.

lea r15, [rel .data]

movaps xmm0,  [r15 + 0x00]   ; A = {1.0, 2.0, 3.0, 4.0}
movaps xmm1,  [r15 + 0x10]   ; {10.0, 20.0, 30.0, 40.0}
movaps xmm2,  [r15 + 0x20]   ; {2.0, 200.0, 300.0, 400.0}
movaps xmm3,  [r15 + 0x30]   ; {5.0, 50.0, 60.0, 70.0}
movaps xmm5,  [r15 + 0x40]   ; {21.0, 90.0, 91.0, 92.0}
movaps xmm7,  [r15 + 0x50]   ; {1.5, 2.5} f64
movaps xmm8,  [r15 + 0x60]   ; {0.25, 9.0} f64
movaps xmm10, [r15 + 0x70]   ; {1, 1, 1, 1} i32
movaps xmm11, [r15 + 0x80]   ; {64.0, 7.0, 8.0, 9.0}

; f32 accumulator chain with a mid-chain full-width observation.
addss  xmm0, xmm1            ; elem0 = 11.0
movaps xmm6, xmm0            ; architectural duplicate mid-chain
mulss  xmm0, xmm2            ; elem0 = 22.0
subss  xmm0, xmm3            ; elem0 = 17.0

; consumers of the finished chain value.
paddd  xmm10, xmm0           ; full-width integer read
minss  xmm5, xmm0            ; element-0-only read as Vector2
movss  [r15 + 0x90], xmm0    ; narrow store of splat-form-producing value
xorps  xmm9, xmm9
movss  xmm9, [r15 + 0x90]    ; reload: {17.0, 0, 0, 0}

; load-fed link: movss-load zeroes uppers, then one chain op.
movss  xmm4, [r15 + 0xA0]    ; {100.0, 0, 0, 0}
addss  xmm4, xmm1            ; {110.0, 0, 0, 0}

; f64 chain.
addsd  xmm7, xmm8            ; elem0 = 1.75
mulsd  xmm7, xmm8            ; elem0 = 0.4375

; divss coverage.
divss  xmm11, xmm2           ; {32.0, 7.0, 8.0, 9.0}

hlt

align 16
.data:
dd 1.0, 2.0, 3.0, 4.0
dd 10.0, 20.0, 30.0, 40.0
dd 2.0, 200.0, 300.0, 400.0
dd 5.0, 50.0, 60.0, 70.0
dd 21.0, 90.0, 91.0, 92.0
dq 1.5, 2.5
dq 0.25, 9.0
dd 1, 1, 1, 1
dd 64.0, 7.0, 8.0, 9.0
dd 0, 0, 0, 0
dd 100.0, 0, 0, 0
