%ifdef CONFIG
{
  "RegData": {
    "XMM1": ["0x1E2017C5BEE29400", "0x38358E40CC367C7A"],
    "XMM2": ["0x6868C3F3AAED56E0", "0xF0FCE9E294E6E6DE"],
    "XMM3": ["0xE208147952DE57A0", "0x317D360F86C80DC9"],
    "XMM4": ["0xBBA54C87DA872B40", "0x6495428B7641EBE6"],
    "XMM5": ["0x170B5A1B5CDD42EA", "0x719F094BB2358CA1"],
    "XMM6": ["0x5555555555555555", "0x5555555555555555"],
    "XMM7": ["0x5555555555555555", "0x5555555555555555"]
  },
  "HostFeatures": ["PCLMUL"],
  "Mode": "32BIT"
}
%endif

; 32-BIT MODE PCLMULQDQ, all four immediate selectors. The 64-bit suite has
; H0F3A/pclmulqdq.asm but there was NO 32-bit PCLMUL test. Steam's download
; path is a 32-bit process whose CRC uses PCLMULQDQ-based folding
; (steam-download-crypto-bound), so the PPC64LE vpmsumd lowering must be
; proven in 32-bit mode specifically.
;
; XMM1..XMM5 use the exact same input blobs and immediates as the 64-bit
; H0F3A/pclmulqdq.asm, so the expected values are the suite's known-good
; (host-verified) values. Any divergence here while the 64-bit test passes
; isolates a 32-bit-mode-only defect (decoder, SRA layout, or the
; vs14-vs31 dw1 volatility class).
;
; XMM6/XMM7: ones x ones carryless square, imm 0x00 and 0x11. Derivation:
; (sum_{i=0..63} x^i)^2 over GF(2) -- result bit k is the parity of the
; number of (i,j) pairs with i+j=k, which is odd exactly for even k <= 126,
; giving the alternating pattern 0x5555...5555 in both halves. This is the
; worst-case full-width popcount pattern for a widening multiply lowering.

lea edx, [d0]
movups xmm1, [edx]
lea edx, [d1]
movups xmm2, [edx]

; imm = 0b00000000: low(src1) * low(src2)
pclmulqdq xmm1, xmm2, 0x00

; imm = 0b00000001: high(src1) * low(src2)
lea edx, [d0]
movups xmm3, [edx]
pclmulqdq xmm3, xmm2, 0x01

; imm = 0b00010000: low(src1) * high(src2)
movups xmm4, [edx]
pclmulqdq xmm4, xmm2, 0x10

; imm = 0b00010001: high(src1) * high(src2)
movups xmm5, [edx]
pclmulqdq xmm5, xmm2, 0x11

; all-ones square
lea edx, [ones]
movups xmm6, [edx]
movups xmm7, [edx]
pclmulqdq xmm6, xmm7, 0x00
pclmulqdq xmm7, xmm7, 0x11

hlt

; Same blobs as unittests/ASM/H0F3A/pclmulqdq.asm .data
d0:   db 0xe0, 0xfc, 0x2b, 0xa1, 0x06, 0x4f, 0x6c, 0xa7, 0x0f, 0x06, 0x6a, 0x1e, 0x7f, 0x76, 0x80, 0x9b
d1:   db 0xe0, 0x56, 0xed, 0xaa, 0xf3, 0xc3, 0x68, 0x68, 0xde, 0xe6, 0xe6, 0x94, 0xe2, 0xe9, 0xfc, 0xf0
ones: dq 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
