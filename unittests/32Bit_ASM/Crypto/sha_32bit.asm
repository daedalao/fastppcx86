%ifdef CONFIG
{
  "RegData": {
    "XMM1": ["0x97D4574EE323773D", "0xA934C32F562D8E88"],
    "XMM2": ["0x6868C3F3AAED56E0", "0xF0FCE9E294E6E6DE"],
    "XMM3": ["0xA5E1EC3918BE0C95", "0xA3F7BF0143303AFB"],
    "XMM4": ["0xA8B3BD15FA04D6D7", "0xDE761956A1F750B1"],
    "XMM5": ["0xCFBBDFA4E5E4712D", "0x76AD0D46447127D3"],
    "XMM6": ["0x9BDCA44510E70C65", "0x4474BFAA2B70A524"]
  },
  "HostFeatures": ["SHA"],
  "Mode": "32BIT"
}
%endif

; 32-BIT MODE SHA-NI: sha256rnds2 and sha1rnds4 (all four imm2 values).
; The 64-bit suite has H0F38/sha256rnds2.asm and H0F3A/sha1rnds4.asm; there
; was NO 32-bit SHA test. The Steam client (32-bit) verifies depot chunks
; with SHA-1/SHA-256, and the PPC64LE JIT recently rewrote these lowerings
; (inline VSha1H, SHA256RNDS2 vector design) -- 32-bit mode exercises the
; same IR through the 32-bit SRA/decoder path where the vs14-vs31 dw1
; volatility class historically hid (vsx-low-bank-dw1-volatile).
;
; Inputs and expected values are IDENTICAL to the two 64-bit tests (same
; .data blobs, same register roles), so the expectations are the suite's
; known-good host-verified values, additionally reproduced by an
; independent Python model of the SDM pseudocode. A failure here with the
; 64-bit twins passing isolates a 32-bit-mode-only defect.
;
; sha256rnds2: XMM0 (implicit) = wk = d2 blob, dest XMM1 = CDGH = d0 blob,
;              src XMM2 = ABEF = d1 blob.
; sha1rnds4:   dest = ABCD = d0 blob, src = W0E..W3 = d1 blob, imm 0..3
;              (SHA1 f/K constant selection per round quadrant).

lea edx, [d2]
movups xmm0, [edx]
lea edx, [d0]
movups xmm1, [edx]
lea edx, [d1]
movups xmm2, [edx]

sha256rnds2 xmm1, xmm2

; sha1rnds4 with each immediate; XMM2 (src) must be unchanged throughout
lea edx, [d0]
movups xmm3, [edx]
sha1rnds4 xmm3, xmm2, 0

movups xmm4, [edx]
sha1rnds4 xmm4, xmm2, 1

movups xmm5, [edx]
sha1rnds4 xmm5, xmm2, 2

movups xmm6, [edx]
sha1rnds4 xmm6, xmm2, 3

hlt

; Same blobs as the 64-bit sha256rnds2.asm / sha1rnds4.asm .data
d0: db 0xe0, 0xfc, 0x2b, 0xa1, 0x06, 0x4f, 0x6c, 0xa7, 0x0f, 0x06, 0x6a, 0x1e, 0x7f, 0x76, 0x80, 0x9b
d1: db 0xe0, 0x56, 0xed, 0xaa, 0xf3, 0xc3, 0x68, 0x68, 0xde, 0xe6, 0xe6, 0x94, 0xe2, 0xe9, 0xfc, 0xf0
d2: db 0xc7, 0xcd, 0x73, 0xec, 0x95, 0xd6, 0x6f, 0x6a, 0xbb, 0xae, 0xf2, 0xbb, 0x27, 0xb9, 0xa1, 0xdd
