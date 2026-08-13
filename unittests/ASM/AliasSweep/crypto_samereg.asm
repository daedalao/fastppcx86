%ifdef CONFIG
{
  "RegData": {
      "RBX": "0x0"
  },
  "HostFeatures": ["AES", "SHA", "PCLMUL", "SSE4.2"]
}
%endif

; Same-register (Dst==Src) aliasing sweep for the crypto lowerings
; (hand-written companion to the generate_samereg.py files -- those cover
; the SSE/SSSE3/SSE4 integer ops; this covers AES/PCLMUL/SHA/CRC32, which
; the generator does not).
;
; Rationale (mmx-alias-hazard-class): a multi-instruction PPC64LE lowering
; that writes Dst before consuming every source is only wrong when a source
; aliases Dst, and only same-register guest encodings force that aliasing
; through SRA. Tonight's rewritten crypto lowerings (vcipher/vncipher AES
; chain with mask fusion + round-key folding, vpmsumd PCLMUL, VSha
; SHA rounds, CRC32) never get dst==src coverage from the FIPS-vector
; tests, so this file adds it. SHA256RNDS2 additionally has an IMPLICIT
; XMM0 operand -- a third role that can silently alias either explicit
; operand; all three alias shapes are exercised.
;
; Test shape per section (self-checking, expected RBX == 0):
;   reference: dst <- blob_a, src <- blob_b (identical CONTENT, distinct
;              labels so load-CSE cannot merge them), op dst, src
;   aliased:   alias <- blob_a, op alias, alias
;   bitwise compare; mismatch sets bit N of RBX, convicting the lowering
;   named at that section. The oracle is the emulator's own non-aliased
;   path: equal input values must give bitwise-equal results regardless
;   of operand aliasing.

xor rbx, rbx

; bit 0: aesenc xmm,xmm (state == round key)
movdqa xmm0, [rel blob_a]
movdqa xmm1, [rel blob_b]
aesenc xmm0, xmm1
movdqa xmm2, [rel blob_a]
aesenc xmm2, xmm2
pcmpeqb xmm0, xmm2
pmovmskb eax, xmm0
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 0
or rbx, rax

; bit 1: aesdec xmm,xmm
movdqa xmm0, [rel blob_a]
movdqa xmm1, [rel blob_b]
aesdec xmm0, xmm1
movdqa xmm2, [rel blob_a]
aesdec xmm2, xmm2
pcmpeqb xmm0, xmm2
pmovmskb eax, xmm0
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 1
or rbx, rax

; bit 2: aesenclast xmm,xmm
movdqa xmm0, [rel blob_a]
movdqa xmm1, [rel blob_b]
aesenclast xmm0, xmm1
movdqa xmm2, [rel blob_a]
aesenclast xmm2, xmm2
pcmpeqb xmm0, xmm2
pmovmskb eax, xmm0
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 2
or rbx, rax

; bit 3: aesdeclast xmm,xmm
movdqa xmm0, [rel blob_a]
movdqa xmm1, [rel blob_b]
aesdeclast xmm0, xmm1
movdqa xmm2, [rel blob_a]
aesdeclast xmm2, xmm2
pcmpeqb xmm0, xmm2
pmovmskb eax, xmm0
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 3
or rbx, rax

; bit 4: aesimc xmm,xmm (single-source dst==src)
movdqa xmm1, [rel blob_a]
aesimc xmm0, xmm1
movdqa xmm2, [rel blob_a]
aesimc xmm2, xmm2
pcmpeqb xmm0, xmm2
pmovmskb eax, xmm0
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 4
or rbx, rax

; bit 5: pclmulqdq xmm,xmm, 0x00 (carryless square, low*low)
movdqa xmm0, [rel blob_a]
movdqa xmm1, [rel blob_b]
pclmulqdq xmm0, xmm1, 0x00
movdqa xmm2, [rel blob_a]
pclmulqdq xmm2, xmm2, 0x00
pcmpeqb xmm0, xmm2
pmovmskb eax, xmm0
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 5
or rbx, rax

; bit 6: pclmulqdq xmm,xmm, 0x11 (high*high)
movdqa xmm0, [rel blob_a]
movdqa xmm1, [rel blob_b]
pclmulqdq xmm0, xmm1, 0x11
movdqa xmm2, [rel blob_a]
pclmulqdq xmm2, xmm2, 0x11
pcmpeqb xmm0, xmm2
pmovmskb eax, xmm0
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 6
or rbx, rax

; bit 7: sha1rnds4 xmm,xmm, 0 (ABCD state == W block)
movdqa xmm0, [rel blob_a]
movdqa xmm1, [rel blob_b]
sha1rnds4 xmm0, xmm1, 0
movdqa xmm2, [rel blob_a]
sha1rnds4 xmm2, xmm2, 0
pcmpeqb xmm0, xmm2
pmovmskb eax, xmm0
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 7
or rbx, rax

; bit 8: sha256rnds2 with DST aliasing the implicit XMM0 (wk).
; reference: XMM0 = wk = blob_a, dst xmm2 = state = blob_b (same content
; as blob_a so dst VALUE == wk VALUE), src xmm3 = blob_c.
; aliased: XMM0 reloaded from blob_b, sha256rnds2 xmm0, xmm3 -- XMM0 is
; simultaneously dst and implicit wk with the same input values.
movdqa xmm0, [rel blob_a]
movdqa xmm2, [rel blob_b]
movdqa xmm3, [rel blob_c]
sha256rnds2 xmm2, xmm3
movdqa xmm0, [rel blob_b]
sha256rnds2 xmm0, xmm3
pcmpeqb xmm2, xmm0
pmovmskb eax, xmm2
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 8
or rbx, rax

; bit 9: sha256rnds2 with SRC aliasing the implicit XMM0.
; reference: XMM0 = wk = blob_a, dst xmm2 = state = blob_c,
; src xmm3 = blob_b (same content as the wk).
; aliased: dst xmm4 = blob_c, sha256rnds2 xmm4, xmm0 -- XMM0 is
; simultaneously explicit src and implicit wk.
movdqa xmm0, [rel blob_a]
movdqa xmm2, [rel blob_c]
movdqa xmm3, [rel blob_b]
sha256rnds2 xmm2, xmm3
movdqa xmm4, [rel blob_c]
sha256rnds2 xmm4, xmm0
pcmpeqb xmm2, xmm4
pmovmskb eax, xmm2
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 9
or rbx, rax

; bit 10: sha256rnds2 xmm0, xmm0 -- all three roles (dst, src, implicit wk)
; in one register.
; reference: XMM0 = wk = blob_a, dst xmm2 = blob_b, src xmm3 = blob_b2
; (three distinct labels, all identical content).
movdqa xmm0, [rel blob_a]
movdqa xmm2, [rel blob_b]
movdqa xmm3, [rel blob_b2]
sha256rnds2 xmm2, xmm3
movdqa xmm0, [rel blob_b2]
sha256rnds2 xmm0, xmm0
pcmpeqb xmm2, xmm0
pmovmskb eax, xmm2
cmp eax, 0xFFFF
setne al
movzx eax, al
shl rax, 10
or rbx, rax

; bit 11: crc32 eax, eax (GPR accumulator == data)
mov ecx, 0xDEADBEEF
mov edx, 0xDEADBEEF
crc32 ecx, edx
mov eax, 0xDEADBEEF
crc32 eax, eax
cmp ecx, eax
setne al
movzx eax, al
shl rax, 11
or rbx, rax

hlt

align 16
; Identical content, distinct labels (so load-CSE cannot merge the loads
; and the reference genuinely uses two registers). Bytes chosen with all
; dword lanes distinct and byte-reverse-asymmetric -- the AES lowering's
; byte-reverse mask fusion (0293792c5) reorders lanes, so a palindromic
; blob could hide a swap.
blob_a:  db 0xe0, 0xfc, 0x2b, 0xa1, 0x06, 0x4f, 0x6c, 0xa7, 0x0f, 0x06, 0x6a, 0x1e, 0x7f, 0x76, 0x80, 0x9b
blob_b:  db 0xe0, 0xfc, 0x2b, 0xa1, 0x06, 0x4f, 0x6c, 0xa7, 0x0f, 0x06, 0x6a, 0x1e, 0x7f, 0x76, 0x80, 0x9b
blob_b2: db 0xe0, 0xfc, 0x2b, 0xa1, 0x06, 0x4f, 0x6c, 0xa7, 0x0f, 0x06, 0x6a, 0x1e, 0x7f, 0x76, 0x80, 0x9b
; A different second operand for the SHA dual-role sections
blob_c:  db 0xc7, 0xcd, 0x73, 0xec, 0x95, 0xd6, 0x6f, 0x6a, 0xbb, 0xae, 0xf2, 0xbb, 0x27, 0xb9, 0xa1, 0xdd
