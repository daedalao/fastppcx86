%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x0706050403020100",
    "RBX": "0xEEEEEEEEEEEEEEEE",
    "RCX": "0xEEEEEEEEB5A69788",
    "RDX": "0xDEADBEEFCAFEBABE",
    "RSI": "0xEEEEEEEEEEEEEEEE",
    "RDI": "0xEEEEEEEE03020100",
    "RBP": "0xE2D3C4B5A69788EE",
    "R8":  "0xEEEEEEEEEEEEEEF1",
    "R9":  "0xEECAFEBABEEEEEEE",
    "R10": "0xEEEEEEEEEEEEEEEE",
    "R11": "0x020100EEEEEEEEEE",
    "R12": "0xEEEEEE0706050403",
    "R13": "0xEEEEEEEEEEEEEEEE",
    "XMM0": ["0x0706050403020100", "0x0F0E0D0C0B0A0908"],
    "XMM1": ["0xF1E2D3C4B5A69788", "0x1122334455667788"],
    "XMM2": ["0xDEADBEEFCAFEBABE", "0x0123456789ABCDEF"]
  }
}
%endif

; 4- and 8-byte FPR->memory stores (movss/movsd/movd/movq) must write EXACTLY
; `size` bytes, taken from the LOW end of the xmm register, at ANY alignment,
; and must leave the source register untouched.
;
; On the PPC64LE backend these go through StoreFPRSized, whose 4/8-byte fast
; path is xxpermdi + stxsdx/stxsiwx. A wrong permute or a wrong element size
; there does not fault — it silently writes the wrong bytes, or writes 16 of
; them (the historical stvx bug that ate __tls_init_tp's neighbours in
; hello_static). So every store below lands in a buffer pre-filled with 0xEE
; and the read-back checks the SENTINEL bytes on both sides as well as the
; stored bytes: an over-wide store or a misplaced value fails a GPR compare.
;
; Offsets are deliberately mixed: naturally aligned (0/16/24/40) and
; deliberately misaligned by 1, 3 and 5 (49/67/85).

lea r15, [rel .scratch]

movups xmm0, [rel .val0]
movups xmm1, [rel .val1]
movups xmm2, [rel .val2]

jmp .test
.test:

; Aligned stores.
movsd [r15 + 0],  xmm0        ; 8 bytes: 0706050403020100
movss [r15 + 16], xmm1        ; 4 bytes: B5A69788
movq  [r15 + 24], xmm2        ; 8 bytes: DEADBEEFCAFEBABE
movd  [r15 + 40], xmm0        ; 4 bytes: 03020100

; Unaligned stores (offset 1, 3 and 5 past a doubleword boundary).
movsd [r15 + 49], xmm1        ; 8 bytes straddling 48..56
movss [r15 + 67], xmm2        ; 4 bytes inside 64..71
movq  [r15 + 85], xmm0        ; 8 bytes straddling 80..93

; Read every touched doubleword back, including the untouched neighbours.
mov rax, [r15 + 0]
mov rbx, [r15 + 8]
mov rcx, [r15 + 16]
mov rdx, [r15 + 24]
mov rsi, [r15 + 32]
mov rdi, [r15 + 40]
mov rbp, [r15 + 48]
mov r8,  [r15 + 56]
mov r9,  [r15 + 64]
mov r10, [r15 + 72]
mov r11, [r15 + 80]
mov r12, [r15 + 88]
mov r13, [r15 + 96]

hlt

align 16
.val0:
dq 0x0706050403020100, 0x0F0E0D0C0B0A0908
.val1:
dq 0xF1E2D3C4B5A69788, 0x1122334455667788
.val2:
dq 0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF

align 16
.scratch:
times 16 dq 0xEEEEEEEEEEEEEEEE
