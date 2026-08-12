%ifdef CONFIG
{
  "RegData": {
    "R8":  "0x4142434445464748",
    "R9":  "0x4142434445464748",
    "R10": "0x4142434445464748",
    "R11": "0x1112131415161718",
    "R12": "0x2122232425262728",
    "R13": "0x2122232425262728",
    "R14": "0xA1A2A3A4A5A6A7A8",
    "R15": "0xF1F2F3F4F5F6F7F8"
  }
}
%endif

; Boundary coverage for chunked rep-movsb fast paths (PPC64LE MemCpy tiers):
; forward copies where dst - src == 8 and == 16 are legal self-replicating
; pattern fills whose results differ if a backend chunks wider than the
; delta allows, plus a non-overlapping copy with a misaligned destination
; long enough to exercise the destination-alignment steps ahead of the
; widest chunk loop.

cld

; delta == 8, len 48: byte-forward semantics replicate the first 8 bytes.
; A 16-byte chunk here would read bytes its own earlier stores should have
; produced from stale memory instead.
mov rdx, 0xe0000000
mov rax, 0x4142434445464748
mov [rdx], rax
lea rsi, [rdx]
lea rdi, [rdx + 8]
mov rcx, 48
rep movsb
mov r8,  [rdx + 8]
mov r9,  [rdx + 24]
mov r10, [rdx + 48]

; delta == 16, len 48: replicates the first 16 bytes; 16-byte chunks are
; exact here, wider ones would not be.
mov rdx, 0xe0001000
mov rax, 0x1112131415161718
mov [rdx], rax
mov rax, 0x2122232425262728
mov [rdx + 8], rax
lea rsi, [rdx]
lea rdi, [rdx + 16]
mov rcx, 48
rep movsb
mov r11, [rdx + 16]
mov r12, [rdx + 24]
mov r13, [rdx + 56]

; Non-overlapping, destination misaligned to ...05, len 48: forces the
; byte-align and 8-byte-align steps before the widest chunk loop, plus a
; byte tail.
mov rdx, 0xe0002000
mov rax, 0xA1A2A3A4A5A6A7A8
mov [rdx], rax
mov rax, 0xB1B2B3B4B5B6B7B8
mov [rdx + 8], rax
mov rax, 0xC1C2C3C4C5C6C7C8
mov [rdx + 16], rax
mov rax, 0xD1D2D3D4D5D6D7D8
mov [rdx + 24], rax
mov rax, 0xE1E2E3E4E5E6E7E8
mov [rdx + 32], rax
mov rax, 0xF1F2F3F4F5F6F7F8
mov [rdx + 40], rax
lea rsi, [rdx]
lea rdi, [rdx + 0x105]
mov rcx, 48
rep movsb
mov r14, [rdx + 0x105]
mov r15, [rdx + 0x105 + 40]

hlt
