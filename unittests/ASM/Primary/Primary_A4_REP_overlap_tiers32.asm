%ifdef CONFIG
{
  "RegData": {
    "R8":  "0x1112131415161718",
    "R9":  "0x2122232425262728",
    "R10": "0x3132333435363738",
    "R11": "0x4142434445464748",
    "R12": "0x6162636465666768",
    "R13": "0x0706050403020100",
    "R14": "0x3F3E3D3C3B3A3938",
    "R15": "0x7877767574737271"
  }
}
%endif

; Boundary coverage for the 32-byte MemCpy chunk tier (PPC64LE): copies long
; enough for the 32B tier's len >= 64 gate, with forward deltas of 16 and 32.
; delta == 16 replicates the first 16 bytes -- exact for 16B chunks, broken
; by 32B chunks, so it pins the tier-selection boundary. delta == 32 is the
; widest legal self-replicating fill the 32B tier may chunk. The third copy
; is non-overlapping with a misaligned destination and a ragged length so one
; run crosses every stage: byte-align, 8B-align, 32B loop, 8B chunk, byte tail.

cld

; delta == 16, len 96: byte-forward semantics replicate the first 16 bytes
; across [16, 112). The 32B tier must reject this (delta < 32) and leave it
; to the 16B tier, which is exact here.
mov rdx, 0xe0000000
mov rax, 0x1112131415161718
mov [rdx], rax
mov rax, 0x2122232425262728
mov [rdx + 8], rax
lea rsi, [rdx]
lea rdi, [rdx + 16]
mov rcx, 96
rep movsb
mov r8,  [rdx + 16]      ; first replicated qword
mov r9,  [rdx + 104]     ; last qword: offset 88 into the fill, 88 % 16 == 8

; delta == 32, len 96: replicates the first 32 bytes across [32, 128).
; 32B chunks are exact here; anything wider would not be.
mov rdx, 0xe0001000
mov rax, 0x3132333435363738
mov [rdx], rax
mov rax, 0x4142434445464748
mov [rdx + 8], rax
mov rax, 0x5152535455565758
mov [rdx + 16], rax
mov rax, 0x6162636465666768
mov [rdx + 24], rax
lea rsi, [rdx]
lea rdi, [rdx + 32]
mov rcx, 96
rep movsb
mov r10, [rdx + 32]      ; offset 0 into the fill
mov r11, [rdx + 72]      ; offset 40, 40 % 32 == 8
mov r12, [rdx + 120]     ; offset 88, 88 % 32 == 24

; Non-overlapping, destination misaligned to ...05, len 121 = 3 align bytes
; + one 8B align step + 3 x 32B chunks + one 8B chunk + 6-byte tail (the
; 16B remainder peel is skipped: remainder 14 < 16). Source byte j holds j.
mov rdx, 0xe0002000
xor rax, rax
fill:
mov [rdx + rax], al
inc rax
cmp rax, 128
jne fill
lea rsi, [rdx]
lea rdi, [rdx + 0x205]
mov rcx, 121
rep movsb
mov r13, [rdx + 0x205]        ; bytes 0..7
mov r14, [rdx + 0x205 + 56]   ; bytes 56..63
mov r15, [rdx + 0x205 + 113]  ; bytes 113..120, the copy's final 8

hlt
