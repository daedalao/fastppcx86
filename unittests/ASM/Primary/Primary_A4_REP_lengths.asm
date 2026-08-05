%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x0"
  },
  "MemoryRegions": {
    "0xe0000000": "65536"
  }
}
%endif

; REP MOVSB across the lengths and alignments that select different arms of the
; PPC64LE backend's fast path: the byte align-up loop, the CTR-counted 8-byte
; chunk loop (mtctr/ldu/stdu/bdnz), and the byte tail loop. Source and
; destination are 16 KiB apart, so the unsigned delta >= 8 overlap guard always
; picks the chunked path.
;
; Every case self-checks in-guest and increments r15 on mismatch, so the only
; expected result is RAX == 0. Buffer prep uses explicit byte loops rather than
; another REP MOVS so a bug in the path under test cannot cancel itself out.
;
; rbp = destination base, r14 = source base, r15 = error count, rbx = index.

; %1 = length, %2 = misalignment of the destination (source stays 8-aligned so
; that the source-unaligned and destination-unaligned cases are distinguishable)
%macro MOVS_CASE 2
    ; Poison the destination span with 0xAA by hand.
    xor rbx, rbx
%%prepdst:
    mov byte [rbp + rbx], 0xAA
    inc rbx
    cmp rbx, (128 + %1 + %2)
    jb %%prepdst

    ; Source pattern: src[j] = (j ^ 0x5A) & 0xFF, so any lane rotation or
    ; off-by-one in the chunk loop shows up as a value mismatch, not just a
    ; length mismatch. Guard against a zero-length loop body.
%if %1 > 0
    xor rbx, rbx
%%prepsrc:
    mov eax, ebx
    xor eax, 0x5A
    mov byte [r14 + rbx], al
    inc rbx
    cmp rbx, %1
    jb %%prepsrc
%endif

    lea rdi, [rbp + (64 + %2)]
    mov rsi, r14
    mov rcx, %1
    cld
    rep movsb

    ; RDI/RSI must both have advanced by exactly the length, RCX drained.
    lea rdx, [rbp + (64 + %2 + %1)]
    cmp rdi, rdx
    je %%rdi_ok
    inc r15
%%rdi_ok:
    lea rdx, [r14 + %1]
    cmp rsi, rdx
    je %%rsi_ok
    inc r15
%%rsi_ok:
    test rcx, rcx
    jz %%rcx_ok
    inc r15
%%rcx_ok:

    ; Byte-exact check over the whole span: the pattern inside the copied
    ; range, untouched 0xAA outside it.
    xor rbx, rbx
%%vloop:
    movzx eax, byte [rbp + rbx]
    mov edx, 0xAA
    cmp rbx, (64 + %2)
    jb %%cmpit
    cmp rbx, (64 + %2 + %1)
    jae %%cmpit
    mov edx, ebx
    sub edx, (64 + %2)
    xor edx, 0x5A
    and edx, 0xFF
%%cmpit:
    cmp eax, edx
    je %%next
    inc r15
%%next:
    inc rbx
    cmp rbx, (128 + %1 + %2)
    jb %%vloop
%endmacro

    mov rbp, 0xe0000000
    mov r14, 0xe0004000
    xor r15, r15

    MOVS_CASE 0, 0
    MOVS_CASE 1, 0
    MOVS_CASE 7, 0
    MOVS_CASE 8, 0
    MOVS_CASE 9, 0
    MOVS_CASE 255, 0
    MOVS_CASE 4096, 0

    MOVS_CASE 1, 1
    MOVS_CASE 7, 3
    MOVS_CASE 8, 1
    MOVS_CASE 9, 7
    MOVS_CASE 255, 5
    MOVS_CASE 4096, 3

    mov rax, r15
    hlt
