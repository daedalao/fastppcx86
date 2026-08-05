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

; REP STOSB across the lengths and alignments that select different arms of the
; PPC64LE backend's fast path: the byte align-up loop, the CTR-counted 8-byte
; chunk loop (mtctr/stdu/bdnz), and the byte tail loop.
;
; Every case self-checks in-guest and increments r15 on mismatch, so the only
; expected result is RAX == 0. Buffer prep uses an explicit byte loop rather
; than another REP STOS so a bug in the path under test cannot cancel itself
; out during setup.
;
; rbp = scratch base, r15 = error count, rbx = verify index.

; %1 = length, %2 = misalignment of the destination
%macro STOS_CASE 2
    ; Fill [rbp, rbp + SPAN) with 0xAA by hand.
    xor rbx, rbx
%%prep:
    mov byte [rbp + rbx], 0xAA
    inc rbx
    cmp rbx, (128 + %1 + %2)
    jb %%prep

    lea rdi, [rbp + (64 + %2)]
    mov rcx, %1
    mov eax, 0x5A
    cld
    rep stosb

    ; RDI must have advanced by exactly the length.
    lea rdx, [rbp + (64 + %2 + %1)]
    cmp rdi, rdx
    je %%rdi_ok
    inc r15
%%rdi_ok:
    ; RCX must be drained.
    test rcx, rcx
    jz %%rcx_ok
    inc r15
%%rcx_ok:

    ; Byte-exact check: 0x5A inside the written range, 0xAA everywhere else in
    ; the span (catches both short writes and overruns past either end).
    xor rbx, rbx
%%vloop:
    movzx eax, byte [rbp + rbx]
    mov edx, 0xAA
    cmp rbx, (64 + %2)
    jb %%cmpit
    cmp rbx, (64 + %2 + %1)
    jae %%cmpit
    mov edx, 0x5A
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
    xor r15, r15

    ; Aligned destination (misalign 0): exercises the chunk loop entry with no
    ; align-up iterations, including the zero-chunk (len < 8) cases.
    STOS_CASE 0, 0
    STOS_CASE 1, 0
    STOS_CASE 7, 0
    STOS_CASE 8, 0
    STOS_CASE 9, 0
    STOS_CASE 255, 0
    STOS_CASE 4096, 0

    ; Misaligned destinations: 1..7 align-up bytes before the chunk loop, and a
    ; non-empty tail after it.
    STOS_CASE 1, 1
    STOS_CASE 7, 3
    STOS_CASE 8, 1
    STOS_CASE 9, 7
    STOS_CASE 255, 5
    STOS_CASE 4096, 3

    mov rax, r15
    hlt
