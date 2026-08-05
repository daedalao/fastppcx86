%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x0"
  },
  "MemoryRegions": {
    "0xe0000000": "131072"
  }
}
%endif

; REP STOSB with a compile-time-zero fill value. On PPC64LE this selects the
; dcbz block-zero arm of the backend's fast path: byte align-up, 8-byte
; align-up to a cache block, dcbz per block via CTR, then the std chunk loop
; and the byte tail for whatever is left.
;
; Lengths are chosen around the >= 2 blocks threshold (128-byte blocks on
; POWER8, so 256) and to straddle it, and all runs cross at least one 4 KiB
; page boundary at the longer sizes. Misalignments 0..7 force a non-empty byte
; align-up, and starting offsets that are 8-aligned-but-not-block-aligned force
; a non-empty std align-up before the first dcbz.
;
; Self-checking: r15 counts mismatches, expected RAX == 0. Prep uses an
; explicit byte loop so the path under test is not used to set up its own
; input.
;
; rbp = scratch base, r15 = error count, rbx = index.

; %1 = length, %2 = extra offset added to the 64-byte guard prefix
%macro STOSZ_CASE 2
    xor rbx, rbx
%%prep:
    mov byte [rbp + rbx], 0xAA
    inc rbx
    cmp rbx, (128 + %1 + %2)
    jb %%prep

    lea rdi, [rbp + (64 + %2)]
    mov rcx, %1
    xor eax, eax
    cld
    rep stosb

    lea rdx, [rbp + (64 + %2 + %1)]
    cmp rdi, rdx
    je %%rdi_ok
    inc r15
%%rdi_ok:
    test rcx, rcx
    jz %%rcx_ok
    inc r15
%%rcx_ok:

    xor rbx, rbx
%%vloop:
    movzx eax, byte [rbp + rbx]
    mov edx, 0xAA
    cmp rbx, (64 + %2)
    jb %%cmpit
    cmp rbx, (64 + %2 + %1)
    jae %%cmpit
    xor edx, edx
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

    ; Below and around the two-block threshold: must stay on the std path or
    ; take exactly one/two dcbz blocks.
    STOSZ_CASE 0, 0
    STOSZ_CASE 8, 0
    STOSZ_CASE 128, 0
    STOSZ_CASE 255, 0
    STOSZ_CASE 256, 0
    STOSZ_CASE 257, 0
    STOSZ_CASE 383, 0

    ; Multi-block, page-crossing.
    STOSZ_CASE 1024, 0
    STOSZ_CASE 4096, 0
    STOSZ_CASE 8192, 0

    ; Byte align-up plus block align-up, still multi-block and page-crossing.
    STOSZ_CASE 256, 1
    STOSZ_CASE 300, 3
    STOSZ_CASE 1024, 7
    STOSZ_CASE 4096, 5
    STOSZ_CASE 4097, 8
    STOSZ_CASE 8192, 40

    mov rax, r15
    hlt
