%ifdef CONFIG
{
  "RegData": {
    "R8":  "0x0706050403020100",
    "R9":  "0x4746454443424140",
    "R10": "0x1716151413121110",
    "R11": "0x5F5E5D5C5B5A5958",
    "R12": "0x2726252423222120",
    "R13": "0x4F4E4D4C4B4A4948",
    "R14": "0xB7B6B5B4B3B2B1B0",
    "R15": "0x5C5B5A5958575655"
  }
}
%endif

; Boundary coverage for the FEX_MEMCPYDCBZ cache-line MemCpy tier (PPC64LE).
; ctest forces FEX_MEMCPYDCBZ=1 for this file (unittests/ASM/CMakeLists.txt
; matches on the name), so the tier is actually entered here; every case below
; must produce the same bytes with the tier off, which is what the other legs
; and Primary_A4_REP_overlap_tiers32.asm cover.
;
; The tier is the only one that WRITES the destination line (dcbz) before
; reading the matching source line, so unlike every other tier it needs a
; TWO-SIDED distance gate. Cases 1 and 3 sit just inside that gate on either
; side of zero and would be corrupted by a one-sided `delta >= 128` test;
; case 2 sits exactly on the legal edge.

cld

; ---------------------------------------------------------------------------
; Case 1: dst BELOW src by 64. Every other tier passes this for free (reads run
; ahead of the writes that would clobber them) and the unsigned delta test
; waves it through, but a 128-byte dcbz at the aligned destination would zero
; source bytes this very iteration has not read yet. Result must be a plain
; copy of the original source bytes.
; ---------------------------------------------------------------------------
mov rdx, 0xe0000400
xor rax, rax
fill1:
mov [rdx + rax], al          ; src[j] = j & 0xFF
inc rax
cmp rax, 512
jne fill1

lea rsi, [rdx]               ; src = 0xe0000400
lea rdi, [rdx - 64]          ; dst = src - 64
mov rcx, 512
rep movsb
mov r8, [rdx - 64]           ; src[0..7]
mov r9, [rdx - 64 + 64]      ; src[64..71] -- zeroed if the gate is one-sided

; ---------------------------------------------------------------------------
; Case 2: forward delta == 128, exactly the line size. The widest legal
; self-replicating fill the tier may chunk: byte-forward semantics replicate
; the first 128 bytes across the whole destination, and 128-byte chunking
; agrees because chunk k is fully written before chunk k+1 is read.
; ---------------------------------------------------------------------------
mov rdx, 0xe0001000
xor rax, rax
fill2:
lea rbx, [rax + 0x10]
mov [rdx + rax], bl          ; pattern[j] = (j + 0x10) & 0xFF
inc rax
cmp rax, 128
jne fill2

lea rsi, [rdx]
lea rdi, [rdx + 128]
mov rcx, 512
rep movsb
mov r10, [rdx + 128]         ; pattern[0..7]
mov r11, [rdx + 128 + 200]   ; 200 mod 128 == 72 -> pattern[72..79]

; ---------------------------------------------------------------------------
; Case 3: forward delta == 64, one line size short. A legal self-replicating
; fill with a 64-byte period that 128-byte chunking would break, so the tier
; must decline it and leave the copy to the 32B tier.
; ---------------------------------------------------------------------------
mov rdx, 0xe0002000
xor rax, rax
fill3:
lea rbx, [rax + 0x20]
mov [rdx + rax], bl          ; pattern[j] = (j + 0x20) & 0xFF
inc rax
cmp rax, 64
jne fill3

lea rsi, [rdx]
lea rdi, [rdx + 64]
mov rcx, 512
rep movsb
mov r12, [rdx + 64]          ; pattern[0..7]
mov r13, [rdx + 64 + 40]     ; 40 mod 64 == 40 -> pattern[40..47]

; ---------------------------------------------------------------------------
; Case 4: non-overlapping, destination misaligned to ...05, length 301. One
; run crosses every stage in order: 3 byte-align, one 8B align step, seven 16B
; steps to reach the 128-byte line, one dcbz line, three 16B chunks and a
; 2-byte tail (3 + 8 + 112 + 128 + 48 + 2 == 301).
; ---------------------------------------------------------------------------
mov rdx, 0xe0003000
xor rax, rax
fill4:
lea rbx, [rax + 0x30]
mov [rdx + rax], bl          ; src[j] = (j + 0x30) & 0xFF
inc rax
cmp rax, 320
jne fill4

lea rsi, [rdx]
lea rdi, [rdx + 0x805]
mov rcx, 301
rep movsb
mov r14, [rdx + 0x805 + 128] ; src[128..135], inside the dcbz'd line
mov r15, [rdx + 0x805 + 293] ; src[293..300], the copy's final 8 bytes

hlt
