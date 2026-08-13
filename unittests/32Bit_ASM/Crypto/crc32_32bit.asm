%ifdef CONFIG
{
  "RegData": {
    "RAX": "0xE3069283",
    "RBX": "0x29853549",
    "RCX": "0x6BCBAD0D",
    "RDX": "0x56D72B93",
    "RDI": "0x2B14F3BC"
  },
  "HostFeatures": ["SSE4.2"],
  "Mode": "32BIT"
}
%endif

; 32-BIT MODE CRC32 (SSE4.2 CRC-32C, poly 0x11EDC6F41, bit-reflected) at
; r/m8, r/m16 and r/m32 operand widths. The 64-bit suite has H0F38/F2_F0/F1;
; there was NO 32-bit crc32 test. Steam (32-bit) is crc-bound on downloads
; and the PPC64LE lowering is moving from a scalar helper to
; vpmsumd/Barrett (crypto-stack-remaining-work), so lock 32-bit-mode
; semantics down first.
;
; Expected values from a bit-level reflected CRC-32C model that reproduces
; the existing suite's F2_F0.asm values (crc32(0, byte 0xe0) = 0xE330A81A
; etc.) before generating these:
;
; EAX: the RFC 3720 / iSCSI check value. acc = 0xFFFFFFFF, then crc32 over
;      the 9 bytes "123456789", then final xor 0xFFFFFFFF. The standard
;      CRC-32C check value is 0xE3069283 -- if any byte-width step is
;      wrong, this cannot come out right. (Pre-final-xor acc = 0x1CF96D7C.)
; EBX: acc = 0x12345678, crc32 ebx, byte 0x21     -> 0x29853549
; ECX: acc = 0x12345678, crc32 ecx, word 0x4321   -> 0x6BCBAD0D
;      (a 16-bit reflected update is mathematically equivalent to byte
;      steps 0x21 then 0x43 in LE order -- verified both ways -- so this
;      catches a lowering that consumes the word in the WRONG byte order
;      or width.)
; EDX: acc = 0x12345678, crc32 edx, dword 0x87654321 -> 0x56D72B93
; EDI: width-chaining: acc = 0, byte 0xAB -> 0x3BC21E9D, then word 0xCDEF
;      -> 0x589FCDF4, then dword 0x01234567 -> 0x2B14F3BC. Exercises
;      accumulator flow between differently-sized updates (the fold/Barrett
;      seam in a vectorized lowering).

; EAX: iSCSI check value over "123456789"
mov eax, 0xFFFFFFFF
lea esi, [nine]
xor ecx, ecx
.loop:
crc32 eax, byte [esi + ecx]
inc ecx
cmp ecx, 9
jne .loop
xor eax, 0xFFFFFFFF

; EBX: byte width from register
mov ebx, 0x12345678
mov dl, 0x21
crc32 ebx, dl

; ECX: word width from memory
mov ecx, 0x12345678
crc32 ecx, word [w16]

; EDX: dword width from memory
mov edx, 0x12345678
crc32 edx, dword [w32]

; EDI: chained widths
xor edi, edi
crc32 edi, byte [b8]
crc32 edi, word [wchain]
crc32 edi, dword [dchain]

hlt

nine:   db "123456789"
w16:    dw 0x4321
w32:    dd 0x87654321
b8:     db 0xAB
wchain: dw 0xCDEF
dchain: dd 0x01234567
