%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x0000000080050033",
    "RBX": "0x0000000041420033",
    "RCX": "0x0000000041420033",
    "RDX": "0x0000000041420033",
    "RDI": "0x0000000080050033",
    "RSP": "0x0000000080050033",
    "RBP": "0x0000000041420033"
  },
  "Mode": "32BIT"
}
%endif

mov eax, 0x41424344
mov ebx, 0x41424344
mov ecx, 0x41424344
mov edx, 0x41424344
mov esi, 0xe000_0000
mov [esi], edx

mov edi, 0x41424344
mov esp, 0x41424344
mov ebp, 0x41424344

; Modern NASM does not emit 0x66 for 'smsw bx' based on the destination
; register name; the encoding is always '0F 01 /4'. Use explicit prefix
; bytes to force 16-bit operand size where needed.

; smsw eax: no prefix => 32-bit destination.
db 0x0f, 0x01, 0xe0
; smsw bx: 0x66 => 16-bit destination, upper 16 of low-32 preserved.
db 0x66, 0x0f, 0x01, 0xe3

; smsw [esi]: memory dest, 16-bit.
smsw [esi]
mov ecx, [esi]

; o16 smsw dx
db 0x66, 0x0f, 0x01, 0xe2
; repe smsw edi
db 0xf3, 0x0f, 0x01, 0xe7
; repne smsw esp
db 0xf2, 0x0f, 0x01, 0xe4

; o16 smsw bp (16-bit dest)
db 0x66, 0x0f, 0x01, 0xe5

hlt
