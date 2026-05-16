%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x0000000080050033",
    "RBX": "0x4142434480050033",
    "RCX": "0x4142434445460033",
    "RDX": "0x4142434445460033",
    "RDI": "0x0000000080050033",
    "RSP": "0x0000000080050033",
    "RBP": "0x0000000080050033",
    "R8":  "0x4142434445460033",
    "R9":  "0x4142434445460033",
    "R10": "0x4142434445460033"
  }
}
%endif

mov rax, 0x4142434445464748
mov rbx, 0x4142434445464748
mov rcx, 0x4142434445464748
mov rdx, 0x4142434445464748
mov rsi, 0xe000_0000
mov [rsi], rdx

mov rdi, 0x4142434445464748
mov rsp, 0x4142434445464748
mov rbp, 0x4142434445464748
mov r8, 0x4142434445464748
mov r9, 0x4142434445464748
mov r10, 0x4142434445464748

; Modern NASM (>= 2.16) does not emit REX.W or 0x66 for SMSW based on
; the destination register name; the encoding is always '0F 01 /4'.
; To exercise every operand-size variant we encode prefix bytes manually.

; smsw rax: REX.W => 64-bit destination, zero-extended.
db 0x48, 0x0f, 0x01, 0xe0
; smsw ebx: no prefix => 32-bit destination, upper 32 preserved (FEX/AMD semantic).
db 0x0f, 0x01, 0xe3
; smsw cx: 0x66 => 16-bit destination, upper 48 preserved.
db 0x66, 0x0f, 0x01, 0xe1

; smsw [rsi]: memory destination, always 16-bit.
smsw [rsi]
mov rdx, [rsi]

; 0x66 + REX.W: REX.W wins => 64-bit destination, zero-extended.
db 0x66, 0x48, 0x0f, 0x01, 0xe7
db 0xf3, 0x48, 0x0f, 0x01, 0xe4
db 0xf2, 0x48, 0x0f, 0x01, 0xe5

; 0x66 + REX.B (no REX.W) => 16-bit destination, upper 48 preserved.
db 0x66, 0x41, 0x0f, 0x01, 0xe0
db 0x66, 0xf3, 0x41, 0x0f, 0x01, 0xe1
db 0x66, 0xf2, 0x41, 0x0f, 0x01, 0xe2

hlt
