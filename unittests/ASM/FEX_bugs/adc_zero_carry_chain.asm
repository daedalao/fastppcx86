%ifdef CONFIG
{
  "RegData": {
    "RAX": "5",
    "RBX": "0",
    "RCX": "3",
    "RDX": "0",
    "R8":  "1",
    "R9":  "1"
  }
}
%endif

; PPC64LE backend: `adc $0, reg` (AdcZeroWithFlags) stored its carry-out in
; the CFInverted=true convention while the dispatcher's ADCOp declares
; `CFInverted = false` after emitting it. Every carry consumer AFTER a mid-chain
; `adc $0` therefore read !CF: a following `adc` added a phantom +1 whenever
; the real CF was 0 (and dropped a real +1 when CF was 1), and a following
; `jc`/`cmovc`/`setc` took the wrong side.
;
; Found via BoringSSL's ecp_nistz256_point_add_nohw (__ecp_nistz256_subq):
;   addq $-1, %rax ; adcq %r14, %rbp ; adcq $0, %rcx ; adcq %r15, %r10
; The final adc consumed the inverted carry, so p256 point-add X/Y were off by
; 2^192 and every Chromium/Steam TLS handshake failed with BAD_SIGNATURE.
;
; The test replicates a mid-chain adc $0 in both carry states and checks the
; following adc and setc observe the true carry.

section .text
global _start

_start:
; Case 1: CF=0 into `adc $0` (no carry generated anywhere).
; rax = 2 + 2 (+0) = 4; adc $0 keeps 4, CF stays 0; next adc must add +1 only
; from its own carry-in (0): 4 + 1 + 0 = 5.
mov rax, 2
add rax, 2                    ; CF=0
adc rax, 0                    ; rax=4, CF must remain 0
mov rbx, 0
setc bl                       ; RBX = real CF after adc $0 (expect 0)
adc rax, 1                    ; rax = 4 + 1 + CF(0) = 5

; Case 2: CF=1 into `adc $0`.
; rcx = ~0 + 2 = 1 with CF=1; adc $0 -> rcx = 2, CF becomes 0;
; next adc: 2 + 1 + 0 = 3.
mov rcx, -1
add rcx, 2                    ; rcx=1, CF=1
adc rcx, 0                    ; rcx=2, CF=0 (1+0+... no wait: 1+0+1=2, carry-out 0)
mov rdx, 0
setc dl                       ; expect 0
adc rcx, 1                    ; rcx = 2 + 1 + 0 = 3

; Case 3: adc $0 that itself produces a carry-out.
; r8 = ~0, CF=1 in: ~0 + 0 + 1 = 0 with CF=1 out.
mov r8, -1
xor r9, r9
stc
adc r8, 0                     ; r8 = 0, CF=1
setc r9b                      ; expect 1
mov r8, 0
adc r8, 0                     ; r8 = 0 + 0 + 1 = 1, CF=0
; leave R8=1, R9=1

hlt
