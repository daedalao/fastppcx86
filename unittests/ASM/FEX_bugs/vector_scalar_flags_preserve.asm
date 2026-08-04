%ifdef CONFIG
{
  "RegData": {
    "RDI": "0x81818181818181",
    "RSI": "0x1"
  }
}
%endif

; Scalar/vector SSE ops that write NO EFLAGS must not clobber pending flags.
; The PPC64LE JIT keeps packed NZCV in host CR0; VFCMPScalarInsert (CMPSS/SD),
; VFToIScalarInsert (ROUNDSS/SD) and the wide-shift ops used fcmpu/cmpld on
; cr0 as scratch, corrupting a preceding cmp's flags. Hard West wedged forever
; in a cmp -> cmpltss -> jne loop because the jne branched on garbage.
;
; Each case: cmp 3,5 sets CF=1 ZF=0 SF=1; run the op under test; harvest
; SF/ZF/CF via lahf. Expected 0x81 per case, accumulated bytewise in RDI.

%macro flagcase 1+
  mov rbx, 3
  cmp rbx, 5
  %1
  lahf
  movzx rdx, ah
  and rdx, 0xC1        ; keep SF | ZF | CF
  shl rdi, 8
  or rdi, rdx
%endmacro

mov rdi, 0

movss xmm0, [rel .f_one]
movss xmm1, [rel .f_two]
movsd xmm2, [rel .d_one]
movsd xmm3, [rel .d_two]
movapd xmm4, [rel .q_two]

flagcase cmpltss xmm0, xmm1
flagcase cmpneqss xmm0, xmm1
flagcase cmpltsd xmm2, xmm3
flagcase roundss xmm0, xmm1, 0
flagcase roundsd xmm2, xmm3, 0
flagcase psllw xmm5, xmm4
flagcase psraw xmm6, xmm4

; The Hard West shape: equality holds, cmpltss between cmp and jne must not
; steal the branch.
mov rsi, 0
mov rbx, 1
cmp rbx, 1
movss xmm0, [rel .f_one]
cmpltss xmm0, xmm1
jne .bad
mov rsi, 1
jmp .done
.bad:
mov rsi, 0xbad
.done:

hlt

align 16
.q_two:
dq 2, 0
.f_one:
dd 1.0
.f_two:
dd 2.0
.d_one:
dq 1.0
.d_two:
dq 2.0
