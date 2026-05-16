%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x1",
    "RBX": "0x1",
    "R10": "0x1",
    "R11": "0x1",
    "R12": "0x1",
    "R13": "0x1",
    "R14": "0x1",
    "R15": "0x1"
  }
}
%endif

; Exercise the FoldBranch i8/i16 EQ/NEQ-vs-0 fold path. Each subtest sets a
; result register to 0 (failure default) then flips it to 1 only along the
; expected branch direction. RCX/RSI are scratch with deliberately dirty
; upper bits so the compare must respect operand-size, not full 64-bit width.

;-- 8-bit signed: cmp cl,0; jl <ok>  with cl = 0x80 (i.e. -128, must take) --
mov rax, 0
mov rcx, 0xFFFFFFFFFFFFFF80
cmp cl, 0
jl  .a_ok
jmp .done_a
.a_ok:
mov rax, 1
.done_a:

;-- 8-bit signed: cmp cl,0; jge <bad> with cl = 0x80 (must NOT take) --
mov rbx, 1
mov rcx, 0x123456789ABCDE80
cmp cl, 0
jge .b_bad
jmp .done_b
.b_bad:
mov rbx, 0
.done_b:

;-- 8-bit EQ: cmp cl,0; jne <bad> with cl = 0 (must NOT take, upper dirty) --
mov r10, 1
mov rcx, 0xDEADBEEFDEADBE00
cmp cl, 0
jne .c_bad
jmp .done_c
.c_bad:
mov r10, 0
.done_c:

;-- 8-bit EQ: cmp cl,0; je <bad> with cl = 1 (must NOT take) --
mov r11, 1
mov rcx, 0x0000000000000001
cmp cl, 0
je  .d_bad
jmp .done_d
.d_bad:
mov r11, 0
.done_d:

;-- 16-bit signed: cmp cx,0; jl <ok> with cx = 0x8000 (must take) --
mov r12, 0
mov rcx, 0xFFFFFFFF00008000
cmp cx, 0
jl  .e_ok
jmp .done_e
.e_ok:
mov r12, 1
.done_e:

;-- 16-bit signed: cmp cx,0; jge <bad> with cx = 0x8000 (must NOT take) --
mov r13, 1
mov rcx, 0x0000000080008000
cmp cx, 0
jge .f_bad
jmp .done_f
.f_bad:
mov r13, 0
.done_f:

;-- 16-bit unsigned: cmp cx,0; jb <bad> with cx = 0x8000 (must NOT take) --
mov r14, 1
mov rcx, 0xAAAAAAAAAAAA8000
cmp cx, 0
jb  .g_bad
jmp .done_g
.g_bad:
mov r14, 0
.done_g:

;-- 8-bit test+jz: test cl,cl; jz <ok> with cl = 0 (must take) --
mov r15, 0
mov rcx, 0x1122334455667700
test cl, cl
jz  .h_ok
jmp .done_h
.h_ok:
mov r15, 1
.done_h:

hlt
