;; Simpler versions of FXAM_Push* tests.
;; FXAM Zero classification: RCX = 0x4000 (the architecturally-correct value).
%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x6",
    "RBX": "0x0400",
    "RCX": "0x4000",
    "RDX": "0x4100"
  }
}
%endif

mov rdx, 0xe0000000

fninit
;; Before adding anything to the stack, lets examine it.
;; The result should be empty.
fxam
fwait

fnstsw ax 
and ax, 0x4500 ; should be 0x4100 for zero
mov edx, eax

fldz
fxam 
fwait 

fnstsw ax
and ax, 0x4500 ; 0x4000 for zero (TopValid && ExpZero && MantissaZero -> C3:C2:C0 = 100, mask 0x4500 -> bit 14 only)
mov ecx, eax

fld1
fxam
fwait

fnstsw ax
mov ebx, eax
and ebx, 0x4500 ; should be 0x0400 for normal

;; Top should be 6
;; right shift status word by 11 and and with 0x7.
shr eax, 11
and eax, 0x7


hlt
