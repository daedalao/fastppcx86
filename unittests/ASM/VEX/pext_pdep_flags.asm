%ifdef CONFIG
{
  "RegData": {
      "RDX": "0x57",
      "R10": "0x12003400",
      "RBX": "0x1",
      "RCX": "0x1",
      "R8":  "0x0",
      "R9":  "0x1"
  },
  "HostFeatures": ["BMI2"]
}
%endif

; BMI2 PEXT/PDEP affect no flags (Intel SDM "Flags Affected: None").
; Regression test for the PPC64LE JIT's CR0 stash: the PExt lowering used to
; overwrite its own CR0 (packed NZCV) snapshot with its output-position
; counter, so any cmp;pext;setcc saw cleared SF/ZF.

xor rbx, rbx
xor rcx, rcx
xor r8, r8
xor r9, r9

; CF=1, SF=1, ZF=0 must survive a nonzero-mask PEXT
mov rax, 1
cmp rax, 2
mov rdx, 0x12345678
mov rsi, 0xF0F0
pext rdx, rdx, rsi
setb bl                 ; CF -> 1
sets cl                 ; SF -> 1
setz r8b                ; ZF -> 0

; ZF=1 must survive a nonzero-mask PDEP
mov rax, 5
cmp rax, 5
mov r10, 0x1234
mov rsi, 0xFF00FF00
pdep r10, r10, rsi
setz r9b                ; ZF -> 1

hlt
