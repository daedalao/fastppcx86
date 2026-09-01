%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x0000000000000002",
    "RBX": "0x0000000000000004",
    "RCX": "0x0000000080000000",
    "RDX": "0x0000000080000000",
    "RBP": "0x0000000000000002",
    "RSI": "0x8000000000000000"
  }
}
%endif

; cvtss2si/cvtsd2si (no 'tt'): convert using the current (host) rounding
; mode -- MXCSR default is round-to-nearest-even, untouched by
; TestHarnessRunner. This is the OTHER half of CVTFPR_To_GPRImpl
; (HostRoundingMode=true), which on this backend maps to the independent
; Float_ToGPR_S op (fctiw/fctid honouring FPSCR.RN) rather than
; Float_ToGPR_ZS. Same dispatcher short-circuit, same sentinel contract,
; different backend op -- this file is the check that the short-circuit's
; HostRoundingMode ? Float_ToGPR_S : Float_ToGPR_ZS branch is wired to the
; right one and that Float_ToGPR_S's own (separately implemented) fixup is
; equally exact.
;
;   2.5f  = 0x40200000 -> ties-to-even -> 2
;   3.5f  = 0x40600000 -> ties-to-even -> 4
;   QNaN f32 = 0x7FC00000 -> sentinel
;   1e30f = 0x7149F2CA -> sentinel (overflow)
;   2.5 (double) = 0x4004000000000000 -> ties-to-even -> 2
;   9223372036854775808.0 (=2^63, double) = 0x43E0000000000000 -> sentinel

lea r15, [rel .data]

cvtss2si eax, [r15 + 0*4]    ; 2.5f -> 2
cvtss2si ebx, [r15 + 1*4]    ; 3.5f -> 4
cvtss2si ecx, [r15 + 2*4]    ; QNaN -> sentinel
cvtss2si edx, [r15 + 3*4]    ; 1e30f -> sentinel
cvtsd2si rbp, [r15 + 4*4]    ; 2.5 (double) -> 2
cvtsd2si rsi, [r15 + 6*4]    ; 2^63 (double) -> sentinel

hlt

align 16
.data:
dd 0x40200000  ; 0: 2.5f
dd 0x40600000  ; 1: 3.5f
dd 0x7FC00000  ; 2: QNaN f32
dd 0x7149F2CA  ; 3: 1e30f
dq 0x4004000000000000  ; 4 (offset 16): 2.5 double
dq 0x43E0000000000000  ; 6 (offset 24): 2^63 double
