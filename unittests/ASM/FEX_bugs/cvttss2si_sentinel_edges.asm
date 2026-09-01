%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x0000000000000003",
    "RBX": "0x00000000FFFFFFFD",
    "RCX": "0x0000000080000000",
    "RDX": "0x0000000080000000",
    "RBP": "0x0000000080000000",
    "RSI": "0x0000000080000000",
    "RDI": "0x0000000080000000",
    "R8":  "0x0000000080000000",
    "R9":  "0x0000000000000000",
    "R10": "0x0000000000000000",
    "R11": "0x8000000000000000",
    "R12": "0x000000000000007B"
  }
}
%endif

; cvttss2si (F3 0F 2C): truncate-toward-zero float32 -> signed integer, with
; x86's "integer indefinite" sentinel (0x80000000 / 0x8000000000000000) on
; NaN or out-of-range input (SDM Vol.1 4.8.3, CVTTSS2SI in Vol.2).
;
; This backend implements the sentinel in two places today
; (ALUOps.cpp DEF_OP(Float_ToGPR_ZS), and a redundant wrapper in
; OpcodeDispatcher/Vector.cpp CVTFPR_To_GPRImpl); this test is the
; differential check that removing the wrapper does not change any of these
; results. R8/RDI (huge finite overflow) are the load-bearing rows: POWER's
; own xscvdpsxws/xscvdpsxds saturate positive overflow to INT_MAX
; (0x7FFFFFFF), which is what the backend op's own xscmpudp-gated fixup
; corrects to the x86 sentinel -- if that fixup were ever lost, exactly
; these two rows would silently read back the wrong (but plausible-looking)
; integer.
;
; Values (computed with Python struct.pack, not hand-derived):
;   3.75f       = 0x40700000        -3.75f      = 0xC0700000
;   QNaN f32    = 0x7FC00000        SNaN f32    = 0x7F800001
;   +Inf f32    = 0x7F800000        -Inf f32    = 0xFF800000
;   1e30f       = 0x7149F2CA        -1e30f      = 0xF149F2CA
;   -0.0f       = 0x80000000        min denorm  = 0x00000001
;   123.0f      = 0x42F60000

lea r15, [rel .data]

cvttss2si eax,  [r15 + 0*4]   ; 3.75f      -> 3
cvttss2si ebx,  [r15 + 1*4]   ; -3.75f     -> -3 (0xFFFFFFFD, zero-extended)
cvttss2si ecx,  [r15 + 2*4]   ; QNaN       -> sentinel
cvttss2si edx,  [r15 + 3*4]   ; SNaN       -> sentinel
cvttss2si ebp,  [r15 + 4*4]   ; +Inf       -> sentinel
cvttss2si esi,  [r15 + 5*4]   ; -Inf       -> sentinel
cvttss2si edi,  [r15 + 6*4]   ; 1e30f      -> sentinel (positive-overflow case)
cvttss2si r8d,  [r15 + 7*4]   ; -1e30f     -> sentinel (negative-overflow case)
cvttss2si r9d,  [r15 + 8*4]   ; -0.0f      -> 0
cvttss2si r10d, [r15 + 9*4]   ; min denorm -> 0
cvttss2si r11,  [r15 + 6*4]   ; 1e30f, 64-bit dest -> sentinel (still overflows int64)
cvttss2si r12,  [r15 + 10*4]  ; 123.0f, 64-bit dest -> 123 (in-range sanity)

hlt

align 16
.data:
dd 0x40700000  ; 0: 3.75f
dd 0xC0700000  ; 1: -3.75f
dd 0x7FC00000  ; 2: QNaN
dd 0x7F800001  ; 3: SNaN
dd 0x7F800000  ; 4: +Inf
dd 0xFF800000  ; 5: -Inf
dd 0x7149F2CA  ; 6: 1e30f
dd 0xF149F2CA  ; 7: -1e30f
dd 0x80000000  ; 8: -0.0f
dd 0x00000001  ; 9: min denormal
dd 0x42F60000  ; 10: 123.0f
