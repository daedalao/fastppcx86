%ifdef CONFIG
{
  "RegData": {
    "XMM1": ["0x8000000080000000", "0x0000000180000000"],
    "XMM2": ["0x8000000080000000", "0x0000000280000000"]
  }
}
%endif

; FEX-Emu PPC64LE: CVTTPS2DQ / CVTPS2DQ must produce the x86 "integer
; indefinite" value (INT_MIN = 0x80000000) for any non-representable input:
; a NaN, a positive overflow, or a negative overflow all map to 0x80000000.
; A normal, in-range value converts as usual (truncate for CVTTPS2DQ,
; round-to-nearest-even for CVTPS2DQ under the default MXCSR).
;
; The PPC64LE JIT's VMX vctsxs primitive maps NaN -> 0 rather than INT_MIN;
; this test pins down the end-to-end x86 semantics for the four boundary lanes.
;
; Lane layout (LE element 0 = lowest dword):
;   lane0 = NaN (0x7FC00000)
;   lane1 = +overflow (1e30)
;   lane2 = -overflow (-1e30)
;   lane3 = 1.5 (normal)
;
; Expected (both truncate and round):
;   NaN, +overflow, -overflow -> 0x80000000
;   1.5 -> 0x1 (truncate)  /  0x2 (round-to-nearest-even)
; XMM RegData packs [low64 = (lane1<<32)|lane0, high64 = (lane3<<32)|lane2].

lea rdx, [rel .input]
movaps xmm0, [rdx]

cvttps2dq xmm1, xmm0        ; truncate
cvtps2dq  xmm2, xmm0        ; round (MXCSR default = nearest-even)

hlt

align 16
.input:
dd 0x7FC00000       ; quiet NaN (raw bit pattern)
dd 1.0e30           ; +overflow for int32
dd -1.0e30          ; -overflow for int32
dd 1.5              ; normal in-range value
