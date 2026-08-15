%ifdef CONFIG
{
  "RegData": {
    "RAX": "0xB4B2C29"
  }
}
%endif

; 8/16-bit INC/DEC flag production on FlagM backends (SetSmallNZV gating test).
;
; On SupportsFlagM hosts the frontend lowers small INC/DEC through
; _SetSmallNZV (SETF8/SETF16 semantics: N = Src<sz-1>, Z = low-sz == 0,
; V = Src<sz> ^ Src<sz-1>, C preserved) plus an RmifNZCV V fixup. The PPC64LE
; backend stubbed SetSmallNZV as a nop — dead code until SupportsFlagM went on
; (5c91fdb86), after which every 8/16-bit INC/DEC left N/Z stale from the
; previous CR0 writer and Steam's CEF crashed within seconds of client start.
;
; Each leg establishes CF explicitly (stc/clc), runs one small INC or DEC, and
; captures SF/OF/ZF/CF via setcc (flag-preserving) before any folding
; arithmetic. CF capture doubles as the INC/DEC-preserves-CF check and pins
; the FlagM STC/CLC RmifNZCV path. Leg 7 uses BH for the high-8 partial
; register variant.
;
; Per-leg nibble = SF | OF<<1 | ZF<<2 | CF<<3, RAX = legs 1..7 concatenated
; (leg 1 in the top nibble):
;   1: inc al  0x7F  ->0x80  CF=1 : SF=1 OF=1 ZF=0 CF=1 -> 0xB
;   2: inc bl  0xFF  ->0x00  CF=0 : SF=0 OF=0 ZF=1 CF=0 -> 0x4
;   3: inc cx  0x7FFF->0x8000 CF=1: SF=1 OF=1 ZF=0 CF=1 -> 0xB
;   4: dec dl  0x80  ->0x7F  CF=0 : SF=0 OF=1 ZF=0 CF=0 -> 0x2
;   5: dec si  0x0001->0x0000 CF=1: SF=0 OF=0 ZF=1 CF=1 -> 0xC
;   6: dec di  0x8000->0x7FFF CF=0: SF=0 OF=1 ZF=0 CF=0 -> 0x2
;   7: dec bh  0x00  ->0xFF  CF=1 : SF=1 OF=0 ZF=0 CF=1 -> 0x9
; Expected RAX = 0xB4B2C29.

%macro CAPTURE 0
  sets r8b
  seto r9b
  setz r10b
  setc r11b
  movzx r12, r8b
  movzx r13, r9b
  shl r13, 1
  or r12, r13
  movzx r13, r10b
  shl r13, 2
  or r12, r13
  movzx r13, r11b
  shl r13, 3
  or r12, r13
  shl r15, 4
  or r15, r12
%endmacro

; r15 accumulates (leg 1 INCs AL, so RAX can't hold partial results while
; legs run — the low byte would alias the leg-1 operand).
xor r15, r15

; leg 1: 8-bit INC overflow into sign, CF=1 preserved
mov al, 0x7F
stc
inc al
CAPTURE

; leg 2: 8-bit INC wrap to zero, CF=0 preserved
mov bl, 0xFF
clc
inc bl
CAPTURE

; leg 3: 16-bit INC overflow into sign, CF=1 preserved
mov cx, 0x7FFF
stc
inc cx
CAPTURE

; leg 4: 8-bit DEC overflow out of sign, CF=0 preserved
mov dl, 0x80
clc
dec dl
CAPTURE

; leg 5: 16-bit DEC to zero, CF=1 preserved
mov si, 1
stc
dec si
CAPTURE

; leg 6: 16-bit DEC overflow out of sign, CF=0 preserved
mov di, 0x8000
clc
dec di
CAPTURE

; leg 7: high-8 DEC wrap through zero to negative, CF=1 preserved
mov bh, 0
stc
dec bh
CAPTURE

mov rax, r15

hlt
