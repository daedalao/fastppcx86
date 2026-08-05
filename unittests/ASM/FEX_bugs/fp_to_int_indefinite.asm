%ifdef CONFIG
{
  "RegData": {
    "XMM1": ["0xFFFFFFFE80000000", "0x8000000000000001"],
    "XMM2": ["0xFFFFFFFF80000000", "0x8000000000000001"],
    "XMM4": ["0x0000000380000000", "0xFFFFFFFFFFFFFFFD"],
    "XMM5": ["0x0000000280000000", "0x00000000FFFFFFFE"],
    "XMM7": ["0xFFFFFFFD80000000", "0x0000000000000000"],
    "XMM8": ["0xFFFFFFFE80000000", "0x0000000000000000"],
    "XMM10": ["0x80000000FFFFFFFD", "0x0000000000000000"],
    "XMM11": ["0x8000000080000000", "0x0000000000000000"],
    "XMM12": ["0x8000000080000000", "0x0000000000000000"],
    "XMM13": ["0x0000000280000000", "0x0000000000000000"],
    "XMM14": ["0x000000027FFFFFFF", "0x0000000000000000"]
  },
  "MemoryRegions": {
    "0xe0000000": "4096"
  }
}
%endif

; Packed float/double -> int32 conversion, including the out-of-range cases
; that must produce x86's "integer indefinite" sentinel 0x80000000.
;
; The rest of the ASM suite never feeds these instructions an out-of-range
; operand, so the whole overflow-sentinel path in the PPC64LE backend's
; Vector_FToS / Vector_FToZS / Vector_FToISized / Vector_F64ToI32 lowerings --
; the compare against the FP bound and the xxsel that substitutes INT_MIN --
; went unexercised: deliberately corrupting the INT_MIN constant failed no
; test at all before this file existed.
;
; Overflowing lanes are placed in BOTH 64-bit halves, and in both the first
; and second lane of the f64 conversions, so a constant whose two doublewords
; disagree (or a swapped pack order) cannot pass by feeding the right bytes to
; the one lane that happens to be checked. NaN is included but is not a
; sentinel test: POWER's convert already yields INT_MIN for NaN without the
; xxsel, so it only guards against the mask wrongly firing.
;
; Rounding is left at the default (round-to-nearest-even), so the cvt* and
; cvtt* forms disagree on every .7 input and are distinguishable.

mov rdx, 0xe0000000

; xmm0 = [3e30f, -1.5f, 1.0f, 3e30f] -- overflow in lane 0 and lane 3
mov rax, 0xbfc0000072177617
mov [rdx + 0], rax
mov rax, 0x721776173f800000
mov [rdx + 8], rax
movaps xmm0, [rdx]

cvtps2dq  xmm1, xmm0      ; nearest-even: -1.5 -> -2
cvttps2dq xmm2, xmm0      ; truncate:     -1.5 -> -1

; xmm3 = [NaN, 2.7f, -2.7f, -0.9f]
mov rax, 0x402ccccd7fc00000
mov [rdx + 16], rax
mov rax, 0xbf666666c02ccccd
mov [rdx + 24], rax
movaps xmm3, [rdx + 16]

cvtps2dq  xmm4, xmm3      ; 2.7 -> 3, -2.7 -> -3, -0.9 -> -1
cvttps2dq xmm5, xmm3      ; 2.7 -> 2, -2.7 -> -2, -0.9 ->  0

; xmm6 = [1e30, -2.7] as doubles -- overflow in lane 0
mov rax, 0x46293e5939a08cea
mov [rdx + 32], rax
mov rax, 0xc00599999999999a
mov [rdx + 40], rax
movaps xmm6, [rdx + 32]

cvtpd2dq  xmm7, xmm6      ; -2.7 -> -3, result packed to the low quadword
cvttpd2dq xmm8, xmm6      ; -2.7 -> -2

; xmm9 = [-2.7, 1e30] -- same values, overflow moved to lane 1
mov rax, 0xc00599999999999a
mov [rdx + 48], rax
mov rax, 0x46293e5939a08cea
mov [rdx + 56], rax
movaps xmm9, [rdx + 48]

cvtpd2dq xmm10, xmm9

; --- [2^31, 2^63) range: the bound-constant regression (fixed 2026-08-05) ---
; The sentinel compare used 2^63 as the overflow bound, so f64 values in
; [2^31, 2^63) kept POWER's INT_MAX saturation instead of x86's 0x80000000.
; 5e9 sits squarely in that window; -5e9 checks the negative side (correct
; via POWER's own INT_MIN saturation, no mask involved).
mov rax, 0x41f2a05f20000000   ; 5e9
mov [rdx + 64], rax
mov rax, 0xc1f2a05f20000000   ; -5e9
mov [rdx + 72], rax
movaps xmm6, [rdx + 64]

cvtpd2dq  xmm11, xmm6         ; both lanes -> 0x80000000
cvttpd2dq xmm12, xmm6         ; both lanes -> 0x80000000

; Rounds-up-to-2^31 edge: 2147483647.7 truncates to 0x7FFFFFFF (valid) but
; rounds (nearest) to exactly 2^31 -> indefinite. Distinguishes comparing
; the ROUNDED value from comparing the raw source. 2.5 -> 2 both ways
; (banker's rounding ties to even).
mov rax, 0x41dfffffffeccccd   ; 2147483647.7
mov [rdx + 80], rax
mov rax, 0x4004000000000000   ; 2.5
mov [rdx + 88], rax
movaps xmm6, [rdx + 80]

cvtpd2dq  xmm13, xmm6         ; [0x80000000, 2]
cvttpd2dq xmm14, xmm6         ; [0x7FFFFFFF, 2]

hlt
