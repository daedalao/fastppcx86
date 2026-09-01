%ifdef CONFIG
{
  "RegData": {
    "RAX": "0x000000007FFFFFFF",
    "RBX": "0x0000000080000000",
    "RCX": "0x0000000080000000",
    "RDX": "0x0000000080000000",
    "RBP": "0x7FFFFFFFFFFFFC00",
    "RSI": "0x8000000000000000",
    "RDI": "0x8000000000000000",
    "R8":  "0x0000000080000000",
    "R9":  "0x8000000000000000",
    "R10": "0x0000000000000000"
  }
}
%endif

; cvttsd2si (F2 0F 2C): truncate-toward-zero float64 -> signed integer,
; exercising the exact +/-2^31 and +/-2^63 boundaries where "in range" and
; "sentinel" give bit-identical answers for the wrong reason if the compare
; is off by one. Doubles have enough mantissa (52 bits) to represent every
; boundary value here exactly, so there is no rounding ambiguity in the test
; vectors themselves -- only in what the backend does with them.
;
; RAX/RCX (in-range boundary) and RBX/RDX (one step out of range) probe the
; same bit pattern (0x...80000000) from opposite sides of the i32 boundary:
; RAX must come from a genuine truncation (2^31-1 fits), RCX from the
; natural negative-saturation of xscvdpsxws (-2^31 fits exactly), while RBX
; and RDX must come from the sentinel fixup (2^31 and -2^31-1 do not fit).
; RBP/RSI/RDI repeat the same three-way split at the i64 boundary.
;
; Values (Python struct.pack):
;   2147483647.0          = 0x41DFFFFFFFC00000  (INT32_MAX, in range)
;   2147483648.0  (=2^31)  = 0x41E0000000000000  (out of range, +)
;   -2147483648.0 (=INT32_MIN) = 0xC1E0000000000000 (in range, boundary)
;   -2147483649.0          = 0xC1E0000000200000  (out of range, -)
;   9223372036854774784.0  = 0x43DFFFFFFFFFFFFF  (largest double < 2^63, in range)
;   9223372036854775808.0 (=2^63) = 0x43E0000000000000 (out of range, +)
;   -9223372036854775808.0 (=INT64_MIN) = 0xC3E0000000000000 (in range, boundary)
;   NaN f64                = 0x7FF8000000000000
;   -0.0                    = 0x8000000000000000

lea r15, [rel .data]

cvttsd2si eax,  [r15 + 0*8]   ; 2147483647.0           -> 0x7FFFFFFF (in range)
cvttsd2si ebx,  [r15 + 1*8]   ; 2147483648.0            -> sentinel
cvttsd2si ecx,  [r15 + 2*8]   ; -2147483648.0           -> 0x80000000 (in range, natural)
cvttsd2si edx,  [r15 + 3*8]   ; -2147483649.0           -> sentinel
cvttsd2si rbp,  [r15 + 4*8]   ; 9223372036854774784.0   -> in range
cvttsd2si rsi,  [r15 + 5*8]   ; 9223372036854775808.0   -> sentinel
cvttsd2si rdi,  [r15 + 6*8]   ; -9223372036854775808.0  -> in range, natural
cvttsd2si r8d,  [r15 + 7*8]   ; NaN, 32-bit dest        -> sentinel
cvttsd2si r9,   [r15 + 7*8]   ; NaN, 64-bit dest        -> sentinel
cvttsd2si r10d, [r15 + 8*8]   ; -0.0, 32-bit dest       -> 0

hlt

align 16
.data:
dq 0x41DFFFFFFFC00000  ; 0: 2147483647.0
dq 0x41E0000000000000  ; 1: 2147483648.0
dq 0xC1E0000000000000  ; 2: -2147483648.0
dq 0xC1E0000000200000  ; 3: -2147483649.0
dq 0x43DFFFFFFFFFFFFF  ; 4: 9223372036854774784.0
dq 0x43E0000000000000  ; 5: 9223372036854775808.0
dq 0xC3E0000000000000  ; 6: -9223372036854775808.0
dq 0x7FF8000000000000  ; 7: NaN
dq 0x8000000000000000  ; 8: -0.0
