%ifdef CONFIG
{
  "RegData": {
    "XMM0":  ["0x36A0000000000000", "0x8000000000000000"],
    "XMM1":  ["0xB80FFFFFC0000000", "0x3800000040000000"],
    "XMM2":  ["0x7FF82468A0000000", "0x7FF82468A0000000"],
    "XMM3":  ["0xFFF82468A0000000", "0x3FF0000000000000"],
    "XMM4":  ["0x8000000000000300", "0x0000000000000000"],
    "XMM5":  ["0x3F8000013F800000", "0x0000000000000000"],
    "XMM6":  ["0xFF8000007F800000", "0x0000000000000000"],
    "XMM7":  ["0x0000000100000000", "0x0000000000000000"],
    "XMM8":  ["0x7FC091A27FC091A2", "0x0000000000000000"],
    "XMM9":  ["0x36A0000000000000", "0xDEADBEEFCAFEF00D"],
    "XMM10": ["0xFFF82468A0000000", "0x1111111111111111"],
    "XMM11": ["0x8000000000000000", "0x2222222222222222"]
  }
}
%endif

; cvtps2pd / cvtpd2ps / cvtss2sd edge vectors: denormals in and out, NaN
; payload preservation and SNaN quieting, negative zero, and values that
; depend on correct round-to-nearest-even. The PPC64LE backend just moved
; these lowerings to xvcvspdp/xvcvdpsp -- VSX converts NaNs and denormals
; itself, so any mask/flush behavior difference from x86 shows up here.
;
; SDM references: CVTPS2PD/CVTSS2SD are exact (every float is representable
; as a double). NaN handling per SDM Vol.1 4.8.3.4/4.8.3.5 and the SSE
; conversion pages: a QNaN source converts to a QNaN with the fraction
; bits propagated (widened: fraction << 29; narrowed: fraction >> 29,
; i.e. the 23 most-significant fraction bits kept); an SNaN source is
; QUIETED: same fraction propagation, then the fraction MSB (quiet bit)
; is set. #IA from the SNaN is masked (MXCSR default) so only the value
; result is observable. MXCSR is default throughout: RN rounding, DAZ=0,
; FTZ=0 (TestHarnessRunner does not touch MXCSR).
;
; Derivations (single<->double bit patterns computed with a Python IEEE-754
; model; NaN cases derived by hand per the rule above):
;
; XMM0 cvtps2pd [0x00000001, 0x80000000, ...]:
;   0x00000001 = min denormal float = 2^-149. As a double: exponent field
;   1023-149 = 874 = 0x36A -> 0x36A0000000000000. Proves denormal INPUTS
;   are honored (DAZ off) and normalize exactly on widening.
;   0x80000000 = -0.0 -> 0x8000000000000000 (sign preserved).
; XMM1 cvtps2pd [0x807FFFFF, 0x00400001]:
;   0x807FFFFF = -max denormal = -(2^-126)(1-2^-23): exp 1023-127=896=0x380,
;   fraction 0xFFFFC0000000 -> 0xB80FFFFFC0000000.
;   0x00400001 = (2^22+1)*2^-149 = 2^-127*(1+2^-22) -> 0x3800000040000000.
; XMM2 cvtps2pd [QNaN 0x7FC12345, SNaN 0x7F812345]:
;   QNaN: fraction 0x412345 << 29 = 0x82468A0000000 -> 0x7FF82468A0000000.
;   SNaN: fraction 0x012345 << 29, then quiet bit 0x0008000000000000 set
;   -> 0x7FF82468A0000000. Deliberately the SAME result as the QNaN lane
;   (0x7F812345 quieted IS 0x7FC12345): both lanes equal iff payload
;   propagation AND quieting are both right.
; XMM3 cvtps2pd [SNaN 0xFF812345, 1.0]: negative SNaN keeps sign:
;   0xFFF82468A0000000; 1.0f -> 0x3FF0000000000000.
;
; XMM4 cvtpd2ps [0x3738000000000000, -0.0]:
;   0x3738000000000000 = 1.5 * 2^-140, below the normal float range ->
;   denormal float 0x00000300 (= 0x300 * 2^-149, exact, no rounding).
;   Proves denormal OUTPUTS are produced (FTZ off). -0.0 -> 0x80000000.
;   High qword of the destination must be zeroed by cvtpd2ps.
; XMM5 cvtpd2ps RN edges [0x3FF0000010000000, 0x3FF0000010000001]:
;   1+2^-24 is EXACTLY halfway between 1.0 and 1+2^-23: ties-to-even
;   rounds DOWN to 1.0 = 0x3F800000. Adding 1 ulp (double) breaks the tie
;   upward: 0x3F800001. Adjacent inputs, different outputs -- any rounding
;   mode confusion (RZ, round-half-up) fails one of the two lanes.
; XMM6 cvtpd2ps [1e39, -1e39] = [0x48078287F49C4A1D, 0xC8078287F49C4A1D]:
;   overflows float range -> +/-inf = 0x7F800000 / 0xFF800000 under RN.
; XMM7 cvtpd2ps [2^-150, 2^-150+2^-200] =
;   [0x3690000000000000, 0x3690000000000004]:
;   2^-150 is exactly halfway between 0 and the min denormal 2^-149:
;   ties-to-even -> +0.0. The +2^-200 sticky bit rounds up -> 0x00000001.
;   This is the denormal-boundary twin of the XMM5 tie test.
; XMM8 cvtpd2ps [QNaN 0x7FF8123456789ABC, SNaN 0x7FF0123456789ABC]:
;   fraction 0x8123456789ABC >> 29 = 0x4091A2 (quiet bit already set)
;   -> 0x7FC091A2. SNaN: fraction 0x0123456789ABC >> 29 = 0x0091A2, quiet
;   bit forced -> 0x7FC091A2. Same-result-in-both-lanes trick as XMM2.
;
; XMM9  cvtss2sd (scalar): src = min denormal float -> 0x36A0000000000000;
;   dest[127:64] = 0xDEADBEEFCAFEF00D must be PRESERVED (scalar merge
;   semantics -- xvcvspdp is a full-width op, so the lowering must insert,
;   not overwrite).
; XMM10 cvtss2sd: src = negative SNaN 0xFF812345 -> quieted
;   0xFFF82468A0000000, upper qword 0x1111111111111111 preserved.
; XMM11 cvtss2sd: src = -0.0f -> 0x8000000000000000, upper preserved.

lea rdx, [rel .data]

; cvtps2pd
movaps xmm0, [rdx + 16*0]
cvtps2pd xmm0, xmm0
movaps xmm1, [rdx + 16*1]
cvtps2pd xmm1, xmm1
movaps xmm2, [rdx + 16*2]
cvtps2pd xmm2, xmm2
movaps xmm3, [rdx + 16*3]
cvtps2pd xmm3, xmm3

; cvtpd2ps
movaps xmm4, [rdx + 16*4]
cvtpd2ps xmm4, xmm4
movaps xmm5, [rdx + 16*5]
cvtpd2ps xmm5, xmm5
movaps xmm6, [rdx + 16*6]
cvtpd2ps xmm6, xmm6
movaps xmm7, [rdx + 16*7]
cvtpd2ps xmm7, xmm7
movaps xmm8, [rdx + 16*8]
cvtpd2ps xmm8, xmm8

; cvtss2sd with upper-half preservation checks
movaps xmm9,  [rdx + 16*9]
cvtss2sd xmm9, [rdx + 16*0]        ; min denormal float
movaps xmm10, [rdx + 16*10]
movss xmm15, [rdx + 16*3]          ; negative SNaN 0xFF812345
cvtss2sd xmm10, xmm15
movaps xmm11, [rdx + 16*11]
movss xmm15, [rdx + 16*0 + 4]      ; -0.0f
cvtss2sd xmm11, xmm15

hlt

align 16
.data:
; 0: floats [min denorm, -0.0, pad, pad]
dd 0x00000001, 0x80000000, 0x00000000, 0x00000000
; 1: floats [-max denorm, small denorm-normal boundary]
dd 0x807FFFFF, 0x00400001, 0x00000000, 0x00000000
; 2: floats [QNaN payload, SNaN same payload]
dd 0x7FC12345, 0x7F812345, 0x00000000, 0x00000000
; 3: floats [negative SNaN, 1.0]
dd 0xFF812345, 0x3F800000, 0x00000000, 0x00000000
; 4: doubles [1.5*2^-140, -0.0]
dq 0x3738000000000000, 0x8000000000000000
; 5: doubles [1+2^-24 (tie), 1+2^-24+ulp]
dq 0x3FF0000010000000, 0x3FF0000010000001
; 6: doubles [1e39, -1e39] (float overflow)
dq 0x48078287F49C4A1D, 0xC8078287F49C4A1D
; 7: doubles [2^-150 (denormal tie), 2^-150+2^-200]
dq 0x3690000000000000, 0x3690000000000004
; 8: doubles [QNaN big payload, SNaN same payload]
dq 0x7FF8123456789ABC, 0x7FF0123456789ABC
; 9: cvtss2sd dest preset (upper qword must survive)
dq 0x123456789ABCDEF0, 0xDEADBEEFCAFEF00D
; 10: cvtss2sd dest preset
dq 0x0F0F0F0F0F0F0F0F, 0x1111111111111111
; 11: cvtss2sd dest preset
dq 0x5A5A5A5A5A5A5A5A, 0x2222222222222222
