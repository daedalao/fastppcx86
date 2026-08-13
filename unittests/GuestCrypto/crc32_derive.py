#!/usr/bin/env python3
# Derive and verify a vpmsumd-based inline CRC-32C (Castagnoli) sequence for
# the x86 crc32 instruction semantics (reflected, no init/final inversion),
# for SrcSize N in {1,2,4,8}. Everything is proven numerically against a
# bitwise reference over random inputs before any constant leaves this file.
import random

P = 0x11EDC6F41          # CRC-32C polynomial, normal form, degree 32
PREF = 0x82F63B78        # reflected form (for the reference impl)
random.seed(0xC0FFEE)

def crc_ref(crc, data, n):
    for i in range(n):
        crc ^= (data >> (8 * i)) & 0xFF
        for _ in range(8):
            crc = (crc >> 1) ^ (PREF if crc & 1 else 0)
    return crc & 0xFFFFFFFF

def clmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a <<= 1
        b >>= 1
    return r

def pdiv(num, den):
    """polynomial floor division over GF(2)"""
    q = 0
    dn = den.bit_length() - 1
    while num.bit_length() - 1 >= dn and num:
        sh = num.bit_length() - 1 - dn
        q ^= 1 << sh
        num ^= den << sh
    return q

def pmod(num, den):
    dn = den.bit_length() - 1
    while num.bit_length() - 1 >= dn and num:
        num ^= den << (num.bit_length() - 1 - dn)
    return num

def refl(v, n):
    r = 0
    for i in range(n):
        if (v >> i) & 1: r |= 1 << (n - 1 - i)
    return r

MU = pdiv(1 << 96, P)          # floor(x^96 / P), degree 64 (65 bits)
assert MU.bit_length() == 65
MU_LOW = MU ^ (1 << 64)        # mu' = mu - x^64  (64 bits)
MUP_R = refl(MU_LOW, 64)       # reflected mu'
P_R = refl(P, 33)              # reflected poly (33 bits)

def crc_zero_init(Q, N):
    """Model of the emitted sequence: crc_ref(0, Q, N) via two clmuls.
    q = floor(R(Q)*x^32 / P) = R(Q-as-A) + floor(A*mu'/x^64)  [mu = x^64+mu']
    reflected: q_r = Q ^ ((clmul(Q, MUP_R) >> 63) done as <<1-style pickoff)
    then crc' = bits [8N .. 8N+31] of clmul(q_r, P_R)."""
    bits = 8 * N
    t1 = clmul(Q, MUP_R)               # (bits + 64 - 1) wide
    # q_j = (A*mu')_{64+j}; reflected pickoff: q_r bit i = t1 bit (i-1),
    # i.e. q_r = (t1 << 1) restricted to 8N bits, then ^ Q for the x^64 term.
    q_r = ((t1 << 1) & ((1 << bits) - 1)) ^ Q
    t2 = clmul(q_r, P_R)               # (bits + 33 - 1) wide
    return (t2 >> bits) & 0xFFFFFFFF

def crc_insn(crc, val, N):
    """Full x86 crc32 semantics via the model sequence."""
    mask = (1 << (8 * N)) - 1
    Q = (crc ^ val) & mask if N < 8 else (crc ^ val) & ((1 << 64) - 1)
    out = crc_zero_init(Q, N)
    if N < 4:
        out ^= crc >> (8 * N)
    return out & 0xFFFFFFFF

# ---- verify the algebra ----
fails = 0
for N in (1, 2, 4, 8):
    for _ in range(20000):
        crc = random.getrandbits(32)
        val = random.getrandbits(8 * N)
        want = crc_ref(crc, val, N)
        got = crc_insn(crc, val, N)
        if want != got:
            print(f"MISMATCH N={N} crc={crc:08x} val={val:x} want={want:08x} got={got:08x}")
            fails += 1
            break
print("algebra:", "FAIL" if fails else "PASS (80k random vectors)")

# ---- now express as the exact vpmsumd sequence ----
# vpmsumd(A, B) = clmul(A.dw0,B.dw0) ^ clmul(A.dw1,B.dw1) on 64-bit lanes.
# Keep Q and constants in dw0 with dw1 zero -> plain 64x64 clmul, 127-bit
# result across the register (dw0 = high 63 bits, dw1 = low 64 bits) in the
# BE-integer register convention.
#
# Sequence per SrcSize N (GPR side does Q = (crc ^ val) & maskN):
#   mtvsrd  V, Q_gpr           # Q in dw0? mtvsrd targets dw0. dw1 undefined -> must clear.
#   t1   = vpmsumd(V(Q), C_MU)                 # C_MU = MUP_R
#   q_r  = ((t1 << 1) & mask8N) ^ Q            # one vector shift-left-1 + mask + xor
#   t2   = vpmsumd(q_r, C_P)                   # C_P = P_R
#   crc  = (t2 >> 8N) & 0xFFFFFFFF  [ ^ (crc >> 8N) for N<4, GPR side ]
#
# The <<1 / mask / >>8N are annoying on the vector side. Better: fold the <<1
# into the constant (MUP_R is 64 bits; MUP_R<<1 may be 65 -> check!) and do
# the >>8N extraction on the GPR side after mfvsrd.
print(f"MUP_R    = 0x{MUP_R:016x}  (top bit {'SET - cannot pre-shift' if MUP_R >> 63 else 'clear - CAN pre-shift'})")
if not (MUP_R >> 63):
    C_MU = MUP_R << 1
    def crc_zero_init_v2(Q, N):
        bits = 8 * N
        t1 = clmul(Q, C_MU)                      # <<1 absorbed
        q_r = (t1 & ((1 << bits) - 1)) ^ Q
        t2 = clmul(q_r, P_R)
        return (t2 >> bits) & 0xFFFFFFFF
    ok = all(crc_zero_init_v2(random.getrandbits(8*N), N) == crc_zero_init(random.getrandbits.__self__ and 0 or 0, 0) if False else True for N in ())
    fails2 = 0
    for N in (1, 2, 4, 8):
        for _ in range(20000):
            crc = random.getrandbits(32); val = random.getrandbits(8 * N)
            mask = (1 << (8 * N)) - 1
            Q = (crc ^ val) & mask
            out = crc_zero_init_v2(Q, N)
            if N < 4: out ^= crc >> (8 * N)
            if out != crc_ref(crc, val, N):
                fails2 += 1; break
    print("v2 (pre-shifted C_MU):", "FAIL" if fails2 else "PASS (80k)")
    print(f"C_MU (pool dw)  = 0x{C_MU:016x}")
    print(f"C_P  (pool dw)  = 0x{P_R:016x}")
    # masks needed per N: q_r mask = (1<<8N)-1 -> for N=8 it's all-ones (skip);
    # N<8 masking can be done on the GPR side? No - t1 must be masked BEFORE
    # the second vpmsumd. But: bounce through GPR! mfvsrd, mask+xor Q in GPR
    # (rldicl), mtvsrd back. GPR round trip is 2 direct moves - still fully
    # inline, no memory. Final: mfvsrd, srdi by 8N, mask 32.
    print("emission shape per op:")
    print("  GPR: q = crc ^ (val & maskN)            (rldicl/xor)")
    print("  mtvsrd VT1, q ; vpmsumd VT1, VT1, C_MU  (C_MU in dw0... NOTE dw layout)")
    print("  mfvsrd t, VT1(dw0?) -> pick correct dw; t &= mask8N; t ^= q")
    print("  mtvsrd VT1, t ; vpmsumd VT1, VT1, C_P")
    print("  mfvsrd d, VT1 ; d >>= 8N ; crc' = d & 0xFFFFFFFF [^ crc>>8N if N<4]")

# ---- exact emission-level model: dw-truncations and GPR ops as emitted ----
def crc_emit(crc, val, N):
    mask = (1 << (8 * N)) - 1
    q = (crc ^ val) & mask                    # GPR: xor (+rldicl for N<8)
    t1 = clmul(q, MUP_R)                      # vpmsumd, Q in dw0, C_MU dw0
    t1_lo = t1 & ((1 << 64) - 1)              # read LOW dw only (xxswapd+mfvsrd)
    s = (t1_lo << 1) & ((1 << 64) - 1)        # sldi 1
    if N < 8: s &= mask                       # rldicl
    qr = s ^ q                                # xor
    t2 = clmul(qr, P_R)                       # vpmsumd
    if N == 8:
        out = (t2 >> 64) & 0xFFFFFFFF         # dw0 read, mask32
    else:
        out = ((t2 & ((1 << 64) - 1)) >> (8 * N)) & 0xFFFFFFFF  # dw1, srdi, mask32
    if N < 4:
        out ^= crc >> (8 * N)                 # srdi+xor
    return out & 0xFFFFFFFF

f3 = 0
for N in (1, 2, 4, 8):
    for _ in range(50000):
        crc = random.getrandbits(32); val = random.getrandbits(8 * N)
        if crc_emit(crc, val, N) != crc_ref(crc, val, N):
            print(f"EMIT MISMATCH N={N}"); f3 += 1; break
print("emission model:", "FAIL" if f3 else "PASS (200k random vectors)")
print(f"pool C_MU dw0 = 0x{MUP_R:016x}, dw1 = 0")
print(f"pool C_P  dw0 = 0x{P_R:016x}, dw1 = 0")
