# GuestCrypto

Freestanding, self-checking guest-side conformance tests for the x86 crypto
instruction families that the PPC64LE JIT now lowers onto POWER8 hardware
instructions: **AES-NI**, **PCLMULQDQ**, **SHA-NI** and **SSE4.2 CRC32**.

Every program is a static, libc-free x86 binary (`_start` + raw syscalls) built
for **both i686 and x86_64**, so the same source covers the 32-bit paths that
Steam, DXVK-era game code and OpenSSL's `aesni-x86.pl` actually execute.  Each
program prints `PASS <name>` / `FAIL <name>` lines and **exits with the number
of failures**, so it drops straight into any harness.

## Why stress mode exists

The failure that motivated this suite was not a wrong lowering: a pinned
constant living in `vs15` was silently corrupted by an intervening host libc
call, because ELFv2 only guarantees the *FPR half* (doubleword 0) of
`vs14`-`vs31` — a scalar `lfd` restore leaves the vector half undefined.
It reproduced deterministically in Steam (81 of 2585 manifest filenames
decrypted wrong) while **every isolated test passed**: 122/122 ctests, FIPS
KATs in both bitnesses, hand-written interleave replicas.  Isolation tests are
structurally blind to cross-call register-state corruption, so this suite adds
a long-running **mixed workload** mode that interleaves crypto with the host
calls (syscalls, x87 F80 FABI helpers, bulk memcpy) that trigger it, and
verifies precomputed results on *every* iteration.

## Layout

| File | Covers |
| --- | --- |
| `crypto_common.h` | freestanding runtime (syscalls, printing, xorshift PRNG) plus **all scalar reference implementations**, transcribed from Intel SDM pseudocode with no intrinsics anywhere |
| `aes_test.c` | AESENC/AESENCLAST/AESDEC/AESDECLAST/AESIMC/AESKEYGENASSIST vs reference over 1024 random vectors; FIPS-197 AES-128/192/256 KATs (AES-NI key schedule → encrypt → equivalent-inverse decrypt); AESKEYGENASSIST with every RCON and the 0xff / 0x55 / 0xaa lane-shuffle patterns the three key schedules use; 256 random key/block round-trips; aliasing shapes (dst==src1==src2, 64-deep dst==src chain, in-place on **every** architectural XMM) |
| `pclmul_test.c` | all four selectors over 2048 random vectors; every single-bit × single-bit product (64×64 matrix); edge patterns (zero, all-ones, bit 0, bit 63, alternating); self-aliased and memory-operand forms; a GHASH-shaped schoolbook 128×128 multiply |
| `sha_test.c` | SHA1MSG1/MSG2/NEXTE, SHA1RNDS4 with **all four** function immediates, SHA256MSG1/MSG2/RNDS2 — each vs reference over 1024 random vectors; full SHA-1 and SHA-256 digests computed *with the instructions* over multi-block messages, checked against clean scalar SHA implementations and the NIST `abc` / 448-bit vectors; aliasing shapes incl. SHA256RNDS2 with the implicit XMM0 operand aliased and driven from every source register |
| `crc32_test.c` | CRC32 r/m8, r/m16, r/m32 (and r/m64 in 64-bit) vs a bitwise reflected CRC-32C reference; incremental chaining across a 4 KiB buffer with byte/dword/qword/mixed widths all required to agree; `0xE3069283` check value; memory-operand and high-byte (`%ch`) encodings |
| `interleave_test.c` | multiway register shapes: 2-way, the **steamclient.so 4-way CBC** loop (states xmm0-3, key reloaded into xmm4, chain through xmm7), the **OpenSSL `_aesni_decrypt6` 6-way** shape (states xmm2-7, keys ping-ponging xmm0/xmm1), an **8-way** all-registers-live pressure variant, and a 4-way encrypt interleave — each over 8 independent key/data sets, referenced against the plain-C inverse cipher |
| `stress_test.c` | the mixed-workload mode described above |
| `run.sh` | builds both bitnesses and runs them, locally or on op4k under FEX |

## Running

```sh
./run.sh                     # default: build + run on op4k under FEX
./run.sh local               # build + run natively (x86 host only)
STRESS_ITERS=1000000 ./run.sh
ONLY="stress_test" ./run.sh
```

Knobs: `STRESS_ITERS` (default 100000), `REMOTE` (default `op4k`),
`REMOTE_DIR` (default `/tmp/guestcrypto`), `FEX_BIN`, `FEX_ROOTFS`,
`BUILD_DIR`, `ONLY`, `CLANG`.  `run.sh` exits with the number of failing test
programs and filters FEX's `CPUINFO` chatter out of stderr.

Compile flags that matter:

* `-ffreestanding` is **required** — without it clang's `<immintrin.h>` chain
  pulls in `mm_malloc.h`, which includes the *host* (ppc64le) `stdlib.h`.
* `-fno-stack-protector` (no libc to provide `__stack_chk_fail`).
* `-nostdlib -static -fuse-ld=lld`, plus `-mstackrealign` for i686.
* `-maes -mpclmul -msha -msse4.2 -msse4.1`.

## Interpreting a stress failure

`stress_test` breaks out on the first divergence and prints

```
FAIL stress.sha1 first divergence at iteration 12345
```

The operation name says which primitive diverged; the iteration number times
it against the noise rotation (`it % 6` selects syscalls / x87 / bulk copy /
combinations), which narrows down which host-call class preceded the damage.
`stress.xmm_live_across_hostcall` failing is the strongest signal available:
it means guest XMM registers held live *across* a syscall or an x87 FABI
helper did not survive the call, i.e. the bug is in FEX's register
save/restore, not in a crypto lowering.

## Extending

* **New instruction**: add a scalar reference to `crypto_common.h` (SDM
  pseudocode, no intrinsics — the whole point is that the reference and the
  instruction share no code), then a randomized sweep plus aliasing shapes in
  the matching `*_test.c`.
* **New register shape**: add it to `interleave_test.c` next to the existing
  asm blocks; keep operands as `"r"` pointers and globals as `"m"` operands so
  the 32-bit build does not run out of GPRs.
* **New host-call class for stress**: add a `noise_*()` function and widen the
  `it % 6` rotation in `guest_main`.  Anything that makes FEX leave the JIT —
  new syscalls, signal delivery, SMC faults, thunked calls — is a good
  candidate.
* Keep new tests self-contained: no libc, no writes outside the test's own
  buffers, `exit(number_of_failures)`.
