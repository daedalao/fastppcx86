# seccomp functional test

`seccomp_bpf_filters.c` exercises FEX's cBPF seccomp interpreter
(`Source/Tools/LinuxEmulation/LinuxSyscalls/Seccomp/BPFInterpreter.cpp`) through the guest ABI: it installs filters with
`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` and checks the resulting actions.

Every case is written so a bare x86-64 kernel and FEX must produce the same output, which makes the host kernel the oracle. Run it
natively first, then under FEX, and diff.

Build (x86-64 host, e.g. booksmain):

    gcc -O2 -static -o seccomp_bpf_filters seccomp_bpf_filters.c

The prebuilt static binary is checked in so it can be run on a POWER host that has no x86 toolchain.

Run:

    ./seccomp_bpf_filters                          # native kernel
    FEX_NEEDSSECCOMP=1 FEXLoader ./seccomp_bpf_filters   # under FEX

Exit status is 0 when every case passed, 1 on any failure, 2 when seccomp is unavailable (under FEX that means `FEX_NEEDSSECCOMP=1`
was not set — the emulator returns `-EINVAL` for every seccomp operation when the feature is off).

`mod_and_x_source` reports SKIP on a stock kernel: `seccomp_check_filter()` has no `BPF_MOD` entry in its whitelist, so the kernel
refuses that program. FEX accepts it, matching the instruction set the previous ARM64 JIT accepted, so under FEX the case runs and must
pass.

This is not wired into ctest. The `unittests/FEXLinuxTests` harness would be the natural home, but it builds its guest binaries with an
x86 cross-toolchain that is not present on the POWER hosts where this needs to run.
