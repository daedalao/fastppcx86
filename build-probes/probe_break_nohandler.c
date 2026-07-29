/*
 * probe_break_nohandler — same three opcodes as probe_jit_futex step 6, but with NO sigaction call.
 *
 * probe_jit_futex step 6 installs SIGILL/SIGTRAP/SIGSEGV handlers before firing the opcode. That
 * only exercises the "guest handler installed" path. Adversarial review of the Break-fix design
 * found that FEX does not install a host SIGTRAP thunk at all (SignalDelegator.cpp:1229 handles
 * SIGILL / SIGSEGV / SIGBUS / pause; SIGTRAP is missing). So the missing-handler path may behave
 * differently — and specifically, int3 may die on the host default disposition entirely bypassing
 * FEX, while ud2 (SIGILL) reaches the FEX host thunk before falling through to the guest default.
 *
 * Structure: argv[1] chooses the opcode. A shell wrapper invokes this once per opcode and records
 * the wait status, resulting signal, whether a core was dumped, and any output on stderr.
 *
 * BUILD:
 *   XT=$HOME/Development/fexrootfs/x-tools/x86_64-linux-gnu
 *   $XT/bin/x86_64-linux-gnu-gcc -O1 -g -o probe_break_nohandler probe_break_nohandler.c
 *
 * RUN (one opcode per invocation; process expected to die):
 *   FEX ./probe_break_nohandler int3 ; echo "exit=$? sig=$(($? - 128))"
 *   FEX ./probe_break_nohandler ud2  ; echo "exit=$? sig=$(($? - 128))"
 *   FEX ./probe_break_nohandler hlt  ; echo "exit=$? sig=$(($? - 128))"
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s int3|ud2|hlt\n", argv[0]);
        return 2;
    }
    fprintf(stderr, "about to execute %s (no signal handler installed)\n", argv[1]);
    fflush(stderr);

    if (strcmp(argv[1], "int3") == 0) {
        __asm__ volatile("int3");
    } else if (strcmp(argv[1], "ud2") == 0) {
        __asm__ volatile("ud2");
    } else if (strcmp(argv[1], "hlt") == 0) {
        __asm__ volatile("hlt");
    } else {
        fprintf(stderr, "unknown opcode: %s\n", argv[1]);
        return 2;
    }

    fprintf(stderr, "NOPED: instruction did not raise anything\n");
    return 0;
}
