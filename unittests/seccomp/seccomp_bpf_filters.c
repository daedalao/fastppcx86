// SPDX-License-Identifier: MIT
/*
 * Functional test for FEX's seccomp cBPF interpreter.
 *
 * Runs as an x86-64 guest under FEX with FEX_NEEDSSECCOMP=1, and equally on a bare x86-64 kernel, which is the point: every case below
 * is written so the real kernel and FEX must agree. Filters are permanent and stack, so each case runs in its own forked child and the
 * parent judges it by exit status.
 *
 * Build (on an x86-64 host):
 *   gcc -O2 -static -o seccomp_bpf_filters seccomp_bpf_filters.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Offsets into struct seccomp_data. The 64-bit members are loaded as two 32-bit words because cBPF only has word loads.
#define OFF_NR offsetof(struct seccomp_data, nr)
#define OFF_ARCH offsetof(struct seccomp_data, arch)
#define OFF_IP_LO offsetof(struct seccomp_data, instruction_pointer)
#define OFF_IP_HI (offsetof(struct seccomp_data, instruction_pointer) + 4)
#define OFF_ARG_LO(n) (offsetof(struct seccomp_data, args) + 8 * (n))
#define OFF_ARG_HI(n) (offsetof(struct seccomp_data, args) + 8 * (n) + 4)

// getpriority is the guinea pig throughout: it is never used by libc startup, so a filter can single it out without disturbing anything
// else the child needs to do (including printf).
#define TEST_SYSCALL __NR_getpriority

static int Failures = 0;

static int install_filter(struct sock_filter* filter, unsigned short len) {
  struct sock_fprog prog = {.len = len, .filter = filter};
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}

// Exit codes the children use. Anything else means the child died somewhere unexpected.
enum {
  CHILD_OK = 0,
  CHILD_FILTER_FAILED = 90,
  CHILD_UNEXPECTED = 91,
  // The instruction under test is outside what this kernel accepts. Reported, not counted as a failure, so the same binary is usable as
  // an oracle on a bare kernel and under FEX.
  CHILD_SKIP = 92,
};

/// Calls the guinea-pig syscall raw and reports errno, bypassing libc's wrapper so nothing rewrites the arguments.
static long test_syscall(uint64_t arg0, uint64_t arg1) {
  return syscall(TEST_SYSCALL, arg0, arg1);
}

/// Returns the errno the filter produced, or 0 if the syscall was allowed through. -1 means it succeeded in a way we can't read.
static int errno_from_test_syscall(uint64_t arg0, uint64_t arg1) {
  errno = 0;
  long Res = test_syscall(arg0, arg1);
  if (Res == -1) {
    return errno;
  }
  return 0;
}

typedef int (*ChildFunc)(void);

/// Forks, runs Body under its own filter, and checks how it ended.
/// ExpectedSignal of 0 means the child is expected to exit normally with CHILD_OK.
static void run_case(const char* Name, ChildFunc Body, int ExpectedSignal) {
  fflush(stdout);
  pid_t Pid = fork();
  if (Pid == 0) {
    // Filters require no_new_privs unless the caller is CAP_SYS_ADMIN.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(CHILD_FILTER_FAILED);
    }
    _exit(Body());
  }

  if (Pid < 0) {
    printf("FAIL %s: fork failed\n", Name);
    ++Failures;
    return;
  }

  int Status = 0;
  if (waitpid(Pid, &Status, 0) != Pid) {
    printf("FAIL %s: waitpid failed\n", Name);
    ++Failures;
    return;
  }

  if (ExpectedSignal) {
    if (WIFSIGNALED(Status) && WTERMSIG(Status) == ExpectedSignal) {
      printf("PASS %s\n", Name);
      return;
    }
    if (WIFEXITED(Status)) {
      printf("FAIL %s: expected signal %d, child exited with %d\n", Name, ExpectedSignal, WEXITSTATUS(Status));
    } else {
      printf("FAIL %s: expected signal %d, got signal %d\n", Name, ExpectedSignal, WTERMSIG(Status));
    }
    ++Failures;
    return;
  }

  if (WIFEXITED(Status) && WEXITSTATUS(Status) == CHILD_OK) {
    printf("PASS %s\n", Name);
    return;
  }

  if (WIFEXITED(Status) && WEXITSTATUS(Status) == CHILD_SKIP) {
    printf("SKIP %s: instruction not accepted here\n", Name);
    return;
  }

  if (WIFSIGNALED(Status)) {
    printf("FAIL %s: child died with signal %d\n", Name, WTERMSIG(Status));
  } else {
    printf("FAIL %s: child exited with %d\n", Name, WEXITSTATUS(Status));
  }
  ++Failures;
}

// ---------------------------------------------------------------------------
// Case: a filter that allows everything still lets syscalls through.
// ---------------------------------------------------------------------------
static int case_allow_all(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  if (getpid() <= 0) {
    return 1;
  }
  if (errno_from_test_syscall(0, 0) != 0) {
    return 2;
  }
  // prctl(PR_GET_SECCOMP) must report filter mode now.
  if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER) {
    return 3;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: SECCOMP_RET_ERRNO for one syscall, everything else allowed. Exercises the taken and the not-taken side of one jump.
// ---------------------------------------------------------------------------
static int case_errno_one_syscall(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 42),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  if (errno_from_test_syscall(0, 0) != 42) {
    return 1;
  }
  // Not-taken side: unrelated syscalls are untouched.
  if (getpid() <= 0) {
    return 2;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: SECCOMP_RET_KILL_PROCESS terminates the child with SIGSYS.
// ---------------------------------------------------------------------------
static int case_kill_process(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  // FEX implements the kill as kill(0, sig), which targets the whole process group rather than just this process. Isolate the child in
  // its own group so a kill can't take the test harness with it.
  setpgid(0, 0);

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  test_syscall(0, 0);
  // Must not be reached.
  return CHILD_UNEXPECTED;
}

// ---------------------------------------------------------------------------
// Case: BPF_LD|BPF_W|BPF_ABS at every interesting offset, including the high and low halves of a 64-bit argument, plus BPF_LD|BPF_W|BPF_LEN.
// ---------------------------------------------------------------------------
static int case_abs_offsets(void) {
  struct sock_filter filter[] = {
    /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 16),
    /* 2 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG_LO(0)),
    /* 3 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x56789ABC, 1, 0),
    /* 4 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 21),
    /* 5 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG_HI(0)),
    /* 6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x12340000, 1, 0),
    /* 7 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 22),
    /* 8 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG_LO(1)),
    /* 9 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x11, 1, 0),
    /*10 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 23),
    /*11 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
    /*12 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    /*13 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 24),
    // BPF_LEN is rewritten by the kernel into an immediate load of sizeof(struct seccomp_data).
    /*14 */ BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
    /*15 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sizeof(struct seccomp_data), 1, 0),
    /*16 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 25),
    /*17 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 26),
    /*18 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  int Res = errno_from_test_syscall(0x1234000056789ABCULL, 0x11);
  if (Res != 26) {
    // 21-25 identify which field mismatched.
    return Res;
  }
  if (getpid() <= 0) {
    return 1;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: scratch memory. BPF_ST must store the accumulator and BPF_STX the index register; the poison value catches an implementation
// that stores the wrong one.
// ---------------------------------------------------------------------------
static int case_scratch_memory(void) {
  struct sock_filter filter[] = {
    /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 12),
    // X = poison, so a BPF_ST that stores X instead of A produces a different errno.
    /* 2 */ BPF_STMT(BPF_LDX | BPF_W | BPF_IMM, 0xDEAD),
    /* 3 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG_LO(0)),
    /* 4 */ BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, 5),
    /* 5 */ BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, 3),
    /* 6 */ BPF_STMT(BPF_ST, 3),                     // M[3] = A
    /* 7 */ BPF_STMT(BPF_STX, 4),                    // M[4] = X = poison
    /* 8 */ BPF_STMT(BPF_LD | BPF_W | BPF_IMM, 0),   // clobber A
    /* 9 */ BPF_STMT(BPF_LDX | BPF_W | BPF_MEM, 3),  // X = M[3]
    /*10 */ BPF_STMT(BPF_MISC | BPF_TXA, 0),         // A = X
    /*11 */ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xFF),
    /*12 */ BPF_STMT(BPF_ALU | BPF_OR | BPF_K, SECCOMP_RET_ERRNO),
    /*13 */ BPF_STMT(BPF_RET | BPF_A, 0),
    /*14 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  // (7 + 5) * 3 == 36. A wrong-register store would yield 0xDEAD & 0xFF == 173.
  int Res = errno_from_test_syscall(7, 0);
  if (Res != 36) {
    return Res == 173 ? 60 : 61;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: scratch memory read back with BPF_LD|BPF_MEM and combined with BPF_ALU|BPF_OR|BPF_X, using the instruction pointer, which must
// be non-zero.
// ---------------------------------------------------------------------------
static int case_instruction_pointer(void) {
  struct sock_filter filter[] = {
    /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 8),
    /* 2 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_IP_LO),
    /* 3 */ BPF_STMT(BPF_ST, 0),
    /* 4 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_IP_HI),
    /* 5 */ BPF_STMT(BPF_LDX | BPF_W | BPF_MEM, 0),
    /* 6 */ BPF_STMT(BPF_ALU | BPF_OR | BPF_X, 0),
    /* 7 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
    /* 8 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 29),
    /* 9 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 28),
    /*10 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  int Res = errno_from_test_syscall(0, 0);
  if (Res == 28) {
    return 62; // instruction_pointer came through as zero.
  }
  if (Res != 29) {
    return 63;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: every ALU operation, chained so a wrong result cannot land on the expected value by accident.
// ---------------------------------------------------------------------------
static int case_alu_ops(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 11),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG_LO(0)), // 100
    BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, 7),            // 14
    BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, 3),            // 42
    BPF_STMT(BPF_ALU | BPF_SUB | BPF_K, 2),            // 40
    BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 2),            // 160
    BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 1),            // 80
    BPF_STMT(BPF_ALU | BPF_XOR | BPF_K, 0x0F),         // 95
    BPF_STMT(BPF_ALU | BPF_NEG, 0),                    // 0xFFFFFFA1, wrapping in 32 bits
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xFF),         // 161
    BPF_STMT(BPF_ALU | BPF_OR | BPF_K, SECCOMP_RET_ERRNO),
    BPF_STMT(BPF_RET | BPF_A, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  int Res = errno_from_test_syscall(100, 0);
  if (Res != 161) {
    return Res ? Res : 64;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: BPF_MOD and BPF_ALU with an X source. seccomp_check_filter's whitelist has no BPF_MOD entry, so a stock kernel refuses this
// program; FEX accepts it, as the JIT that preceded the interpreter did.
// ---------------------------------------------------------------------------
static int case_mod_and_x_source(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 6),
    BPF_STMT(BPF_LDX | BPF_W | BPF_IMM, 7),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG_LO(0)), // 100
    BPF_STMT(BPF_ALU | BPF_MOD | BPF_X, 0),            // 100 % 7 == 2
    BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),            // + 7 == 9
    BPF_STMT(BPF_ALU | BPF_OR | BPF_K, SECCOMP_RET_ERRNO),
    BPF_STMT(BPF_RET | BPF_A, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return errno == EINVAL ? CHILD_SKIP : CHILD_FILTER_FAILED;
  }

  int Res = errno_from_test_syscall(100, 0);
  if (Res != 9) {
    return Res ? Res : 65;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: every jump form, both taken and not taken, including BPF_JA skipping over a poisoned instruction.
// ---------------------------------------------------------------------------
static int case_jumps(void) {
  struct sock_filter filter[] = {
    /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 10),
    /* 2 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG_LO(0)),
    /* 3 */ BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 100, 0, 1),
    /* 4 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 11),
    /* 5 */ BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 100, 0, 1),
    /* 6 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 12),
    /* 7 */ BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 1, 0, 1),
    /* 8 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 13),
    /* 9 */ BPF_STMT(BPF_JMP | BPF_JA, 1),
    /*10 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 99), // Poison: the JA above must skip this.
    /*11 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 14),
    /*12 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  if (errno_from_test_syscall(200, 0) != 11) { // JGT taken
    return 1;
  }
  if (errno_from_test_syscall(100, 0) != 12) { // JGT not taken, JGE taken
    return 2;
  }
  if (errno_from_test_syscall(3, 0) != 13) { // JSET taken
    return 3;
  }
  if (errno_from_test_syscall(2, 0) != 14) { // all not taken, JA skips the poison
    return 4;
  }
  if (getpid() <= 0) { // outermost jf path
    return 5;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: filters stack, and the highest-precedence action across the chain wins even though the newest filter runs first.
// ---------------------------------------------------------------------------
static int case_filter_chain(void) {
  struct sock_filter allow_with_errno[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 77),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_filter allow_all[] = {
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  if (install_filter(allow_with_errno, ARRAY_SIZE(allow_with_errno)) != 0) {
    return CHILD_FILTER_FAILED;
  }
  if (install_filter(allow_all, ARRAY_SIZE(allow_all)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  // ERRNO outranks ALLOW, so the older filter still decides.
  if (errno_from_test_syscall(0, 0) != 77) {
    return 1;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: filters survive fork.
// ---------------------------------------------------------------------------
static int case_inherit_across_fork(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 55),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  pid_t Pid = fork();
  if (Pid == 0) {
    _exit(errno_from_test_syscall(0, 0) == 55 ? CHILD_OK : 1);
  }
  if (Pid < 0) {
    return 2;
  }

  int Status = 0;
  if (waitpid(Pid, &Status, 0) != Pid) {
    return 3;
  }
  if (!WIFEXITED(Status) || WEXITSTATUS(Status) != CHILD_OK) {
    return 4;
  }

  // The parent of the fork is still filtered too.
  if (errno_from_test_syscall(0, 0) != 55) {
    return 5;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: SECCOMP_RET_TRAP raises SIGSYS with the syscall details filled in.
// ---------------------------------------------------------------------------
static volatile int TrapSeen = 0;
static volatile int TrapErrno = 0;
static volatile int TrapSyscall = 0;
static volatile int TrapArch = 0;
static volatile int TrapCode = 0;

static void sigsys_handler(int Signal, siginfo_t* Info, void* Context) {
  TrapSeen = 1;
  TrapErrno = Info->si_errno;
  TrapSyscall = Info->si_syscall;
  TrapArch = Info->si_arch;
  TrapCode = Info->si_code;
}

static int case_trap(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TEST_SYSCALL, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | 66),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sigaction Action;
  memset(&Action, 0, sizeof(Action));
  Action.sa_sigaction = sigsys_handler;
  Action.sa_flags = SA_SIGINFO;
  if (sigaction(SIGSYS, &Action, NULL) != 0) {
    return CHILD_UNEXPECTED;
  }

  if (install_filter(filter, ARRAY_SIZE(filter)) != 0) {
    return CHILD_FILTER_FAILED;
  }

  test_syscall(0, 0);

  if (!TrapSeen) {
    return 1;
  }
  if (TrapErrno != 66) {
    return 2;
  }
  if (TrapSyscall != TEST_SYSCALL) {
    return 3;
  }
  if (TrapArch != AUDIT_ARCH_X86_64) {
    return 4;
  }
  if (TrapCode != SYS_SECCOMP) {
    return 5;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: programs the interpreter must refuse. Each has to come back -EINVAL rather than being installed.
// ---------------------------------------------------------------------------
static int case_rejected_programs(void) {
  // Jumping past the end of the program.
  struct sock_filter jump_out_of_range[] = {
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  // BPF_ABS past the end of struct seccomp_data.
  struct sock_filter abs_out_of_range[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, sizeof(struct seccomp_data)),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  // Misaligned BPF_ABS.
  struct sock_filter abs_unaligned[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  // Scratch slot past BPF_MEMWORDS.
  struct sock_filter mem_out_of_range[] = {
    BPF_STMT(BPF_ST, BPF_MEMWORDS),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };

  // Program that doesn't end in a RET.
  struct sock_filter no_trailing_ret[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
  };

  struct {
    const char* Name;
    struct sock_filter* Filter;
    unsigned short Len;
  } Cases[] = {
    {"jump_out_of_range", jump_out_of_range, ARRAY_SIZE(jump_out_of_range)},
    {"abs_out_of_range", abs_out_of_range, ARRAY_SIZE(abs_out_of_range)},
    {"abs_unaligned", abs_unaligned, ARRAY_SIZE(abs_unaligned)},
    {"mem_out_of_range", mem_out_of_range, ARRAY_SIZE(mem_out_of_range)},
    {"no_trailing_ret", no_trailing_ret, ARRAY_SIZE(no_trailing_ret)},
  };

  for (size_t i = 0; i < ARRAY_SIZE(Cases); ++i) {
    errno = 0;
    if (install_filter(Cases[i].Filter, Cases[i].Len) == 0) {
      // Installing succeeded, which means a bad program is now live. Report which one.
      return 10 + i;
    }
    if (errno != EINVAL) {
      return 20 + i;
    }
  }

  // Nothing was installed, so syscalls still work.
  if (getpid() <= 0) {
    return 1;
  }
  return CHILD_OK;
}

// ---------------------------------------------------------------------------
// Case: strict mode allows only read/write/exit/sigreturn.
// ---------------------------------------------------------------------------
static int case_strict_mode(void) {
  setpgid(0, 0);

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) != 0) {
    return CHILD_FILTER_FAILED;
  }

  // write() is permitted, so this reaches the pipe the parent isn't reading; that's fine, we only care that it isn't killed.
  const char Msg[] = "";
  syscall(__NR_write, -1, Msg, 0);

  // getpriority is not on the strict allow-list, so this must not return.
  test_syscall(0, 0);
  return CHILD_UNEXPECTED;
}

int main(void) {
  // Sanity: the emulator must have seccomp support enabled at all, otherwise every case below fails for the same uninteresting reason.
  {
    struct sock_filter filter[] = {
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    pid_t Pid = fork();
    if (Pid == 0) {
      if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        _exit(1);
      }
      _exit(install_filter(filter, ARRAY_SIZE(filter)) == 0 ? 0 : 1);
    }
    int Status = 0;
    waitpid(Pid, &Status, 0);
    if (!WIFEXITED(Status) || WEXITSTATUS(Status) != 0) {
      printf("seccomp is unavailable. Under FEX this needs FEX_NEEDSSECCOMP=1.\n");
      return 2;
    }
  }

  run_case("allow_all", case_allow_all, 0);
  run_case("errno_one_syscall", case_errno_one_syscall, 0);
  run_case("kill_process", case_kill_process, SIGSYS);
  run_case("abs_offsets", case_abs_offsets, 0);
  run_case("scratch_memory", case_scratch_memory, 0);
  run_case("instruction_pointer", case_instruction_pointer, 0);
  run_case("alu_ops", case_alu_ops, 0);
  run_case("mod_and_x_source", case_mod_and_x_source, 0);
  run_case("jumps", case_jumps, 0);
  run_case("filter_chain", case_filter_chain, 0);
  run_case("inherit_across_fork", case_inherit_across_fork, 0);
  run_case("trap", case_trap, 0);
  run_case("rejected_programs", case_rejected_programs, 0);
  run_case("strict_mode", case_strict_mode, SIGKILL);

  if (Failures) {
    printf("%d failure(s)\n", Failures);
    return 1;
  }

  printf("All cases passed.\n");
  return 0;
}
