// Settles the PowerPC kernel termios layout by observation, not by reading
// headers or reasoning about glibc.
//
// Native ppc64le. No FEX involved. Build:
//   gcc -O0 -o probe_termios_layout probe_termios_layout.c
// Run from a real terminal, and also under a pty:
//   ./probe_termios_layout
//   script -qc ./probe_termios_layout /dev/null
//
// Method: poison an oversized buffer with 0xAA, issue a RAW ioctl (bypassing
// glibc's tcgetattr, which silently translates between the kernel struct and
// glibc's), then report exactly which byte offsets the kernel modified. The
// highest modified offset is the true size the kernel writes; the offset map
// tells us whether c_cc precedes c_line or follows it.

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <errno.h>

#define BUFSZ 128
#define POISON 0xAA

// PowerPC encodes a size into the ioctl number, and the size comes from
// whichever `struct termios` is visible where the macro expands. Both
// candidates are spelled out numerically so neither depends on header scope.
#define TCGETS_SZ44 0x402c7413u // _IOR('t',19,<44-byte kernel struct>)
#define TCGETS_SZ60 0x403c7413u // _IOR('t',19,<60-byte glibc struct>)

static void Probe(const char* Name, unsigned long Cmd, int fd) {
  unsigned char Buf[BUFSZ];
  memset(Buf, POISON, sizeof(Buf));

  errno = 0;
  long rc = syscall(SYS_ioctl, fd, Cmd, Buf);

  printf("  %-12s cmd=0x%08lx rc=%ld", Name, Cmd, rc);
  if (rc < 0) {
    printf("  errno=%d (%s)\n", errno, strerror(errno));
    return;
  }

  int Highest = -1, Count = 0;
  for (int i = 0; i < BUFSZ; ++i) {
    if (Buf[i] != POISON) {
      Highest = i;
      ++Count;
    }
  }
  printf("  bytes_written_upto=%d (touched=%d)\n", Highest + 1, Count);

  printf("    raw[0..63]:");
  for (int i = 0; i < 64; ++i) {
    if (i % 16 == 0) {
      printf("\n      +%02d: ", i);
    }
    printf("%02x ", Buf[i]);
  }
  printf("\n");

  // The decisive read. c_cc[0] is VINTR and on any normal terminal is 0x03
  // (^C); c_line is almost always 0. If offset 16 holds 0x03 then c_cc starts
  // at 16 and c_line follows it -- the kernel layout. If offset 16 holds 0x00
  // and offset 17 holds 0x03, c_line comes first -- the glibc layout.
  printf("    offset16=0x%02x offset17=0x%02x  -> ", Buf[16], Buf[17]);
  if (Buf[16] == 0x03) {
    printf("c_cc FIRST (44-byte kernel layout)\n");
  } else if (Buf[17] == 0x03) {
    printf("c_line FIRST (60-byte glibc layout)\n");
  } else {
    printf("INCONCLUSIVE -- is VINTR remapped? check stty -a intr\n");
  }
}

int main(void) {
  printf("sizeof(glibc struct termios) = %zu\n", sizeof(struct termios));
  printf("NCCS (glibc)                 = %d\n", NCCS);
  printf("TCGETS as compiled here      = 0x%08lx\n", (unsigned long)TCGETS);
#ifdef _HAVE_STRUCT_TERMIOS_C_ISPEED
  printf("glibc struct has c_ispeed    = yes\n");
#endif
  // Does glibc's struct even have c_line on this arch? If this fails to
  // compile, that alone refutes "c_line before c_cc on PowerPC glibc".
  printf("offsetof-ish check: &c_cc - &termios = %zu\n", (size_t)((char*)&((struct termios*)0)->c_cc - (char*)0));

  int fd = -1;
  for (int i = 0; i <= 2; ++i) {
    if (isatty(i)) {
      fd = i;
      break;
    }
  }
  if (fd < 0) {
    printf("\nNO TTY on fd 0/1/2 -- run under `script -qc ... /dev/null`.\n");
    printf("Without a real terminal this probe proves nothing.\n");
    return 2;
  }
  printf("\nusing tty fd=%d\n\n", fd);

  Probe("size=44", TCGETS_SZ44, fd);
  printf("\n");
  Probe("size=60", TCGETS_SZ60, fd);
  return 0;
}
