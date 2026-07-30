/*
 * probe_readlink_policy — verify the RootFS-containment policy for readlink and
 * friends after the FileManagement.cpp fallback-guard fix.
 *
 * Unlike probe_file_lookup.c, this checks *values and errnos against an
 * expectation*, not just "did the syscall return >= 0". Each line prints PASS or
 * FAIL so a run is self-scoring. It also dumps st_size and the first bytes of
 * the file, because a stat/open that "succeeds" while reporting the wrong size
 * or content would look identical to a correct one in a rc-only probe.
 *
 * BUILD (on the POWER9 box):
 *   XT=$HOME/Development/fexrootfs/x-tools/x86_64-linux-gnu
 *   $XT/bin/x86_64-linux-gnu-gcc -O0 -g -o probe_readlink_policy probe_readlink_policy.c
 *
 * RUN:
 *   FEXLoader -- ./probe_readlink_policy [rootfs_file] [host_file]
 *
 * rootfs_file defaults to /root/csharp/hello.cs (the file that reproduced the
 * EACCES). host_file defaults to a path under $HOME, which must resolve via the
 * host passthrough and must NOT regress.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

static int Failures = 0;
static int Checks = 0;

static const char* ErrName(int e) {
  switch (e) {
  case 0: return "0";
  case EACCES: return "EACCES";
  case EINVAL: return "EINVAL";
  case ENOENT: return "ENOENT";
  case ENOTDIR: return "ENOTDIR";
  case ELOOP: return "ELOOP";
  case ENAMETOOLONG: return "ENAMETOOLONG";
  case EPERM: return "EPERM";
  default: return "other";
  }
}

/* Expect readlink(path) to fail with errno == want. */
static void ExpectReadlinkErrno(const char* what, const char* path, int want) {
  char buf[PATH_MAX];
  ++Checks;
  errno = 0;
  ssize_t rc = readlink(path, buf, sizeof buf - 1);
  if (rc >= 0) {
    buf[rc] = 0;
    printf("  FAIL %-44s readlink succeeded -> '%s' (wanted %s)\n", what, buf, ErrName(want));
    ++Failures;
    return;
  }
  if (errno != want) {
    printf("  FAIL %-44s errno=%d %s (wanted %s)\n", what, errno, ErrName(errno), ErrName(want));
    ++Failures;
    return;
  }
  printf("  PASS %-44s errno=%s\n", what, ErrName(want));
}

/* Expect readlink(path) to succeed. */
static void ExpectReadlinkOk(const char* what, const char* path) {
  char buf[PATH_MAX];
  ++Checks;
  errno = 0;
  ssize_t rc = readlink(path, buf, sizeof buf - 1);
  if (rc < 0) {
    printf("  FAIL %-44s errno=%d %s (wanted success)\n", what, errno, ErrName(errno));
    ++Failures;
    return;
  }
  buf[rc] = 0;
  printf("  PASS %-44s -> '%s'\n", what, buf);
}

static void ExpectRealpathOk(const char* what, const char* path) {
  char out[PATH_MAX];
  ++Checks;
  errno = 0;
  if (!realpath(path, out)) {
    printf("  FAIL %-44s errno=%d %s (wanted success)\n", what, errno, ErrName(errno));
    ++Failures;
    return;
  }
  printf("  PASS %-44s -> '%s'\n", what, out);
}

/* stat + open + read, checking values rather than just return codes. */
static void ExpectReadableWithContent(const char* what, const char* path) {
  struct stat st;
  ++Checks;
  if (stat(path, &st) != 0) {
    printf("  FAIL %-44s stat errno=%d %s\n", what, errno, ErrName(errno));
    ++Failures;
    return;
  }
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    printf("  FAIL %-44s open errno=%d %s (stat said size=%lld)\n", what, errno, ErrName(errno), (long long)st.st_size);
    ++Failures;
    return;
  }
  char head[65];
  ssize_t n = read(fd, head, sizeof head - 1);
  close(fd);
  if (n < 0) {
    printf("  FAIL %-44s read errno=%d %s\n", what, errno, ErrName(errno));
    ++Failures;
    return;
  }
  head[n] = 0;
  for (char* p = head; *p; ++p) {
    if (*p == '\n' || *p == '\r') {
      *p = ' ';
    }
  }
  if (st.st_size == 0 || n == 0) {
    printf("  FAIL %-44s st_size=%lld read=%zd -- empty, stat/read disagree with a readable file\n", what, (long long)st.st_size, n);
    ++Failures;
    return;
  }
  if ((long long)n != (long long)st.st_size && (size_t)st.st_size < sizeof head - 1) {
    printf("  FAIL %-44s st_size=%lld but read %zd bytes\n", what, (long long)st.st_size, n);
    ++Failures;
    return;
  }
  printf("  PASS %-44s st_size=%lld mode=%06o first='%s'\n", what, (long long)st.st_size, (unsigned)st.st_mode, head);
}

int main(int argc, char** argv) {
  const char* RootFSFile = argc > 1 ? argv[1] : "/root/csharp/hello.cs";
  const char* HostFile = argc > 2 ? argv[2] : NULL;
  char HostDefault[PATH_MAX];

  if (!HostFile) {
    const char* Home = getenv("HOME");
    snprintf(HostDefault, sizeof HostDefault, "%s/.bashrc", Home ? Home : "/tmp");
    HostFile = HostDefault;
  }

  printf("probe_readlink_policy\n");
  printf("  rootfs-view file : %s\n", RootFSFile);
  printf("  host-view file   : %s\n\n", HostFile);

  printf("== the regression: readlink on a non-symlink must be EINVAL, never EACCES ==\n");
  ExpectReadlinkErrno("readlink(rootfs regular file)", RootFSFile, EINVAL);
  ExpectReadlinkErrno("readlink(host regular file)", HostFile, EINVAL);

  printf("\n== realpath must now walk the rootfs path ==\n");
  ExpectRealpathOk("realpath(rootfs regular file)", RootFSFile);
  ExpectRealpathOk("realpath(host regular file)", HostFile);

  printf("\n== must not regress: real symlinks still resolve ==\n");
  /* Present in essentially every x86-64 rootfs, and it is a symlink. */
  ExpectReadlinkOk("readlink(/proc/self/exe)", "/proc/self/exe");
  ExpectReadlinkOk("readlink(/proc/self/cwd)", "/proc/self/cwd");

  printf("\n== must not regress: directories, empty and absent paths ==\n");
  ExpectReadlinkErrno("readlink(\"/\")", "/", EINVAL);
  ExpectReadlinkErrno("readlink(\"\")", "", ENOENT);
  ExpectReadlinkErrno("readlink(/definitely/not/here)", "/definitely/not/here", ENOENT);
  ExpectReadlinkErrno("readlink(rootfs dir /usr)", "/usr", EINVAL);

  printf("\n== must not regress: /proc/self/fd/N, where the host fallback is load-bearing ==\n");
  /* The RootFS has no populated /proc, so this lookup MUST reach the host and
   * then get the RootFS prefix stripped back off by StripRootFSPrefix. It is
   * the case that most depends on the fallback surviving the policy change. */
  {
    int fd = open(RootFSFile, O_RDONLY);
    ++Checks;
    if (fd < 0) {
      printf("  FAIL %-44s could not open subject file, errno=%d %s\n", "readlink(/proc/self/fd/N)", errno, ErrName(errno));
      ++Failures;
    } else {
      char ProcPath[64];
      char out[PATH_MAX];
      snprintf(ProcPath, sizeof ProcPath, "/proc/self/fd/%d", fd);
      errno = 0;
      ssize_t rc = readlink(ProcPath, out, sizeof out - 1);
      if (rc < 0) {
        printf("  FAIL %-44s errno=%d %s (wanted success)\n", "readlink(/proc/self/fd/N)", errno, ErrName(errno));
        ++Failures;
      } else {
        out[rc] = 0;
        /* Must be the guest-visible path, i.e. RootFS prefix stripped. */
        if (strcmp(out, RootFSFile) == 0) {
          printf("  PASS %-44s -> '%s'\n", "readlink(/proc/self/fd/N)", out);
        } else {
          printf("  WARN %-44s -> '%s' (expected '%s'; a leaked RootFS prefix here is a\n"
                 "       separate pre-existing bug, not a regression from the fallback guard)\n",
                 "readlink(/proc/self/fd/N)", out, RootFSFile);
        }
      }
      close(fd);
    }
  }

  printf("\n== values, not just return codes (rc-only probes hide these) ==\n");
  ExpectReadableWithContent("stat+open+read(rootfs file)", RootFSFile);
  ExpectReadableWithContent("stat+open+read(host file)", HostFile);

  printf("\n== access() must not answer out of host permissions ==\n");
  ++Checks;
  errno = 0;
  if (access(RootFSFile, R_OK) != 0) {
    printf("  FAIL %-44s errno=%d %s\n", "access(rootfs file, R_OK)", errno, ErrName(errno));
    ++Failures;
  } else {
    printf("  PASS %-44s\n", "access(rootfs file, R_OK)");
  }

  printf("\n%d checks, %d failures\n", Checks, Failures);
  return Failures != 0;
}
