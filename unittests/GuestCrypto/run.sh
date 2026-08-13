#!/usr/bin/env bash
# GuestCrypto suite runner.
#
#   ./run.sh              # build both bitnesses, run them on op4k under FEX
#   ./run.sh local        # build and run natively (only valid on an x86 host)
#   ./run.sh op4k         # explicit remote mode (the default)
#
# Environment knobs:
#   STRESS_ITERS   iterations for stress_test           (default 100000)
#   REMOTE         ssh destination                      (default op4k)
#   REMOTE_DIR     scratch dir on the remote            (default /tmp/guestcrypto)
#   FEX_BIN        FEX binary on the remote
#   FEX_ROOTFS     rootfs for FEX on the remote
#   BUILD_DIR      local build output dir
#   ONLY           space separated test basenames to run (default: all)
#
# Exit status is the number of test programs that failed.
set -u

MODE="${1:-op4k}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-${TMPDIR:-/tmp}/guestcrypto-build}"
STRESS_ITERS="${STRESS_ITERS:-100000}"
REMOTE="${REMOTE:-op4k}"
REMOTE_DIR="${REMOTE_DIR:-/tmp/guestcrypto}"
FEX_BIN="${FEX_BIN:-/home/daedalao/projects/fex-emu-ppc64le/src/build-smc/Bin/FEX}"
FEX_ROOTFS="${FEX_ROOTFS:-/home/daedalao/.local/share/fex-emu/RootFS/ArchLinux}"
CLANG="${CLANG:-clang}"

TESTS_DEFAULT="aes_test pclmul_test sha_test crc32_test interleave_test stress_test"
TESTS="${ONLY:-$TESTS_DEFAULT}"

CFLAGS_COMMON="-O1 -ffreestanding -fno-stack-protector -maes -mpclmul -msha -msse4.2 -msse4.1 -nostdlib -static -fuse-ld=lld"

mkdir -p "$BUILD_DIR" || exit 1

echo "=== building (${BUILD_DIR}) ==="
built=""
for t in $TESTS; do
  src="$HERE/$t.c"
  [ -f "$src" ] || { echo "missing $src"; exit 1; }
  # shellcheck disable=SC2086
  $CLANG --target=x86_64-unknown-linux-gnu $CFLAGS_COMMON -o "$BUILD_DIR/${t}_64" "$src" || exit 1
  # shellcheck disable=SC2086
  $CLANG --target=i686-unknown-linux-gnu -mstackrealign $CFLAGS_COMMON -o "$BUILD_DIR/${t}_32" "$src" || exit 1
  built="$built ${t}_64 ${t}_32"
  echo "  ok: $t (32 + 64)"
done

args_for() {
  case "$1" in
  stress_test_*) echo "$STRESS_ITERS" ;;
  *) echo "" ;;
  esac
}

fails=0
run_one_local() {
  local b="$1" extra
  extra="$(args_for "$b")"
  echo "--- $b ---"
  # shellcheck disable=SC2086
  "$BUILD_DIR/$b" $extra
  local rc=$?
  echo "[$b] exit=$rc"
  [ $rc -ne 0 ] && fails=$((fails + 1))
  return 0
}

if [ "$MODE" = "local" ]; then
  case "$(uname -m)" in
  x86_64 | i?86) : ;;
  *) echo "local mode needs an x86 host (this is $(uname -m))"; exit 1 ;;
  esac
  for b in $built; do run_one_local "$b"; done
else
  echo "=== deploying to $REMOTE:$REMOTE_DIR ==="
  ssh "$REMOTE" "mkdir -p $REMOTE_DIR" || exit 1
  # shellcheck disable=SC2086
  ( cd "$BUILD_DIR" && scp -q $built "$REMOTE:$REMOTE_DIR/" ) || exit 1
  ssh "$REMOTE" "chmod +x $REMOTE_DIR/*" || exit 1

  for b in $built; do
    extra="$(args_for "$b")"
    echo "--- $b (FEX on $REMOTE) ---"
    # CPUINFO chatter goes to stderr on every FEX start; filter it out.
    ssh "$REMOTE" "FEX_ROOTFS=$FEX_ROOTFS $FEX_BIN $REMOTE_DIR/$b $extra; echo EXIT:\$?" \
      2> >(grep -v 'CPUINFO' >&2) | {
      rc=1
      while IFS= read -r line; do
        case "$line" in
        EXIT:*) rc="${line#EXIT:}" ;;
        *) printf '%s\n' "$line" ;;
        esac
      done
      echo "[$b] exit=$rc"
      [ "$rc" != "0" ] && exit 1
      exit 0
    } || fails=$((fails + 1))
  done
fi

echo "=== ${fails} failing test program(s) ==="
exit $fails
