#!/bin/bash
# Set the performance governor on every CPU. op64k boots `ondemand`; no number
# is worth writing down until this has run (PAGE_SIZE_64K_EXECUTION.md §1).
#
# Needs root. Run it, then re-run with `--show` to confirm before benchmarking.
set -euo pipefail

show() {
  if command -v cpupower >/dev/null 2>&1; then
    cpupower frequency-info -p 2>/dev/null || true
  fi
  echo "governors in use:"
  cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort | uniq -c
}

if [[ "${1:-}" == "--show" ]]; then
  show
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "re-running under sudo" >&2
  exec sudo -- "$0" "$@"
fi

if ! compgen -G "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >/dev/null; then
  echo "no cpufreq sysfs nodes -- is the cpufreq driver loaded?" >&2
  exit 1
fi

if command -v cpupower >/dev/null 2>&1; then
  cpupower frequency-set -g performance >/dev/null
else
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > "$g"
  done
fi

show
