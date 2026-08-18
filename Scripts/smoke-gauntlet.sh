#!/usr/bin/env bash
# Title smoke gauntlet (v3). Deployed as ~/fex-scripts/smoke6.sh on the test
# host; this copy is the source of truth. Host assumptions: a per-title `fex
# <title>` launcher registry in ~/fex-scripts, an Xwayland session on :1 with
# its xauth under /run/user/1000, a systemd user manager, gawk, ImageMagick 7,
# and python3-evdev for the seat-wide Enter injection (sendkey.py).
#
# WHY EACH PIECE EXISTS -- every one of these was a verdict-corrupting failure
# on 2026-08-16 before it was added:
#  * cgroup per leg (systemd-run --user): wine/java/crash-handlers daemonize
#    out of any process group; name-blocklist teardowns leaked cohorts three
#    separate times. `systemctl stop` kills the cgroup; nothing escapes.
#  * RENDER verification: process count proves only that wine services idle
#    well. A title passes only with a real window whose pixel stddev clears
#    0.02 -- a wedged title (ntsync park, GLX failure) reads WEDGE, not PASS.
#  * per-title screenshots (shots/): the unattended audit trail.
#  * CPU-delta on windowless legs, with the window sized so a renderer and a
#    parked process cannot overlap (vkcube: >=2s over 30s).
#  * start guard: refuses to run over a live session -- the suite must never
#    fight a human for the machine.
# Gauntlet v3: cgroup isolation + RENDER VERIFICATION. A title passes only if
# it has a real window whose contents are not a black/uniform screen. Alive-
# but-wedged (no window, or black, or idle-CPU park) is called WEDGE, not PASS.
# Screenshots land in /tmp/smoke/shots/<title>.png for post-hoc audit.
# Refuses to start if the box already runs guest processes (unattended-safe).
set -u
OUT=/tmp/smoke
SHOTS=$OUT/shots
mkdir -p "$OUT" "$SHOTS"
export XDG_RUNTIME_DIR=/run/user/1000
export DISPLAY=:1
XAUTH=$(ls /run/user/1000/xauth_* 2>/dev/null | head -1)
export XAUTHORITY=${XAUTH:-$HOME/.Xauthority}
SC="systemctl --user"

# ---- start guard: never stomp a live session -------------------------------
if pgrep -f "Bin/FEX" >/dev/null 2>&1 || pgrep -f "[.]exe" >/dev/null 2>&1; then
  echo "SUITE-ABORT: guest processes already running; refusing to start" | tee -a "$OUT/RESULTS.txt"
  exit 1
fi

leg_teardown() {
  local unit="$1"
  $SC stop "$unit" 2>/dev/null
  $SC reset-failed "$unit" 2>/dev/null
  sleep 2
}

leg_proc_count() {
  local unit="$1"
  local cg="/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/$unit"
  if [[ -f "$cg/cgroup.procs" ]]; then
    wc -l < "$cg/cgroup.procs"
  else
    echo 0
  fi
}

# Total CPU-seconds consumed by the leg's cgroup (usage_usec -> seconds).
leg_cpu_seconds() {
  local unit="$1"
  local cg="/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/$unit"
  if [[ -f "$cg/cpu.stat" ]]; then
    awk '/usage_usec/ {printf "%d", $2/1000000}' "$cg/cpu.stat"
  else
    echo 0
  fi
}

# Largest named window's id, or empty. Ignores the 1x1 IME/selection junk.
biggest_window() {
  xwininfo -root -tree 2>/dev/null | awk '
    match($0, /^ +(0x[0-9a-f]+) "[^"]+".*  ([0-9]+)x([0-9]+)\+/, m) {
      area = m[2] * m[3]
      if (area > best) { best = area; id = m[1] }
    }
    END { if (best > 100000) print id }'
}

# 0 = looks rendered, 1 = black/uniform, 2 = no window
render_check() {
  local title="$1"
  local id
  id=$(biggest_window)
  if [[ -z "$id" ]]; then
    return 2
  fi
  import -window "$id" "$SHOTS/$title.png" 2>/dev/null || return 2
  # Standard deviation of pixel intensity: a black or single-color screen is
  # ~0; any real menu/scene is far above 0.02.
  local dev
  dev=$(magick identify -format "%[fx:standard_deviation]" "$SHOTS/$title.png" 2>/dev/null || echo 0)
  awk -v d="$dev" 'BEGIN { exit (d > 0.02) ? 0 : 1 }'
}

# title  boot  enters  play  check(xwin|proc)
run_one() {
  local title="$1" boot="$2" enters="$3" play="$4" check="${5:-xwin}"
  local unit="smoke-$title.service"
  echo "=== $title $(date +%H:%M:%S) ===" | tee -a "$OUT/RESULTS.txt"
  leg_teardown "$unit"
  systemd-run --user --collect --quiet --unit "smoke-$title" \
    -p TimeoutStopSec=3 -p KillMode=control-group \
    bash -c "exec ~/fex-scripts/fex $title > $OUT/$title.log 2>&1"
  sleep "$boot"
  local n cpu0
  n=$(leg_proc_count "$unit")
  cpu0=$(leg_cpu_seconds "$unit")
  if [[ "$n" -eq 0 ]]; then
    echo "SMOKE-FAIL $title: dead after ${boot}s boot" | tee -a "$OUT/RESULTS.txt"
    tail -5 "$OUT/$title.log" | sed 's/^/    /' >> "$OUT/RESULTS.txt"
    leg_teardown "$unit"
    return 1
  fi
  local i
  for ((i=0; i<enters; i++)); do
    python3 ~/fex-scripts/sendkey.py KEY_ENTER --delay 0.2 >/dev/null 2>&1
    sleep 15
  done
  sleep "$play"
  n=$(leg_proc_count "$unit")
  local cpu1 dcpu
  cpu1=$(leg_cpu_seconds "$unit")
  dcpu=$((cpu1 - cpu0))
  if [[ "$n" -eq 0 ]]; then
    echo "SMOKE-FAIL $title: died during enters/play window" | tee -a "$OUT/RESULTS.txt"
    tail -5 "$OUT/$title.log" | sed 's/^/    /' >> "$OUT/RESULTS.txt"
    leg_teardown "$unit"
    return 1
  fi
  local verdict=""
  if [[ "$check" == "xwin" ]]; then
    render_check "$title"
    case $? in
    0) verdict="SMOKE-PASS $title: window rendering (procs=$n cpuΔ=${dcpu}s) shot=shots/$title.png" ;;
    1) verdict="SMOKE-WEDGE $title: window is BLACK/uniform (procs=$n cpuΔ=${dcpu}s) shot=shots/$title.png" ;;
    2) verdict="SMOKE-WEDGE $title: alive but NO window (procs=$n cpuΔ=${dcpu}s)" ;;
    esac
  else
    # proc-check legs (canaries with no X window): CPU delta is the liveness.
    if [[ "$dcpu" -ge 2 ]]; then
      verdict="SMOKE-PASS $title: alive, cpuΔ=${dcpu}s over the window (proc-check leg)"
    else
      verdict="SMOKE-WEDGE $title: alive but idle (cpuΔ=${dcpu}s) — parked/wedged"
    fi
  fi
  echo "$verdict" | tee -a "$OUT/RESULTS.txt"
  leg_teardown "$unit"
  local leak
  leak=$(pgrep -cf "Bin/FEX|\.exe" 2>/dev/null | head -1)
  [[ "${leak:-0}" -gt 0 ]] && echo "SMOKE-LEAK $title: $leak guest procs survived the cgroup stop" | tee -a "$OUT/RESULTS.txt"
}

# ---- full ladder, render-verified ------------------------------------------
run_one vkcube      20 0 30 proc
run_one ftl         75 3 60 xwin
run_one ziggurat    60 0 45 xwin
run_one rimworld    90 0 60 xwin
run_one grimrock    45 0 45 xwin
run_one stardew     75 0 45 xwin
run_one hardwest    75 0 45 xwin
run_one moonlighter 60 0 45 xwin
run_one amongthesleep 75 0 45 xwin
run_one shadowrunhk 75 0 45 xwin
run_one zomboid     90 0 60 xwin
run_one dex         60 0 45 xwin
run_one psychonauts 60 0 45 xwin
run_one witcher2    90 0 60 xwin
run_one witcher3   180 6 120 xwin
run_one dexwin     150 5 60 xwin
run_one cp2077     240 0 90 xwin
run_one outward    150 0 60 xwin
run_one tombraider 150 0 60 xwin
run_one vtmb       120 0 60 xwin
run_one vtmbup     120 0 60 xwin
run_one arcanum    120 0 60 xwin
run_one rimworldwin 150 0 60 xwin
echo "SUITE-DONE $(date +%H:%M:%S)" | tee -a "$OUT/RESULTS.txt"
