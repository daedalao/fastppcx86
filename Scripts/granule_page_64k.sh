#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Build unittests/FEXLinuxTests/tests/memory/granule_page.cpp as a static x86-64
# binary that a 64K-page host can actually load, and print where it landed.
#
# Why this exists: the granule table (stage S4b) is guest-syscall machinery, but
# nothing reaches a guest syscall until the ELF loader has mapped the guest, and
# the loader still maps PT_LOAD segments at their 4K-congruent file offsets
# (stage S4a, PAGE_SIZE_64K_PLAN Part 1 finding 3). Host mmap wants those
# offsets to be multiples of the host page, so on a 64K host even a *static*
# binary fails to load unless every LOAD segment -- and the end of .bss, which
# the loader maps anonymously -- sits on a 64K boundary. Ordinary linker flags
# cannot express that: -z max-page-size only makes offsets *congruent* with
# addresses, which is all a 4K kernel needs. So we take ld's own default script
# and add three alignments.
#
# Delete this script once stage S4a's loader fallback lands; it exists purely to
# make S4b testable before S4a.
#
# Usage: Scripts/granule_page_64k.sh <output-dir> [source]

set -euo pipefail

OUT=${1:?usage: granule_page_64k.sh <output-dir> [source]}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC=${2:-$HERE/unittests/FEXLinuxTests/tests/memory/granule_page.cpp}
CC=${CC:-x86_64-pc-linux-gnu-gcc}

mkdir -p "$OUT"

# ld's default script, minus its two "=====" banner lines. The link itself
# fails (no main), which is fine -- ld prints the script before it gets there.
set +e
"$CC" -static -Wl,--verbose -x c /dev/null -o /dev/null 2>/dev/null |
  sed -n '/^=====/,/^=====/p' | sed '1d;$d' > "$OUT/default.lds.raw"
set -e
test -s "$OUT/default.lds.raw"

python3 - "$OUT/default.lds.raw" "$OUT/aligned64k.lds" <<'PY'
import sys
lines = open(sys.argv[1]).read().split('\n')
out = []
for i, line in enumerate(lines, start=1):
    stripped = line.strip()
    # Before the data segment: give the RW LOAD a 64K-aligned address, which
    # makes its file offset 64K-aligned too.
    if stripped.startswith('. = DATA_SEGMENT_ALIGN'):
        out.append('  . = ALIGN(0x10000);')
    # Before __bss_start: a section with real content, padded out, so that
    # p_filesz ends on a 64K boundary. An assignment to '.' alone would not
    # write any file bytes.
    if stripped.startswith('__bss_start = .'):
        out.append('  .fexfilepad : { BYTE(0); . = ALIGN(0x10000); }')
    out.append(line)
    # Last statement inside .bss: pad p_memsz out, so the anonymous BSS mapping
    # the loader makes is 64K-aligned at both ends.
    if stripped.startswith('. = ALIGN(. != 0 ?'):
        out.append('      . = ALIGN(0x10000);')
open(sys.argv[2], 'w').write('\n'.join(out))
PY

"$CC" -static -O1 -std=gnu99 -Wall \
  -Wl,-z,max-page-size=0x10000 -Wl,-z,norelro -Wl,--build-id=none \
  -Wl,-T,"$OUT/aligned64k.lds" \
  -x c "$SRC" -o "$OUT/granule_page"

echo "built $OUT/granule_page"
echo "run:   FEX_HOSTPAGEMODE=force <builddir>/Bin/FEX $OUT/granule_page"
