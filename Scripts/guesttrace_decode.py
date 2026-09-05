#!/usr/bin/env python3
"""Decode a FEX_GUESTTRACE ring (/tmp/fex-guesttrace-<pid>.bin).

Format contract: JIT.cpp GuestTraceRingHeader / GuestTraceOff* constants.
Header page (4096 bytes): magic "GTRACE01", u64 recsize, u64 capacity,
u64 deref_base, u64 deref_len, u64 reserved, u64 idx (monotonic claim count).
Records follow, `recsize` bytes each:
  0x00 u64 tb        timebase, written LAST (0 = torn/unwritten slot)
  0x08 u64 state     STATE pointer = per-thread identity
  0x10 u64 rip       guest RIP of the traced entry
  0x18 u64 cr        saved CR image (CR0 = guest packed NZCV)
  0x20 u64[16] gprs  SRA order per X86State enum: RAX,RCX,RDX,RBX,RSP,...
  0xa0 u64 retaddr   [guest rsp] at entry = call site (garbage if jumped-to)
  0xa8 deref blob    [rcx+deref_base, +deref_len) -- for the W3 TLSF campaign
                     the 16 bucket triples {begin,end,cap}, 3 u64 ptrs each

Default analysis (--w3): treat the blob as TLSF bucket triples and flag
  * records where any bucket has end < begin, or (end-begin) odd
  * the first record whose snapshot differs from the reconstruction implied
    by the previous snapshot of the SAME allocator object (rcx)
  * interleave: runs where two thread identities alternate within a span of
    N claim slots (allocator-exclusion violations show up here)
"""
import argparse
import struct
import sys

SRA_NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
MAGIC = 0x3130454341525447

KNOWN_RIPS = {
    0x141D52690: "RemoveFromBucket",
    0x141D52530: "AddToBucket",
    0x141D529D0: "FreeBlock",
    0x140709770: "u16grow",
}


def load(path):
    with open(path, "rb") as f:
        data = f.read()
    magic, recsize, cap, dbase, dlen, resv, idx = struct.unpack_from("<7Q", data, 0)
    if magic != MAGIC:
        sys.exit(f"bad magic {magic:#x}; not a guesttrace ring")
    if resv:
        # FEX_GUESTANCHOR stamped the discovered module base here; rebase the
        # known-function name table so rva-mode rings decode identically.
        global KNOWN_RIPS
        KNOWN_RIPS = {(rip - 0x140000000) + resv: name for rip, name in KNOWN_RIPS.items()}
        print(f"anchor base: {resv:#x} (rvas rebased)")
    recs = []
    lo = max(0, idx - cap)  # oldest still-present claim number
    for claim in range(lo, idx):
        off = 4096 + (claim % cap) * recsize
        tb, state, rip, cr = struct.unpack_from("<4Q", data, off)
        if tb == 0:
            recs.append(None)  # torn
            continue
        gprs = struct.unpack_from("<16Q", data, off + 0x20)
        retaddr = struct.unpack_from("<Q", data, off + 0xA0)[0]
        blob = data[off + 0xA8 : off + 0xA8 + dlen]
        recs.append({"claim": claim, "tb": tb, "state": state, "rip": rip,
                     "cr": cr, "gprs": gprs, "ret": retaddr, "blob": blob})
    return {"idx": idx, "cap": cap, "deref_base": dbase, "deref_len": dlen,
            "recs": recs}


def triples(blob):
    n = len(blob) // 24
    out = []
    for i in range(n):
        b, e, c = struct.unpack_from("<3Q", blob, i * 24)
        out.append((b, e, c))
    return out


def fmt_rec(r, tb0):
    name = KNOWN_RIPS.get(r["rip"], f"{r['rip']:#x}")
    g = r["gprs"]
    return (f"claim={r['claim']} dt={r['tb']-tb0} state={r['state']:#x} {name:>16} "
            f"ret={r['ret']:#x} rcx={g[1]:#x} rdx={g[2]:#x} r8={g[8]:#x} r9={g[9]:#x} rbx={g[3]:#x}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ring")
    ap.add_argument("--w3", action="store_true", default=True,
                    help="TLSF bucket-triple analysis (default)")
    ap.add_argument("--dump", action="store_true", help="print every record")
    ap.add_argument("--tail", type=int, default=64,
                    help="records of context to print before a finding")
    args = ap.parse_args()

    ring = load(args.ring)
    recs = [r for r in ring["recs"] if r]
    torn = sum(1 for r in ring["recs"] if r is None)
    if not recs:
        sys.exit("ring is empty")
    tb0 = recs[0]["tb"]
    threads = sorted({r["state"] for r in recs})
    print(f"{len(recs)} records ({torn} torn), claims {recs[0]['claim']}..{recs[-1]['claim']} "
          f"of {ring['idx']} total, {len(threads)} threads")
    for t in threads:
        n = sum(1 for r in recs if r["state"] == t)
        print(f"  thread {t:#x}: {n} records")

    if args.dump:
        for r in recs:
            print(fmt_rec(r, tb0))
        return

    # --w3: bucket-triple invariant scan, keyed by allocator object (rcx)
    findings = []
    last_by_obj = {}
    for i, r in enumerate(recs):
        rcx = r["gprs"][1]
        # The writer's deref-window guard (JIT.cpp): the blob is only written
        # when 0x10000 <= rcx < 2^48. A guard-skipped slot KEEPS the previous
        # lap's blob bytes (there is no per-lap generation tag), so after ring
        # wrap a stale non-zero blob sits under a fresh tb/rip/rcx -- the only
        # sound skip test is recomputing the guard from the recorded rcx, not
        # inspecting the blob.
        if rcx < 0x10000 or rcx >= (1 << 48):
            continue  # deref was guard-skipped; blob may be stale
        trip = triples(r["blob"])
        if all(b == 0 and e == 0 and c == 0 for b, e, c in trip):
            continue  # never-deref'd slot (first lap) or all-empty buckets
        bad = []
        for bi, (b, e, c) in enumerate(trip):
            if b == 0 and e == 0 and c == 0:
                continue
            if e < b or c < e or (e - b) % 2:
                bad.append((bi, b, e, c))
        if bad:
            findings.append((i, r, bad))
        prev = last_by_obj.get(rcx)
        if prev is not None:
            pi, ptrip = prev
            for bi, ((pb, pe, pc), (b, e, c)) in enumerate(zip(ptrip, trip)):
                # a bucket's array base moving without cap moving = the 2-byte
                # slide class; flag any begin change that is not a grow
                if pb and b and pb != b and pc == c:
                    findings.append((i, r, [("begin-moved", bi, pb, b, recs[pi]["claim"])]))
        last_by_obj[rcx] = (i, trip)

    if not findings:
        print("no bucket-invariant violations found in the ring window")
        return
    i0 = findings[0][0]
    print(f"\nFIRST FINDING at record index {i0} (claim {findings[0][1]['claim']}):")
    for f in findings[:8]:
        print("  ", fmt_rec(f[1], tb0), "->", f[2])
    lo = max(0, i0 - args.tail)
    print(f"\ncontext (records {lo}..{i0}):")
    for r in recs[lo : i0 + 1]:
        print("  ", fmt_rec(r, tb0))
    # interleave check around the finding
    span = recs[max(0, i0 - 16) : i0 + 1]
    states = [r["state"] for r in span]
    switches = sum(1 for a, b in zip(states, states[1:]) if a != b)
    print(f"\nthread switches in the 16 records before the finding: {switches}")


if __name__ == "__main__":
    main()
