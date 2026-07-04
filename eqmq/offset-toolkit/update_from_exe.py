#!/usr/bin/env python3
"""
update_from_exe.py  --  end-to-end offset update from a (new) eqgame.exe.

Drives the existing toolkit so a single command turns a new client binary into an
updated eqgame.h + version stamp, with a coverage report you review before applying.

    python update_from_exe.py analyze  <path-to-new-eqgame.exe>
        -> Ghidra-analyzes the binary (SLOW, 1-3h), then relocates offsets:
           - if baseline_db.json is seeded: relocate from the DB (one analysis)
           - else: bootstrap-diff against the newest archived client whose offsets
             match the current eqgame.h (needs versions\\archive\\<date>\\eqgame.exe)
           Outputs:  out\\eqgame_new.h            (proposed header)
                     out\\coverage_report.csv     (name, old_va, new_va, kind, confidence)
                     out\\incoming_stamp.json      (detected version date/time)

    python update_from_exe.py apply
        -> backs up the real eqgame.h, writes out\\eqgame_new.h over it, and bumps
           __ExpectedVersionDate / __ExpectedVersionTime / __ClientDate from the new exe.
           REVIEW the coverage first. Always rebuild + verify in-game afterward.

HONEST SCOPE: relocates OFFSETS + version stamp only. Struct-layout / API-drift source
fixes (e.g. a renamed eqlib field) are NOT auto-generated -- they surface when you build
and need a human. See 01-build/patches/api-drift-notes.md.
"""
import os, sys, re, json, shutil, csv
import eqmq_paths as P
import offsettool
import superbaseline

INCOMING = "incoming"


def detect_stamp(exe):
    """Find the client build date + the time string adjacent to it (the __DATE__/__TIME__
    pair the compiler emits), plus the numeric __ClientDate."""
    with open(exe, "rb") as f:
        blob = f.read()
    text = blob.decode("latin-1", "ignore")
    date = None; time = None
    m = re.search(r'([A-Z][a-z]{2} [ 0-9][0-9] 20[0-9]{2})', text)
    if m:
        date = m.group(1)
        # the build time usually sits within a few bytes of the date string
        window = text[m.end(): m.end() + 24]
        tm = re.search(r'([0-2][0-9]:[0-5][0-9]:[0-5][0-9])', window)
        if tm:
            time = tm.group(1)
    # all candidate times (for the UI to let the user pick if the adjacent guess is wrong)
    times = sorted(set(re.findall(r'[0-2][0-9]:[0-5][0-9]:[0-5][0-9]', text)))
    client_num = None
    if date:
        try:
            import datetime
            dt = datetime.datetime.strptime(re.sub(r'\s+', ' ', date), "%b %d %Y")
            client_num = dt.strftime("%Y%m%d")
        except Exception:
            pass
    return {"date": date, "time": time, "time_candidates": times[:10], "client_num": client_num}


def analyze(exe):
    if not os.path.exists(exe):
        print("[update] exe not found: %s" % exe); sys.exit(2)
    os.makedirs(P.OUT, exist_ok=True)

    # record the version stamp detected from the new binary
    stamp = detect_stamp(exe)
    with open(os.path.join(P.OUT, "incoming_stamp.json"), "w", encoding="utf-8") as f:
        json.dump(stamp, f, indent=2)
    print("[update] detected client build: %s %s (ClientDate %s)" %
          (stamp.get("date"), stamp.get("time"), stamp.get("client_num")))

    # 1) Ghidra-analyze the uploaded binary
    print("[update] analyzing the new client in Ghidra (this is the slow part)...")
    offsettool.snapshot(INCOMING, exe)

    db = os.path.join(P.WORKSPACE, "baseline_db.json")
    produced = None
    if os.path.exists(db):
        print("[update] baseline_db.json found -> relocating offsets from the fingerprint DB")
        superbaseline.relocate(INCOMING)               # writes out\eqgame_relocated.h + coverage_report.csv
        produced = os.path.join(P.OUT, "eqgame_relocated.h")
    else:
        print("[update] no fingerprint DB yet -> bootstrap-diff against newest archived client")
        old = _newest_archive()
        if not old:
            print("[update] No baseline_db.json AND no archived client to diff against.")
            print("         Seed the DB first (Seed-Baseline.bat) or archive a known-good client.")
            sys.exit(3)
        print("[update] using archive baseline: %s" % old)
        offsettool.snapshot("baseline_boot", old)      # analyze the old client too (SLOW)
        offsettool.diff("baseline_boot", INCOMING)
        offsettool.suggest("baseline_boot", INCOMING)  # writes out\eqgame_suggested.h + offset_report.csv
        produced = os.path.join(P.OUT, "eqgame_suggested.h")

    # normalize to out\eqgame_new.h
    if produced and os.path.exists(produced):
        shutil.copy2(produced, os.path.join(P.OUT, "eqgame_new.h"))
        print("[update] proposed header -> %s" % os.path.join(P.OUT, "eqgame_new.h"))
        print("[update] REVIEW out\\coverage_report.csv (or offset_report.csv), then 'apply'.")
    else:
        print("[update] no proposed header produced - check Ghidra output above."); sys.exit(4)


def _newest_archive():
    arch = os.path.join(P.VERSIONS, "archive")
    if not os.path.isdir(arch):
        return None
    cands = []
    for root, _dirs, files in os.walk(arch):
        for fn in files:
            if fn.lower() == "eqgame.exe":
                cands.append(os.path.join(root, fn))
    cands.sort()
    return cands[-1] if cands else None


DEFINE_RE = re.compile(r'^(#define\s+)(\S+)(\s+)("?[^"\n]*"?|\d+u?|0x[0-9A-Fa-f]+)(.*)$')

def bump_stamp(eqgame_h, stamp):
    """Rewrite __ExpectedVersionDate/Time and __ClientDate in eqgame.h from the new exe."""
    if not stamp.get("date"):
        print("[update] no detected date - skipping version-stamp bump (set it by hand)."); return
    lines = open(eqgame_h, encoding="utf-8", errors="replace").read().split("\n")
    out = []
    for ln in lines:
        if "__ExpectedVersionDate" in ln and stamp.get("date"):
            ln = re.sub(r'"[^"]*"', '"%s"' % stamp["date"], ln, count=1)
        elif "__ExpectedVersionTime" in ln and stamp.get("time"):
            ln = re.sub(r'"[^"]*"', '"%s"' % stamp["time"], ln, count=1)
        elif "__ClientDate" in ln and stamp.get("client_num"):
            ln = re.sub(r'\d{8}u', '%su' % stamp["client_num"], ln, count=1)
        out.append(ln)
    with open(eqgame_h, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print("[update] version stamp bumped: %s %s / %s" %
          (stamp.get("date"), stamp.get("time"), stamp.get("client_num")))


def apply():
    if not P.require("EQGAME_H"):
        sys.exit(2)
    new_h = os.path.join(P.OUT, "eqgame_new.h")
    if not os.path.exists(new_h):
        print("[update] no out\\eqgame_new.h - run 'analyze <exe>' first."); sys.exit(2)
    # SAFETY: never overwrite eqgame.h with a garbage/partial relocation.
    def _ndef(path):
        return sum(1 for ln in open(path, encoding="utf-8", errors="replace")
                   if re.match(r'^#define\s+\S+\s+0x[0-9A-Fa-f]+', ln))
    cur, new = _ndef(P.EQGAME_H), _ndef(new_h)
    if new < cur * 0.9:
        print("[update] ABORT: proposed header has %d offsets vs current %d (>10%% missing)." % (new, cur))
        print("         That's likely a bad/partial analysis. Not touching eqgame.h. Review out\\coverage_report.csv.")
        sys.exit(5)
    print("[update] sanity: proposed header has %d offsets (current %d) - ok." % (new, cur))
    # backup
    bdir = os.path.join(P.OUT, "backups")
    os.makedirs(bdir, exist_ok=True)
    import time as _t  # only for a counter suffix; not wall-clock-critical
    bak = os.path.join(bdir, "eqgame_h_%d.bak" % len(os.listdir(bdir)))
    shutil.copy2(P.EQGAME_H, bak)
    print("[update] backed up eqgame.h -> %s" % bak)
    shutil.copy2(new_h, P.EQGAME_H)
    print("[update] wrote new offsets into %s" % P.EQGAME_H)
    sp = os.path.join(P.OUT, "incoming_stamp.json")
    if os.path.exists(sp):
        bump_stamp(P.EQGAME_H, json.load(open(sp, encoding="utf-8")))
    print("[update] DONE. Review the git diff in src/eqlib, rebuild (incl. external plugins),")
    print("         and VERIFY in-game on a throwaway login. Revert: restore %s" % bak)


def coverage_summary():
    """Print a quick matched/unmatched tally from the latest coverage report (for the UI)."""
    for name in ("coverage_report.csv", "offset_report.csv"):
        p = os.path.join(P.OUT, name)
        if os.path.exists(p):
            tot = matched = unm = 0
            with open(p, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    tot += 1
                    nv = (r.get("new_va") or "").strip()
                    st = (r.get("status") or r.get("confidence") or "").strip().lower()
                    if nv and st not in ("unmatched", ""):
                        matched += 1
                    elif not nv or st == "unmatched":
                        unm += 1
            print("[coverage] %s: %d offsets, %d matched, %d unmatched" % (name, tot, matched, unm))
            return
    print("[coverage] no report yet")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "analyze":
        analyze(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "apply":
        apply()
    elif len(sys.argv) == 2 and sys.argv[1] == "coverage":
        coverage_summary()
    else:
        print(__doc__); sys.exit(1)
