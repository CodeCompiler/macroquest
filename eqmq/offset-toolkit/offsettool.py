#!/usr/bin/env python3
"""
offsettool.py  --  EQ offset-update helper for MacroQuest (Ghidra-based).

Workflow (see 02-offset-toolkit\\README.md):
    1) python offsettool.py snapshot <label>      # analyze the CURRENT eqgame.exe
       ...later, after an EQ patch...
    2) python offsettool.py snapshot <newlabel>
    3) python offsettool.py diff    <oldlabel> <newlabel>
    4) python offsettool.py suggest <oldlabel> <newlabel>

"snapshot" copies the live eqgame.exe and runs Ghidra headless analysis, exporting
every function + the strings it references (functions.csv).

"diff" matches old<->new functions by their (stable) referenced-string sets and writes
old_va -> new_va pairs.

"suggest" reads MacroQuest's eqgame.h, and for every offset whose old VA was matched in
the diff, proposes the new VA -- producing a report and a suggested header for review.

PATHS ARE NOT HARD-CODED HERE.  They are resolved by eqmq_paths.py (env var ->
eqmq.config.ini -> auto-detect).  Run `python eqmq_paths.py check` to see what resolved,
or `prerequisites\\Detect-Environment.ps1` to generate the config.
"""

import os, sys, csv, shutil, subprocess, re
import eqmq_paths as P

EXPORT_SCRIPT = os.path.join(P.WORKSPACE, "ghidra_export.java")


def vahex(n):            return "0x%X" % n
def parse_va(s):         return int(s, 16)


def snapshot(label, src=None):
    given = src is not None          # an explicit exe path was provided (e.g. an uploaded client)
    src = src or P.EQ_EXE
    # Ghidra + JDK are always required; EQ_EXE only matters when NO explicit exe was given.
    need = ["GHIDRA_HEADLESS", "JDK21"]
    if not given:
        need.append("EQ_EXE")
    if not P.require(*need):
        sys.exit(2)
    if not src or not os.path.exists(src):
        print("[snapshot] source eqgame.exe not found: %s" % src); sys.exit(2)

    vdir = os.path.join(P.VERSIONS, label)
    os.makedirs(vdir, exist_ok=True)
    os.makedirs(P.PROJECTS, exist_ok=True)   # Ghidra requires the project dir to exist
    os.makedirs(P.OUT, exist_ok=True)
    exe = os.path.join(vdir, "eqgame.exe")
    print("[snapshot] copying %s -> %s" % (src, exe))
    shutil.copy2(src, exe)
    funcs_csv = os.path.join(vdir, "functions.csv")
    cmd = [P.GHIDRA_HEADLESS, P.PROJECTS, label,
           "-import", exe,
           "-overwrite",
           "-scriptPath", P.WORKSPACE,
           "-postScript", "ghidra_export.java", funcs_csv]
    # NOTE: `-analysisTimeoutPerFile 0` means "abort analysis at 0s" in headless Ghidra
    # (NOT "no timeout"), which yields zero functions.  Only pass a timeout when it's a
    # positive number; otherwise omit the flag so analysis runs to completion.
    try:
        _timeout = int(str(P.ANALYSIS_TIMEOUT).strip())
    except (TypeError, ValueError):
        _timeout = 0
    if _timeout > 0:
        cmd += ["-analysisTimeoutPerFile", str(_timeout)]
    print("[snapshot] running Ghidra headless analysis (this can take a long time)...")
    print("           " + " ".join('"%s"' % c if " " in c else c for c in cmd))
    env = dict(os.environ)
    env["JAVA_HOME"] = P.JDK21
    env["PATH"] = os.path.join(P.JDK21, "bin") + os.pathsep + env.get("PATH", "")
    rc = subprocess.call(cmd, env=env)
    if rc != 0:
        print("[snapshot] Ghidra returned %d" % rc)
    if os.path.exists(funcs_csv):
        n = sum(1 for _ in open(funcs_csv, encoding="utf-8", errors="replace")) - 1
        print("[snapshot] DONE -> %s  (%d functions)" % (funcs_csv, n))
    else:
        print("[snapshot] WARNING: %s not produced - check Ghidra output above." % funcs_csv)


def load_funcs(label):
    path = os.path.join(P.VERSIONS, label, "functions.csv")
    rows = []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for r in csv.DictReader(f):
            rows.append((r["va"].strip(), r.get("strings", "").strip()))
    return rows


def anchor_map(rows):
    """anchor(string-set) -> va, keeping only anchors that are non-empty AND unique."""
    counts, m = {}, {}
    for va, strings in rows:
        if not strings:
            continue
        counts[strings] = counts.get(strings, 0) + 1
        m[strings] = va
    return {a: va for a, va in m.items() if counts[a] == 1}


def diff(old, new):
    om = anchor_map(load_funcs(old))
    nm = anchor_map(load_funcs(new))
    out_csv = os.path.join(P.OUT, "%s_to_%s.csv" % (old, new))
    matched = moved = 0
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["old_va", "new_va", "changed", "anchor_preview"])
        for anchor, ova in sorted(om.items()):
            if anchor in nm:
                nva = nm[anchor]
                changed = "YES" if parse_va(ova) != parse_va(nva) else "no"
                if changed == "YES":
                    moved += 1
                matched += 1
                w.writerow([vahex(parse_va(ova)), vahex(parse_va(nva)), changed, anchor[:80]])
    print("[diff] %d functions matched by string-anchor, %d moved -> %s" % (matched, moved, out_csv))
    return out_csv


def load_diff(old, new):
    path = os.path.join(P.OUT, "%s_to_%s.csv" % (old, new))
    if not os.path.exists(path):
        path = diff(old, new)
    d = {}
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            d[parse_va(r["old_va"])] = parse_va(r["new_va"])
    return d


DEFINE_RE = re.compile(r'^(#define\s+)(\S+)(\s+)(0x[0-9A-Fa-f]+)(.*)$')


def suggest(old, new):
    if not P.require("EQGAME_H"):
        sys.exit(2)
    d = load_diff(old, new)
    report = os.path.join(P.OUT, "offset_report.csv")
    suggested = os.path.join(P.OUT, "eqgame_suggested.h")
    total = matched = unmatched = unchanged = 0
    rep = open(report, "w", encoding="utf-8", newline="")
    rw = csv.writer(rep); rw.writerow(["name", "old_va", "new_va", "status"])
    outh = open(suggested, "w", encoding="utf-8")
    for line in open(P.EQGAME_H, encoding="utf-8", errors="replace"):
        m = DEFINE_RE.match(line.rstrip("\n"))
        if not m:
            outh.write(line); continue
        name, ova = m.group(2), parse_va(m.group(4))
        total += 1
        if ova in d:
            nva = d[ova]
            if nva != ova:
                matched += 1; status = "UPDATED"
            else:
                unchanged += 1; status = "same"
            rw.writerow([name, vahex(ova), vahex(nva), status])
            outh.write("%s%s%s%s%s\n" % (m.group(1), name, m.group(3), vahex(nva), m.group(5)))
        else:
            unmatched += 1
            rw.writerow([name, vahex(ova), "", "UNMATCHED"])
            outh.write(line)
    rep.close(); outh.close()
    print("[suggest] %d offsets: %d updated, %d unchanged, %d UNMATCHED (need VT/x64dbg/manual)"
          % (total, matched, unchanged, unmatched))
    print("[suggest] review report : %s" % report)
    print("[suggest] suggested .h  : %s   (DIFF vs original before using!)" % suggested)


def usage():
    print(__doc__); sys.exit(1)


if __name__ == "__main__":
    os.makedirs(P.OUT, exist_ok=True)
    if len(sys.argv) < 2: usage()
    cmd = sys.argv[1].lower()
    if   cmd == "snapshot" and len(sys.argv) in (3, 4): snapshot(sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None)
    elif cmd == "diff"     and len(sys.argv) == 4: diff(sys.argv[2], sys.argv[3])
    elif cmd == "suggest"  and len(sys.argv) == 4: suggest(sys.argv[2], sys.argv[3])
    else: usage()
