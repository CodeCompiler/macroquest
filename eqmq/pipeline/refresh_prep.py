#!/usr/bin/env python3
# refresh_prep.py -- rebuild the discovered-functions DB (sig+size from the latest Ghidra export)
# and the decompile VA list (discovered + eqgame.h). Run before build_funcatalog.py + the decompile.
#
#   python refresh_prep.py [label]   -- label defaults to the NEWEST versions/ dir (never the
#                                       stale jun24: that was a live bug that read the wrong
#                                       client's functions.csv every patch day).
import os, sys, json, csv, re, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jsonstore   # crash-safe atomic write

TOOLKIT = r"C:\EQMQ\02-offset-toolkit"

def newest_functions_csv(label=None):
    """Resolve versions/<label>/functions.csv, or the newest version dir that has one."""
    if label:
        p = os.path.join(TOOLKIT, "versions", label, "functions.csv")
        if os.path.isfile(p): return p
    for v in sorted(glob.glob(os.path.join(TOOLKIT, "versions", "*")), key=os.path.getmtime, reverse=True):
        p = os.path.join(v, "functions.csv")
        if os.path.isfile(p): return p
    return os.path.join(TOOLKIT, "versions", "jun24", "functions.csv")  # last-resort fallback

_LABEL = sys.argv[1] if len(sys.argv) > 1 else None
OBS    = r"C:\mmoplugins\funccat_observed.json"
FUNCS  = os.environ.get("EQMQ_FUNCTIONS_CSV") or newest_functions_csv(_LABEL)
EQH    = r"C:\MQ2\macroquest\src\eqlib\include\eqlib\offsets\eqgame.h"
DISC   = r"C:\mmoplugins\funccat_discovered.json"
VALIST = r"C:\eqmq-deploy\decomp_vas.txt"

def usable(s): return bool(s) and (len(s) - s.count("?")) // 2 >= 8

def main():
    obs = json.load(open(OBS, encoding="utf-8")); F = obs.get("functions", {})
    meta = {}
    for r in csv.DictReader(open(FUNCS, encoding="utf-8", errors="replace", newline="")):
        meta[(r.get("va") or "").lower()] = (r.get("sig", ""), r.get("size", ""))
    disc = {}; vas = set(); have = 0
    for va, e in F.items():
        s, sz = meta.get(va.lower(), ("", ""))
        lbl = (e.get("class", "") or "") + ("::vf" + str(e.get("index")) if e.get("index", -1) >= 0 else "")
        disc[va] = {"name": lbl, "class": e.get("class", ""), "index": e.get("index", -1), "sig": s, "size": sz}
        if usable(s): have += 1
        vas.add(va.lower())
    jsonstore.atomic_dump({"functions": disc}, DISC, indent=1)
    DEF = re.compile(r"^\s*#define\s+\S+\s+(0x[0-9A-Fa-f]+)")
    for ln in open(EQH, encoding="utf-8", errors="replace"):
        m = DEF.match(ln)
        if m: vas.add(m.group(1).lower())
    open(VALIST, "w").write("\n".join(sorted(vas)))
    print("refresh_prep: funcs_csv=%s | discovered=%d (relocatable=%d) | decompile VA list=%d"
          % (FUNCS, len(disc), have, len(vas)))

if __name__ == "__main__":
    main()
