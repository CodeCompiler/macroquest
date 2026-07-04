#!/usr/bin/env python3
"""
build_funcatalog.py -- label EVERY function in the analyzed EQ client.

Cross-references the Ghidra export (all functions found in eqgame.exe) with eqgame.h
(the named offsets MacroQuest already uses), producing function_catalog.csv:

    va,label,source,strings,datarefs
      source=named     -> this function's entry VA matches an eqgame.h #define
                          (already wired into MacroQuest; label = the #define name)
      source=inferred  -> labeled from the first string literal it references
                          (a strong hint at what it does -> candidate to hook for new features)
      source=unlabeled -> references no distinctive strings (label = FUN_<va>)

So you have an address + a label for ALL functions in the game, not just the 652 MQ uses --
search it to find new functions to add functionality against later.

    python build_funcatalog.py [functions.csv] [eqgame.h] [out.csv]
"""
import os, csv, re, sys, json

TOOLKIT = r"C:\EQMQ\02-offset-toolkit"
FUNCS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(TOOLKIT, "versions", "jun24", "functions.csv")
EQH   = sys.argv[2] if len(sys.argv) > 2 else r"C:\MQ2\macroquest\src\eqlib\include\eqlib\offsets\eqgame.h"
OUT   = sys.argv[3] if len(sys.argv) > 3 else r"C:\mmoplugins\function_catalog.csv"
OBSERVED = r"C:\mmoplugins\funccat_observed.json"   # live-discovered identifications + admin names
XVER     = r"C:\mmoplugins\crossversion_labels.json"  # fused rtti/vtable/observed/ai labels, carried across patches

DEF = re.compile(r'^\s*#define\s+(\S+)\s+(0x[0-9A-Fa-f]+)')


def main():
    # eqgame.h: VA -> the name MacroQuest gave it
    va2name = {}
    for ln in open(EQH, encoding="utf-8", errors="replace"):
        m = DEF.match(ln)
        if m:
            va2name.setdefault(int(m.group(2), 16), m.group(1))

    # overlay: functions DISCOVERED live by MQ2FuncCat (class + vtable slot) + admin-assigned names,
    # so the discovered set is merged permanently into the catalog (named + diffable across patches).
    obs_label, user_name = {}, {}
    try:
        obs = json.load(open(OBSERVED, encoding="utf-8"))
        for va, e in (obs.get("functions") or {}).items():
            cls, idx = e.get("class", ""), e.get("index", -1)
            if cls:
                obs_label[va.lower()] = cls + ("::vf%d" % idx if isinstance(idx, int) and idx >= 0 else "")
        for va, nm in (obs.get("names") or {}).items():
            if nm: user_name[va.lower()] = nm
    except Exception:
        pass

    # crossversion overlay: rtti/vtable/ai/carried-forward labels (fused, sig-persistent)
    xver = {}
    try:
        for va, e in json.load(open(XVER, encoding="utf-8")).items():
            if e.get("label"): xver[va.lower()] = e
    except Exception:
        pass

    total = named = observed = inferred = unlabeled = engine = 0
    with open(FUNCS, encoding="utf-8", errors="replace", newline="") as f, \
         open(OUT, "w", encoding="utf-8", newline="") as o:
        w = csv.writer(o)
        w.writerow(["va", "label", "source", "category", "purpose", "strings", "size", "datarefs"])
        for r in csv.DictReader(f):
            va_s = (r.get("va") or "").strip()
            try:
                va = int(va_s, 16)
            except ValueError:
                continue
            vl = va_s.lower()
            strings = (r.get("strings") or "").strip()
            size = (r.get("size") or "").strip()
            dcount = len([x for x in (r.get("datarefs") or "").split("|") if x])
            if vl in user_name:
                label, source = user_name[vl], "named"; named += 1
            elif va in va2name:
                label, source = va2name[va], "named"; named += 1
            elif vl in obs_label:
                label, source = obs_label[vl], "observed"; observed += 1
            elif vl in xver:
                label, source = xver[vl]["label"], xver[vl].get("source", "engine"); engine += 1
            elif strings:
                label, source = strings.split("|")[0][:48], "inferred"; inferred += 1
            else:
                label = "FUN_" + (va_s[2:] if va_s.lower().startswith("0x") else va_s)
                source = "unlabeled"; unlabeled += 1
            xe = xver.get(vl)
            cat = (xe.get("category", "") if xe else "")
            pur = (xe.get("purpose", "") if xe else "")
            w.writerow([va_s, label, source, cat, pur[:200], strings[:300], size, dcount])
            total += 1

    print("function catalog: %d total | %d named | %d observed | %d engine(rtti/vtable/ai/carried) | %d inferred | %d unlabeled -> %s"
          % (total, named, observed, engine, inferred, unlabeled, OUT))


if __name__ == "__main__":
    main()
