#!/usr/bin/env python3
"""
superbaseline.py  --  persistent offset-fingerprint DB + relocator for MacroQuest.

This is the "v2" of the offset pipeline. Instead of diffing the immediately-prior
binary against the new one, it accumulates a PERSISTENT fingerprint database
(baseline_db.json) keyed by offset NAME. Once an offset is fingerprinted, you can
relocate it in ANY future client purely from the DB -- no need to keep the previous
binary around.

How offsets are fingerprinted:
  * FUNCTION offsets  -> the (stable, unique) set of string literals the function
                         references. Across patches the address moves but the
                         string-set is constant, so it relocates by string-set.
  * DATA/GLOBAL offsets -> identified indirectly by WHICH functions reference them
                         and at WHICH position (index) in that function's ordered
                         dataref list. We store several such (function-stringset, idx)
                         anchors; at relocate time we re-resolve each anchor and take
                         the consensus. This is HEURISTIC and confidence-rated.

Commands:
    python superbaseline.py seed     <label>
    python superbaseline.py relocate <label>

IMPORTANT (seeding):
    `seed <label>` extracts fingerprints by PAIRING the VAs currently in eqgame.h
    with the functions/data in the export for <label>. Therefore eqgame.h MUST
    currently hold the offsets for the SAME client version as <label>. If eqgame.h
    is stale/mismatched, the fingerprints will be garbage. Re-seed after every
    verified offset update so the DB accumulates corroborating fingerprints and
    gets stronger over time.

Outputs (relocate):
    out\\eqgame_relocated.h   -- eqgame.h copy with matched VAs replaced (review!)
    out\\coverage_report.csv  -- name, old_va, new_va, kind, confidence

PATHS ARE NOT HARD-CODED HERE -- resolved by eqmq_paths.py (env -> eqmq.config.ini
-> auto-detect). Run `python eqmq_paths.py check`.
"""

import os, sys, json, csv, re
import eqmq_paths as P

DB_PATH = P.DB_PATH

DEFINE_RE = re.compile(r'^(#define\s+)(\S+)(\s+)(0x[0-9A-Fa-f]+)(.*)$')

MAX_ANCHORS = 8  # cap data-offset anchors per offset


def vahex(n):
    """Emit VA as 0x + UPPERCASE hex."""
    return "0x%X" % n


def parse_va(s):
    return int(s, 16)


# ----------------------------------------------------------------------------- loaders
def load_export(label):
    """Read versions\\<label>\\functions.csv -> list of dicts.
    Each dict: {va:int, name:str, strings:str, datarefs:[int,...]}."""
    path = os.path.join(P.VERSIONS, label, "functions.csv")
    if not os.path.exists(path):
        print("[error] export not found: %s" % path)
        print("        run:  python offsettool.py snapshot %s" % label)
        sys.exit(2)
    rows = []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for r in csv.DictReader(f):
            va_s = (r.get("va") or "").strip()
            if not va_s:
                continue
            try:
                va = parse_va(va_s)
            except ValueError:
                continue
            strings = (r.get("strings") or "").strip()
            sig = (r.get("sig") or "").strip()
            datarefs_s = (r.get("datarefs") or "").strip()
            datarefs = []
            if datarefs_s:
                for d in datarefs_s.split("|"):
                    d = d.strip()
                    if not d:
                        continue
                    try:
                        datarefs.append(parse_va(d))
                    except ValueError:
                        pass
            rows.append({"va": va, "name": r.get("name", ""),
                         "strings": strings, "sig": sig, "datarefs": datarefs})
    return rows


# A signature is only a useful anchor if it has enough CONCRETE (non-wildcard) bytes;
# otherwise it's too generic and would collide. Each concrete byte = 2 hex chars.
MIN_SIG_CONCRETE_BYTES = 8

def sig_is_usable(sig):
    if not sig:
        return False
    concrete = (len(sig) - sig.count("?")) // 2
    return concrete >= MIN_SIG_CONCRETE_BYTES


def parse_eqgame_h():
    """Return list of (name, oldVA_int) for every #define offset line."""
    if not P.require("EQGAME_H"):
        sys.exit(2)
    out = []
    with open(P.EQGAME_H, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = DEFINE_RE.match(line.rstrip("\n"))
            if not m:
                continue
            out.append((m.group(2), parse_va(m.group(4))))
    return out


def stringset_list(strings_field):
    """Split a 'strings' field into an ordered list of non-empty members.
    The members come from ghidra_export sorted, so order is canonical."""
    if not strings_field:
        return []
    return [s for s in strings_field.split("|") if s]


def stringset_key(members):
    """Canonical hashable key for a string-set (sorted, '|'-joined)."""
    return "|".join(sorted(members))


# ----------------------------------------------------------------------------- DB
def load_db():
    if os.path.exists(DB_PATH):
        with open(DB_PATH, encoding="utf-8") as f:
            db = json.load(f)
    else:
        db = {}
    db.setdefault("offsets", {})
    db.setdefault("versions_seeded", [])
    return db


def save_db(db):
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


# ----------------------------------------------------------------------------- seed
def seed(label):
    rows = load_export(label)

    # (a) func_by_va : {va_int: stringset members list}
    # (b) sig_by_va  : {va_int: masked byte signature}
    # (c) data_xref  : {data_va_int: [ (func_stringset_members, func_sig, index), ... ]}
    func_by_va = {}
    sig_by_va = {}
    data_xref = {}
    for row in rows:
        members = stringset_list(row["strings"])
        func_by_va[row["va"]] = members
        sig_by_va[row["va"]] = row.get("sig", "")
        fsig = row.get("sig", "")
        for idx, dva in enumerate(row["datarefs"]):
            data_xref.setdefault(dva, []).append((members, fsig, idx))

    pairs = parse_eqgame_h()
    db = load_db()
    offsets = db["offsets"]

    seeded = {"func": 0, "data": 0, "unknown": 0}

    def add_anchor(entry, anchor):
        """Add anchor to entry['anchors'] if not already present (dedupe)."""
        for existing in entry["anchors"]:
            if existing == anchor:
                return False
        entry["anchors"].append(anchor)
        return True

    def add_sig(entry, sig):
        entry.setdefault("sigs", [])
        if sig and sig_is_usable(sig) and sig not in entry["sigs"]:
            entry["sigs"].append(sig)

    for name, oldVA in pairs:
        if oldVA in func_by_va:
            members = func_by_va[oldVA]
            anchor = sorted(members)  # store as list of strings
            entry = offsets.get(name)
            if entry is None or entry.get("kind") != "func":
                entry = {"kind": "func", "anchors": [], "sigs": []}
                offsets[name] = entry
            # string anchor (only ~17% of funcs have one) ...
            if anchor:
                add_anchor(entry, anchor)
            # ... plus a masked byte signature (covers the rest)
            add_sig(entry, sig_by_va.get(oldVA, ""))
            seeded["func"] += 1
        elif oldVA in data_xref:
            entry = offsets.get(name)
            if entry is None or entry.get("kind") != "data":
                entry = {"kind": "data", "anchors": []}
                offsets[name] = entry
            added = 0
            for members, fsig, idx in data_xref[oldVA]:
                has_str = bool(members)
                has_sig = sig_is_usable(fsig)
                if not has_str and not has_sig:
                    continue  # referencing function has no usable anchor at all
                anchor = {"fstrings": sorted(members) if has_str else [],
                          "fsig": fsig if has_sig else "",
                          "idx": idx}
                add_anchor(entry, anchor)
                added += 1
                if added >= MAX_ANCHORS:
                    break
            seeded["data"] += 1
        else:
            entry = offsets.get(name)
            if entry is None:
                offsets[name] = {"kind": "unknown", "anchors": []}
            seeded["unknown"] += 1

    if label not in db["versions_seeded"]:
        db["versions_seeded"].append(label)
    save_db(db)

    print("[seed] label=%s  paired %d eqgame.h offsets against export" %
          (label, len(pairs)))
    print("[seed]   func    : %d" % seeded["func"])
    print("[seed]   data    : %d" % seeded["data"])
    print("[seed]   unknown : %d" % seeded["unknown"])
    print("[seed] DB now tracks %d offset names across versions %s" %
          (len(offsets), db["versions_seeded"]))
    print("[seed] saved -> %s" % DB_PATH)


# ----------------------------------------------------------------------------- relocate
def build_new_indexes(rows):
    """Return:
        unique_ss_to_va  : {stringset_key: va}  for stringsets UNIQUE in new binary
        unique_sig_to_va : {sig: va}            for signatures UNIQUE+usable in new binary
        va_to_datarefs   : {va: [data_va_ints]}
    """
    ss_counts, ss_to_va = {}, {}
    sig_counts, sig_to_va = {}, {}
    va_to_datarefs = {}
    for row in rows:
        va_to_datarefs[row["va"]] = row["datarefs"]
        members = stringset_list(row["strings"])
        if members:
            key = stringset_key(members)
            ss_counts[key] = ss_counts.get(key, 0) + 1
            ss_to_va[key] = row["va"]
        sig = row.get("sig", "")
        if sig_is_usable(sig):
            sig_counts[sig] = sig_counts.get(sig, 0) + 1
            sig_to_va[sig] = row["va"]
    unique_ss_to_va = {k: v for k, v in ss_to_va.items() if ss_counts[k] == 1}
    unique_sig_to_va = {k: v for k, v in sig_to_va.items() if sig_counts[k] == 1}
    return unique_ss_to_va, unique_sig_to_va, va_to_datarefs


def locate_func(entry_sigs, entry_string_anchors, unique_sig_to_va, unique_ss_to_va):
    """Resolve a seeded function's NEW va, trying its byte signature(s) first (most
    discriminating, ~83% of funcs), then falling back to string-set anchor(s).
    Returns (new_va_or_None, how)."""
    for sig in entry_sigs:
        if sig in unique_sig_to_va:
            return unique_sig_to_va[sig], "sig"
    for anchor in entry_string_anchors:   # anchor = list of strings
        key = stringset_key(anchor)
        if key in unique_ss_to_va:
            return unique_ss_to_va[key], "str"
    return None, ""


def relocate(label):
    rows = load_export(label)
    db = load_db()
    offsets = db["offsets"]
    if not offsets:
        print("[error] baseline_db.json has no offsets -- seed at least one version first.")
        sys.exit(2)

    unique_ss_to_va, unique_sig_to_va, va_to_datarefs = build_new_indexes(rows)

    # name -> (new_va_int_or_None, kind, confidence)
    results = {}
    n_func = 0
    n_data_high = 0
    n_data_med = 0
    n_unmatched = 0

    for name, entry in offsets.items():
        kind = entry.get("kind", "unknown")
        anchors = entry.get("anchors", [])
        new_va = None
        confidence = ""

        if kind == "func":
            new_va, _how = locate_func(entry.get("sigs", []), anchors,
                                       unique_sig_to_va, unique_ss_to_va)
            if new_va is not None:
                confidence = "high"
                n_func += 1
            else:
                n_unmatched += 1

        elif kind == "data":
            # Triangulate: resolve each referencing function (by its sig or string-set),
            # read the data VA at the stored index, and take the consensus across anchors.
            tally = {}
            for anchor in anchors:  # anchor = {"fstrings":[...], "fsig":str, "idx":int}
                idx = anchor.get("idx", -1)
                fva = None
                fsig = anchor.get("fsig", "")
                if fsig and fsig in unique_sig_to_va:
                    fva = unique_sig_to_va[fsig]
                else:
                    fkey = stringset_key(anchor.get("fstrings", []))
                    if anchor.get("fstrings") and fkey in unique_ss_to_va:
                        fva = unique_ss_to_va[fkey]
                if fva is None:
                    continue
                drefs = va_to_datarefs.get(fva, [])
                if 0 <= idx < len(drefs):
                    cand = drefs[idx]
                    tally[cand] = tally.get(cand, 0) + 1
            if tally:
                # pick most common candidate
                best = None
                best_n = 0
                for cand, n in tally.items():
                    if n > best_n:
                        best, best_n = cand, n
                new_va = best
                if best_n >= 2:
                    confidence = "high"
                    n_data_high += 1
                else:
                    confidence = "medium"
                    n_data_med += 1
            else:
                n_unmatched += 1
        else:
            n_unmatched += 1

        results[name] = (new_va, kind, confidence)

    # ---- emit out\eqgame_relocated.h
    os.makedirs(P.OUT, exist_ok=True)
    relocated_h = os.path.join(P.OUT, "eqgame_relocated.h")
    coverage_csv = os.path.join(P.OUT, "coverage_report.csv")

    total = 0
    with open(relocated_h, "w", encoding="utf-8") as outh, \
         open(coverage_csv, "w", encoding="utf-8", newline="") as repf:
        rw = csv.writer(repf)
        rw.writerow(["name", "old_va", "new_va", "kind", "confidence"])
        with open(P.EQGAME_H, encoding="utf-8", errors="replace") as src:
            for line in src:
                m = DEFINE_RE.match(line.rstrip("\n"))
                if not m:
                    outh.write(line)
                    continue
                name = m.group(2)
                old_va = parse_va(m.group(4))
                total += 1
                res = results.get(name)
                if res is None:
                    # offset in eqgame.h but not in DB at all
                    rw.writerow([name, vahex(old_va), "", "unknown", ""])
                    outh.write(line)
                    continue
                new_va, kind, confidence = res
                if new_va is not None:
                    outh.write("%s%s%s%s%s\n" %
                               (m.group(1), name, m.group(3), vahex(new_va), m.group(5)))
                    rw.writerow([name, vahex(old_va), vahex(new_va), kind, confidence])
                else:
                    outh.write(line)
                    rw.writerow([name, vahex(old_va), "", kind, confidence])

    print("[relocate] label=%s  total offsets in eqgame.h: %d" % (label, total))
    print("[relocate]   func matched           : %d" % n_func)
    print("[relocate]   data matched (high)    : %d" % n_data_high)
    print("[relocate]   data matched (medium)  : %d" % n_data_med)
    print("[relocate]   unmatched              : %d" % n_unmatched)
    print("[relocate] relocated header -> %s" % relocated_h)
    print("[relocate] coverage report  -> %s" % coverage_csv)
    print("[relocate] REVIEW every change and VERIFY in-game. Data/global UNMATCHED")
    print("           entries need Ghidra Version Tracking / x64dbg.")


# ----------------------------------------------------------------------------- main
def usage():
    print("usage:")
    print("  python superbaseline.py seed     <label>   "
          "(eqgame.h MUST match this client version)")
    print("  python superbaseline.py relocate <label>")
    sys.exit(1)


if __name__ == "__main__":
    os.makedirs(P.OUT, exist_ok=True)
    if len(sys.argv) != 3:
        usage()
    cmd = sys.argv[1].lower()
    label = sys.argv[2]
    if cmd == "seed":
        seed(label)
    elif cmd == "relocate":
        relocate(label)
    else:
        usage()
