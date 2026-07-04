#!/usr/bin/env python3
"""
crossversion_db.py -- the self-sufficiency core of the MMOPlugins engine.

A function's masked byte signature is stable across EQ patches even though its address moves.
This script keys every labelled function by (signature, size) into a durable knowledge base
(kb.json) so that names/classes/categories learned on one client version are AUTOMATICALLY
carried forward to every future version by signature match -- you never re-label the same
function twice, and patch-day relabelling approaches 100%.

It fuses labels from all sources (priority high -> low):
    admin   human-assigned names (funccat_observed.json -> names{})
    rtti    Ghidra RTTI class + (demangled) method name        (deep/classes.json)
    vtable  ClassName::vfN from a recovered vftable slot        (deep/vtables.json)
    observed MQ2FuncCat runtime class::vfN                       (funccat_observed.json)
    ai      Claude-proposed name, gated by confidence           (ai_names.json)

Per run it:
  1. reads the current version's functions.csv (va,sig,size,...),
  2. builds a label map for the current VAs from every source,
  3. updates kb.json (sig-keyed) with those labels (best source wins),
  4. CARRIES FORWARD: any current VA with no fresh label whose signature is already
     labelled in the kb inherits that label,
  5. writes crossversion_labels.json (va -> {label,category,source,confidence}) for
     build_funcatalog.py to overlay, and prints a carry-forward report.

    python crossversion_db.py [label]     (label defaults to the newest versions/ dir)
Paths default to the VPS layout; override via the constants below.
"""
import os, re, csv, json, hashlib, sys, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jsonstore   # crash-safe atomic writes + fail-loud loads (protects kb.json)

TOOLKIT = r"C:\EQMQ\02-offset-toolkit"
MMO     = r"C:\mmoplugins"
DEEP    = os.path.join(MMO, "deep")
KB      = os.path.join(MMO, "kb.json")
OUT     = os.path.join(MMO, "crossversion_labels.json")
OBS     = os.path.join(MMO, "funccat_observed.json")
AINAMES = os.path.join(MMO, "ai_names.json")
_AI_META = {}   # va(lower) -> {category, purpose} from ai_names, used to keep the AI's own typing

# source priority: a higher number overwrites a lower one when both label the same function
PRIORITY = {"admin": 100, "rtti": 80, "vtable": 60, "observed": 50, "ai": 40, "inferred": 10}

def usable(sig):
    return bool(sig) and (len(sig) - sig.count("?")) // 2 >= 8

def sigkey(sig, size):
    return hashlib.sha1(("%s|%s" % (sig, size)).encode()).hexdigest()

def load_json(p, default):
    try: return json.load(open(p, encoding="utf-8"))
    except Exception: return default

def newest_label():
    vers = sorted(glob.glob(os.path.join(TOOLKIT, "versions", "*")), key=os.path.getmtime, reverse=True)
    for v in vers:
        if os.path.isfile(os.path.join(v, "functions.csv")):
            return os.path.basename(v)
    return "jun24"

def is_placeholder(name):
    return (not name) or bool(re.match(r"^(FUN_|LAB_|SUB_|thunk_FUN_)", name or ""))

def category_of(label):
    # light reuse of the site's classify() keyword buckets so carried labels get a category
    s = (label or "").lower()
    if any(k in s for k in ("useskill","doattack","kick","backstab","melee","combatability","skill","taunt")): return "Combat, Skills & Casting"
    if any(k in s for k in ("castspell","spellmgr","spellbook","casting","spell","cast","buff")): return "Spells & Casting"
    if any(k in s for k in ("altadv","altabil","alternate")): return "Alternate Advancement (AA)"
    if any(k in s for k in ("item","inventory","container","merchant","loot","equip","bag","augment")): return "Items & Inventory"
    if any(k in s for k in ("wnd","window","sidl","cxwnd","screen","button")): return "UI / Windows"
    if any(k in s for k in ("spawn","actor","playermanager","player")): return "Spawns & Actors"
    if any(k in s for k in ("everquest","zone","world","gamestate")): return "Core Game"
    if any(k in s for k in ("pc","character","profile","bank","guild")): return "Character & Profile"
    return "Other / Unclassified"

def cat_for(va, src, label):
    # prefer the AI's own category for AI-sourced labels; fall back to keyword classify
    if src and src.startswith("ai"):
        m = _AI_META.get((va or "").lower())
        if m:
            c = (m.get("category") or "").strip()
            if c and c != "Other / Unclassified":
                return c
    return category_of(label)

def purpose_for(va, src):
    if src and src.startswith("ai"):
        m = _AI_META.get((va or "").lower())
        if m: return (m.get("purpose") or "")
    return ""

def build_label_sources():
    """va(lower) -> list of (priority_source, label, confidence) for the current version."""
    out = {}
    def add(va, src, label, conf=1.0):
        if not va or not label: return
        va = va.lower()
        out.setdefault(va, []).append((src, label, conf))

    # rtti classes  (deep/classes.json:  "Class::Name": [{va,name}, ...])
    classes = load_json(os.path.join(DEEP, "classes.json"), {})
    for cls, methods in classes.items():
        for m in (methods or []):
            nm = m.get("name", "")
            label = cls if is_placeholder(nm) else (cls + "::" + nm if "::" not in nm else nm)
            add(m.get("va", ""), "rtti", label)

    # vtables  (deep/vtables.json: [{class,va,methods:[funcVA,...]}])
    for vt in load_json(os.path.join(DEEP, "vtables.json"), []):
        cls = vt.get("class") or ""
        if not cls: continue
        for i, mva in enumerate(vt.get("methods", [])):
            add(mva, "vtable", "%s::vf%d" % (cls, i))

    # observed + admin (funccat_observed.json: functions{va:{class,index}}, names{va:str})
    obs = load_json(OBS, {})
    for va, e in (obs.get("functions") or {}).items():
        cls = e.get("class") or ""
        idx = e.get("index", -1)
        if cls:
            add(va, "observed", "%s::vf%s" % (cls, idx) if idx is not None and idx >= 0 else cls)
    for va, nm in (obs.get("names") or {}).items():
        add(va, "admin", nm)

    # ai names (ai_names.json: {va: {name, category, purpose, confidence}})
    for va, e in load_json(AINAMES, {}).items():
        nm = e.get("name") or ""
        _AI_META[(va or "").lower()] = {"category": e.get("category", ""), "purpose": e.get("purpose", "")}
        if nm:
            add(va, "ai", nm, float(e.get("confidence", 0.0) or 0.0))
    return out

def best(sources):
    """pick the highest-priority label among a function's sources."""
    best_src = best_label = None; best_conf = 0.0; best_pri = -1
    for src, label, conf in sources:
        pri = PRIORITY.get(src, 0)
        if pri > best_pri or (pri == best_pri and conf > best_conf):
            best_pri, best_src, best_label, best_conf = pri, src, label, conf
    return best_src, best_label, best_conf

def main():
    ver = sys.argv[1] if len(sys.argv) > 1 else newest_label()
    funcs_csv = os.path.join(TOOLKIT, "versions", ver, "functions.csv")
    if not os.path.exists(funcs_csv):
        print("crossversion_db: no functions.csv for version %r at %s" % (ver, funcs_csv)); return

    # fail-loud load: a corrupt kb.json is healed from kb.json.bak, or aborts the run --
    # NEVER silently reseeds empty (which the old load_json swallow-and-default did).
    kb = jsonstore.safe_load(KB, default={"version": 1, "entries": {}})
    entries = kb.setdefault("entries", {})
    lab_src = build_label_sources()

    cur = {}          # va(lower) -> sigkey (or None if signature not usable)
    rows = 0
    for r in csv.DictReader(open(funcs_csv, encoding="utf-8", errors="replace", newline="")):
        va = (r.get("va") or "").strip().lower()
        if not va: continue
        rows += 1
        cur[va] = sigkey(r.get("sig", ""), r.get("size", "")) if usable(r.get("sig", "")) else None

    # 1) write fresh labels into the kb (best source per VA), keyed by signature
    learned = 0
    for va, key in cur.items():
        if not key or va not in lab_src:
            continue
        src, flabel, conf = best(lab_src[va])
        if not flabel:
            continue
        e = entries.get(key)
        if e is None or PRIORITY.get(src, 0) >= PRIORITY.get(e.get("source", "inferred"), 0):
            entries[key] = {"label": flabel, "category": cat_for(va, src, flabel),
                            "purpose": purpose_for(va, src),
                            "source": src, "confidence": round(conf, 3),
                            "first_version": (e or {}).get("first_version") or ver,
                            "last_version": ver}
            learned += 1

    # 2) produce current-version labels: fresh OR carried-forward by signature
    out = {}
    fresh = carried = 0
    for va, key in cur.items():
        if va in lab_src:
            src, flabel, conf = best(lab_src[va])
            if flabel:
                out[va] = {"label": flabel, "category": cat_for(va, src, flabel),
                           "purpose": purpose_for(va, src),
                           "source": src, "confidence": round(conf, 3)}
                fresh += 1
                continue
        if key and key in entries:
            e = entries[key]
            out[va] = {"label": e["label"], "category": e["category"],
                       "purpose": e.get("purpose", ""),
                       "source": e["source"] + "+carried", "confidence": e.get("confidence", 0.0)}
            carried += 1

    # atomic writes (temp + os.replace, prior kept as .bak). kb.json is guarded so a bug
    # that produced an EMPTY kb can never overwrite the accumulated cross-version knowledge.
    jsonstore.atomic_dump(out, OUT, indent=1)
    jsonstore.dump_guarded(kb, KB, lambda k: len(k.get("entries", {})), indent=1)
    print("crossversion_db: version=%s funcs=%d | kb_entries=%d learned=%d | labels fresh=%d carried-forward=%d -> %s"
          % (ver, rows, len(entries), learned, fresh, carried, OUT))

if __name__ == "__main__":
    main()
