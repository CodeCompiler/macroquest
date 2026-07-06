#!/usr/bin/env python3
# build_structs.py -- extract EVERY struct/class definition from the eqlib headers (name, base classes,
# size, and the full C++ source block = "the structure + the code for it") -> structures.json.
# This is the structure side of the catalog; functions are in function_catalog.csv.
import os, re, json, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "offset-toolkit"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jsonstore   # crash-safe atomic writes + fail-loud loads (protects structures.json)

# Portable roots: honor env overrides (set by the VPS deploy) and fall back to the historical
# hard-coded layout so existing installs keep working unchanged.
MQ_SRC = os.environ.get("EQMQ_MQ_SRC")  or r"C:\MQ2\macroquest"
MMO    = os.environ.get("EQMQ_MMO_DIR") or r"C:\mmoplugins"
INC  = os.environ.get("EQMQ_EQLIB_INC") or os.path.join(MQ_SRC, "src", "eqlib", "include", "eqlib")
OUT  = os.path.join(MMO, "structures.json")
DEEP = os.path.join(MMO, "deep", "structs.json")   # Ghidra DataTypeManager export (real client layouts)

DROP_ALARM = 0.15   # warn if >15% fewer structs than the last good catalog (EQMQ_ALLOW_SHRINK=1 silences)

SIZE_RE = re.compile(r'(?:constexpr\s+size_t\s+|#\s*define\s+)([A-Za-z_]\w*?)_size\s*(?:=\s*|\s+)(0x[0-9A-Fa-f]+|\d+)')
# struct/class <Name> [: bases] {   (skip forward-decls which end in ; before {)
DEF_RE = re.compile(r'\b(struct|class)\s+(?:EQLIB_OBJECT\s+|alignas\([^)]*\)\s+)*([A-Za-z_]\w*)\b([^{;}]*)\{')

def brace_block(txt, brace_pos):
    depth = 0
    i = brace_pos
    n = len(txt)
    while i < n:
        ch = txt[i]
        if ch == '{': depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1

def main():
    sizes = {}
    structs = {}
    for root, _d, files in os.walk(INC):
        for fn in files:
            if not fn.lower().endswith((".h", ".hpp")):
                continue
            try:
                txt = open(os.path.join(root, fn), encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            for m in SIZE_RE.finditer(txt):
                sizes[m.group(1)] = m.group(2)
            for m in DEF_RE.finditer(txt):
                kind, name, bases = m.group(1), m.group(2), (m.group(3) or "").strip()
                bpos = txt.find('{', m.start())
                if bpos < 0:
                    continue
                end = brace_block(txt, bpos)
                if end < 0:
                    continue
                body = txt[m.start():end + 1]
                if len(body) < 12 or "{" not in body:
                    continue
                # prefer the largest/most complete definition if a name appears twice
                if name in structs and len(structs[name]["code"]) >= len(body):
                    continue
                code = body if len(body) <= 24000 else body[:24000] + "\n    /* ... truncated ... */\n};"
                # rough member-field count (lines that look like "Type name;")
                fields = len(re.findall(r'^\s*[A-Za-z_][\w:<>\*&,\s]*\s+[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*;', body, re.M))
                structs[name] = {"kind": kind, "bases": bases, "file": fn, "code": code, "fields": fields}
    for name, e in structs.items():
        if name in sizes:
            e["size"] = sizes[name]

    # merge Ghidra DataTypeManager structs -- the client's REAL layouts, including the
    # macro-defined core classes (CXWnd/CEverQuest/ItemClient...) the header regex can't capture.
    # FAIL LOUD: a missing/corrupt/empty deep export means the Ghidra step failed. Do NOT silently
    # degrade to a headers-only catalog (that would drop every recovered client layout). Abort instead
    # -- the previous structures.json is left intact for carry-forward on the next good run.
    deep_added = 0
    allow_no_deep = os.environ.get("EQMQ_ALLOW_NO_DEEP") == "1"
    if not os.path.exists(DEEP):
        if not allow_no_deep:
            raise RuntimeError(
                "build_structs: Ghidra deep export missing (%s). The deep static-export step likely "
                "failed -- refusing to rebuild structures.json without the recovered client layouts "
                "(would silently drop CXWnd/CEverQuest/ItemClient/...). Set EQMQ_ALLOW_NO_DEEP=1 to "
                "build a headers-only catalog on purpose." % DEEP)
        print("build_structs: WARNING: no Ghidra deep export (%s) and EQMQ_ALLOW_NO_DEEP=1 -- headers "
              "only; prior client layouts will be carried forward if a catalog exists." % DEEP)
        deep = {}
    else:
        try:
            deep = json.load(open(DEEP, encoding="utf-8"))
        except Exception as ex:
            raise RuntimeError(
                "build_structs: Ghidra deep export %s is corrupt (%s) -- refusing to rebuild from a "
                "broken analysis. Previous structures.json left intact." % (DEEP, ex)) from ex
        if not isinstance(deep, dict) or (not deep and not allow_no_deep):
            raise RuntimeError(
                "build_structs: Ghidra deep export %s parsed but contains ZERO structs -- treating as a "
                "failed analysis (fail loud). Set EQMQ_ALLOW_NO_DEEP=1 to override." % DEEP)
    for name, d in deep.items():
        if not name or name in structs:          # eqlib header definition wins when both exist
            continue
        flds = d.get("fields", []) or []
        # skip compiler/runtime boilerplate Ghidra's DataTypeManager carries (lambdas, Windows
        # handle wrappers like HDC__, single-field shims) -- keep only real multi-field layouts.
        if "<" in name or re.match(r"^H[A-Z0-9]*__$", name) or len(flds) < 2:
            continue
        size_hex = ("0x%X" % d["size"]) if isinstance(d.get("size"), int) and d["size"] > 0 else (d.get("size") or "")
        lines = ["// recovered from the client binary by Ghidra's DataTypeManager (real layout)",
                 "struct %s {%s" % (name, ("  // size %s" % size_hex if size_hex else ""))]
        for fc in flds[:4000]:
            off = fc.get("off", 0)
            fn = fc.get("name") or ("field_0x%X" % off if isinstance(off, int) else "field")
            tn = fc.get("type") or "undefined"
            lines.append("    /* +0x%03X */ %s %s;" % (off if isinstance(off, int) else 0, tn, fn))
        lines.append("};")
        structs[name] = {"kind": "class", "bases": "", "file": "Ghidra DataTypeManager",
                         "code": "\n".join(lines), "fields": len(flds),
                         "size": size_hex, "source": "ghidra"}
        deep_added += 1

    # CARRY-FORWARD: if this run recovered NO Ghidra layouts (missing/corrupt deep export -> deep={}
    # above) or dropped a struct it had last build, keep the last-known-good layout from the prior
    # structures.json (marked stale) rather than letting it vanish -- like kb.json does for function
    # labels. A real removal only sticks after a clean, populated capture.
    prior = jsonstore.safe_load(OUT, default={"structs": {}})
    prior_structs = prior.get("structs", {}) if isinstance(prior, dict) else {}
    carried = 0
    for name, pe in prior_structs.items():
        if name not in structs and pe.get("source") == "ghidra":
            pe = dict(pe); pe["stale"] = True
            structs[name] = pe; carried += 1
    if deep_added == 0:
        print("structures: WARNING -- 0 Ghidra layouts this run (deep/structs.json missing or empty?); "
              "carried %d prior layout(s) forward." % carried)
    # SANITY: alarm on a sharp drop vs the last good catalog (a partial analysis, not a real patch).
    if prior_structs and len(structs) < len(prior_structs) * (1 - DROP_ALARM) \
            and os.environ.get("EQMQ_ALLOW_SHRINK") != "1":
        print("structures: WARNING -- catalog shrank from %d to %d structs (>%.0f%%). Possible bad "
              "capture; set EQMQ_ALLOW_SHRINK=1 to silence." % (len(prior_structs), len(structs), DROP_ALARM * 100))
    # atomic + empty-guarded write: a partial run must never overwrite a populated catalog.
    jsonstore.dump_guarded({"structs": structs, "count": len(structs)}, OUT,
                           lambda o: len(o.get("structs", {})))
    sized = sum(1 for e in structs.values() if e.get("size"))
    print("structures: %d total (%d from eqlib headers + %d from Ghidra DataTypeManager), %d with known size, %d carried -> %s"
          % (len(structs), len(structs) - deep_added - carried, deep_added, sized, carried, OUT))

if __name__ == "__main__":
    main()
