#!/usr/bin/env python3
# build_structs.py -- extract EVERY struct/class definition from the eqlib headers (name, base classes,
# size, and the full C++ source block = "the structure + the code for it") -> structures.json.
# This is the structure side of the catalog; functions are in function_catalog.csv.
import os, re, json

INC  = r"C:\MQ2\macroquest\src\eqlib\include\eqlib"
OUT  = r"C:\mmoplugins\structures.json"
DEEP = r"C:\mmoplugins\deep\structs.json"   # Ghidra DataTypeManager export (real client layouts)

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
    deep_added = 0
    try:
        deep = json.load(open(DEEP, encoding="utf-8"))
    except Exception:
        deep = {}
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

    json.dump({"structs": structs, "count": len(structs)}, open(OUT, "w", encoding="utf-8"))
    sized = sum(1 for e in structs.values() if e.get("size"))
    print("structures: %d total (%d from eqlib headers + %d from Ghidra DataTypeManager), %d with known size -> %s"
          % (len(structs), len(structs) - deep_added, deep_added, sized, OUT))

if __name__ == "__main__":
    main()
