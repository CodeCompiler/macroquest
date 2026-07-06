#!/usr/bin/env python3
"""
build_structheaders.py -- turn structures.json into a downloadable C++ header for plugin devs.

structures.json holds, per struct/class: kind, bases, source file, the C++ `code` block,
field count, and (often) size. Two tiers come out:

  eqstructs_layouts.h  -- the GHIDRA-recovered layouts (real client offsets). These are
                          self-contained: with the stdint typedef preamble below they COMPILE,
                          and each gets a static_assert(sizeof==size) so a drifted struct fails
                          the build loudly. This is the useful, verifiable artifact.
  eqstructs_full.h     -- everything (eqlib-header structs + Ghidra), concatenated and indexed,
                          as a single grep-able typed reference. eqlib-sourced blocks reference
                          the wider eqlib tree so they're reference, not standalone-compilable.

Run:  python build_structheaders.py    (reads C:\\mmoplugins\\structures.json)
"""
import os, sys, re, json, shutil, tempfile
_HERE = os.path.dirname(os.path.abspath(__file__))
# jsonstore.py lives in offset-toolkit/ in the source tree but is deployed FLAT next to this script
# in C:\mmoplugins. Put both on the path so `import jsonstore` resolves either way.
sys.path.insert(0, os.path.join(_HERE, "..", "offset-toolkit"))
sys.path.insert(0, _HERE)
import jsonstore

# Portability: the catalog root is deployment-relative, not a fixed C: path. Honor an env override
# so the emitter runs unchanged on the VPS and on a dev box.
MMO = os.environ.get("EQMQ_MMO") or r"C:\mmoplugins"
SRC = os.path.join(MMO, "structures.json")
OUT_LAYOUTS = os.path.join(MMO, "eqstructs_layouts.h")
OUT_FULL    = os.path.join(MMO, "eqstructs_full.h")

# Ghidra's DataTypeManager emits pseudo-types; map the common ones to real widths. The FIELD
# OFFSETS in these layouts are exact (recovered from the live client); the field TYPES are
# best-effort (Ghidra's inference), so treat this as a precise offset reference, not gospel types.
PREAMBLE = """// eqstructs -- recovered EverQuest client structure layouts (MMOPlugins).
// Auto-generated from Ghidra DataTypeManager + eqlib headers. The FIELD OFFSETS (/* +0xNN */)
// are the REAL client layout for the catalogued build and are exact; field TYPES are Ghidra's
// best-effort inference (some are approximate). Use this as an offset reference for plugin dev.
// Do not hand-edit; regenerate with build_structheaders.py.
#pragma once
#include <cstdint>

// --- shims for Ghidra's pseudo-types so these layouts parse as C++ ---
typedef uint8_t   undefined;   typedef uint8_t  undefined1; typedef uint16_t undefined2;
typedef uint32_t  undefined4;  typedef uint64_t undefined8; typedef uint32_t undefined3;
typedef uint8_t   byte;   typedef uint8_t  uchar;  typedef uint16_t ushort;  typedef uint16_t wchar;
typedef uint16_t  word;   typedef uint32_t dword;  typedef uint64_t qword;   typedef uint32_t uint;
typedef uint64_t  ulonglong; typedef int64_t longlong; typedef uint64_t pointer;
typedef char      string;   typedef uint8_t  GUID[16]; typedef void code;   // approximations
"""


# Ghidra writes pointer width as `type *64` / `*32`; normalize to plain C++ `type*`.
_PTRW = re.compile(r"\s*\*\s*(?:8|16|32|64)\b")

def sanitize(code):
    """Best-effort cleanup of Ghidra field-type quirks so the block parses as C++.
    Keeps every offset/field name; only touches the type spelling."""
    return _PTRW.sub("*", code)


def _size_int(s):
    if isinstance(s, int): return s
    if isinstance(s, str) and s:
        try: return int(s, 16) if s.lower().startswith("0x") else int(s)
        except Exception: return None
    return None


def _atomic_write_text(path, text):
    """Crash-safe text write for the generated headers: temp-file + fsync + os.replace, keeping the
    prior header at path + '.bak'. Mirrors jsonstore.atomic_dump so a crash / power-loss mid-write
    can never leave a truncated eqstructs_*.h (which a plugin dev would #include)."""
    path = os.path.abspath(path)
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    if os.path.exists(path):
        try: shutil.copy2(path, path + ".bak")
        except Exception: pass
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path); tmp = None
    finally:
        if tmp and os.path.exists(tmp):
            try: os.remove(tmp)
            except Exception: pass


def main():
    data = jsonstore.safe_load(SRC, default={"structs": {}})
    structs = data.get("structs", {})
    ghidra, eqlib = [], []
    for name, e in structs.items():
        (ghidra if (e.get("source") == "ghidra" or "Ghidra" in (e.get("file") or "")) else eqlib).append((name, e))
    ghidra.sort(key=lambda kv: kv[0]); eqlib.sort(key=lambda kv: kv[0])

    # --- tier 1: the recovered Ghidra layouts (exact offsets, sanitized types) ---
    L = [PREAMBLE, "", "// ================= %d recovered client layouts =================" % len(ghidra), ""]
    for name, e in ghidra:
        code = sanitize((e.get("code") or "").rstrip())
        if not code: continue
        L.append(code if code.endswith(";") else code + ";")
        # DRIFT DETECTION: assert the recovered size so a struct whose layout CHANGED on patch day
        # fails the plugin build loudly instead of compiling with silently-wrong offsets.
        sz = _size_int(e.get("size"))
        if sz and re.match(r"^[A-Za-z_]\w*$", name):
            L.append('#ifndef EQSTRUCTS_NO_DRIFT_CHECK')
            L.append('static_assert(sizeof(%s) == 0x%X, "%s size drifted from catalogued 0x%X");'
                     % (name, sz, name, sz))
            L.append('#endif')
        L.append("")
    _atomic_write_text(OUT_LAYOUTS, "\n".join(L))   # crash-safe: temp + fsync + os.replace (+ .bak)

    # --- tier 2: full indexed reference (eqlib + ghidra) ---
    F = ["// eqstructs_full -- ALL %d recovered structures/classes (reference).\n// eqlib-sourced blocks reference the wider eqlib tree (not standalone-compilable);\n// Ghidra layouts are self-contained (see eqstructs_layouts.h for the compilable tier).\n#pragma once\n" % len(structs)]
    F.append("/* ===== INDEX (%d structs; %d from eqlib headers, %d Ghidra layouts) =====" % (len(structs), len(eqlib), len(ghidra)))
    for name, e in sorted(structs.items()):
        sz = _size_int(e.get("size"))
        F.append("   %-52s size=%-8s fields=%-4s  %s" % (name, ("0x%X" % sz) if sz else "?", e.get("fields", "?"), e.get("file", "")))
    F.append(" */\n")
    for name, e in sorted(structs.items()):
        code = sanitize((e.get("code") or "").rstrip())
        if not code: continue
        sz = _size_int(e.get("size"))
        F.append("// ---- %s%s  (%s) ----" % (name, ("  size 0x%X" % sz) if sz else "", e.get("file", "")))
        F.append(code if code.endswith(";") else code + ";")
        F.append("")
    _atomic_write_text(OUT_FULL, "\n".join(F))   # crash-safe: temp + fsync + os.replace (+ .bak)

    print("structheaders: %d structs (%d ghidra layouts) -> %s (%d KB) + %s (%d KB)"
          % (len(structs), len(ghidra),
             os.path.basename(OUT_LAYOUTS), os.path.getsize(OUT_LAYOUTS) // 1024,
             os.path.basename(OUT_FULL), os.path.getsize(OUT_FULL) // 1024))


if __name__ == "__main__":
    main()
