#!/usr/bin/env python3
"""
build_macros.py -- scan the bundled MacroQuest macro + lua tree and emit macros.json for the
MMOPlugins "Macros" tab. Each macro/lua/include becomes a catalog entry with: a category, a
description, original author credits, usage, required plugins, referenced events/commands, and
its source path (served on demand + downloadable, with character names scrubbed at display time).

    python build_macros.py [libDir] [outJson]
libDir must contain  macros\\  (.mac/.inc) and  lua\\  (.lua) subfolders.
Defaults: C:\\mmoplugins\\macrolib  ->  C:\\mmoplugins\\macros.json
(Locally, pass the build tree:  python build_macros.py C:\\MQ2\\macroquest\\build\\bin\\release ...)

macros.json schema:
  { "generated": <epoch>,
    "roots": {"macros": "<abs>", "lua": "<abs>"},     # resolved on the build box; the app re-resolves
    "macros": [ {slug,name,base,type,category,desc,usage[],authors[],required[],
                 includes[],events[],commands[],loc,rootkey,path} ] }
"""
import os, re, json, sys, time

REL  = sys.argv[1] if len(sys.argv) > 1 else r"C:\mmoplugins\macrolib"
OUT  = sys.argv[2] if len(sys.argv) > 2 else r"C:\mmoplugins\macros.json"
MAC_ROOT = os.path.join(REL, "macros")
LUA_ROOT = os.path.join(REL, "lua")

# lua subtrees that are framework/runtime, not user-facing scripts
LUA_SKIP = ("\\mq\\", "/mq/", "\\integrationtests\\", "/integrationtests/", "\\.git", "/.git")

_AUTH_STOP = {"the","for","and","with","now","use","via","based","fixed","changed","removed","added",
              "updated","initial","release","version","build","redguides","exclusive","auto","feature",
              "string","safety","rewrite","cleanup","refactor","name","names","list","full","null",
              "true","false","char","item","mob","all","new","old","this","that","from","code","note",
              "todo","fix","see","set","get","everyone","community","subscribers","subscriber","help",
              "thanks","contributed","contributied","original","author","maintained","modified","just",
              "edited","one","thing","little","macro","script","everquest","macroquest","required",
              "optional","plugins","plugin","you","your","who","all"}
_MONTHS = {"jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"}

CATS = [
    ("Combat & Assist",   ("kiss","assist","bot","hunter","mez","tank","pull","melee","nuke","heal",
                           "dps","tash","slow","debuff","root","snare","charm","pet","attack","kill")),
    ("Tradeskills",       ("baking","brewing","fish","fletch","jewelry","alchemy","combine","smith",
                           "pottery","tailor","research","poison","tinker","forage","craft","makepoison",
                           "imbue","velium","clay","brew")),
    ("Movement & Travel", ("follow","nav","warp","gate","travel","port","moveto","corpse","run","camp",
                           "waypoint","afk","return")),
    ("Items & Loot",      ("loot","ninja","sell","buy","bazaar","destroy","inventory","mule","bank",
                           "give","trade","merchant","vendor","drop","stack","clicky","clickies")),
    ("Buffs & Songs",     ("buff","twist","song","bard","cleric","ench","shaman","druid")),
    ("Utility & Info",    ("info","charinfo","cams","event","test","array","door","uservar","alert",
                           "drink","food","eat","med","afk","debug","example","mq","ui","window")),
]

def read_text(p):
    try: return open(p, encoding="utf-8", errors="replace").read()
    except Exception: return ""

def header_lines(text, is_lua, limit=90):
    """The leading comment block, decommented (used for desc + usage + author scraping).
    Handles both line comments (| ... / -- ...) and block comments (|* ... *| / --[[ ... ]])."""
    out = []
    in_block = False
    for raw in text.splitlines()[:limit]:
        s = raw.strip()
        if is_lua:
            if in_block:
                if "]]" in s:
                    rest = s.split("]]")[0].strip()
                    if rest: out.append(rest)
                    in_block = False
                else:
                    out.append(s)
                continue
            if s.startswith("--[["):
                rest = s[4:].strip()
                if rest.endswith("]]"): rest = rest[:-2].strip()
                else: in_block = True
                if rest: out.append(rest)
                continue
            if s.startswith("--"): out.append(s.lstrip("-").strip()); continue
            if s == "":
                if out: break
                continue
            break  # first real code line ends the header
        else:
            if in_block:
                if "*|" in s:
                    rest = s.split("*|")[0].rstrip("*").strip()
                    if rest: out.append(rest)
                    in_block = False
                else:
                    out.append(s.strip().rstrip("*").strip())
                continue
            if s.startswith("|*"):
                rest = s.lstrip("|").lstrip("*").strip()
                if rest.endswith("*|"): rest = rest.rstrip("|").rstrip("*").strip()
                else: in_block = True
                if rest: out.append(rest)
                continue
            if s.startswith("|"):
                out.append(s.lstrip("|").lstrip("*").strip()); continue
            if s == "":
                if out: break
                continue
            if s.startswith(("#warning", "#turbo", "#event", "#Event")): continue
            break
    return [l for l in out if l]

def _is_separator(s):
    """A banner/rule line (mostly punctuation) carries no description."""
    return sum(c.isalpha() for c in s) < max(8, int(len(s) * 0.4))

def extract_desc(hlines, name):
    nb = re.sub(r'\.(mac|inc|lua)$', '', name, flags=re.I).lower()
    best = ""
    for l in hlines:
        s = l.strip()
        if len(s) < 16 or _is_separator(s): continue
        low = s.lower()
        if low.startswith("description"):
            return (s.split(":", 1)[-1].strip() or s)[:600]
        if low.startswith(("author","usage","version","updated","maintained","required","optional",
                           "thanks","special thanks","credit","note","#event","#include")):
            continue
        if any(k in low for k in ("original author", "maintained for", "written by", "coded by",
                                  "copyright", "all rights reserved")):
            continue
        sb = re.sub(r'\.(mac|inc|lua)$', '', s, flags=re.I).lower().strip()
        if sb == nb or sb.startswith(nb + " version") or sb.startswith(nb + " v"):
            if not best: best = s  # filename/version line: keep as last resort
            continue
        return s[:600]
    if best: return best[:600]
    cand = [l for l in hlines if not _is_separator(l)]
    cand.sort(key=len, reverse=True)
    return (cand[0][:600] if cand else "")

def extract_authors(text):
    head = text[:7000]
    authors = []
    pats = [
        r'(?:original\s+author|author|written\s+by|coded\s+by|created\s+by)\s*[:\-]?\s*([A-Za-z][A-Za-z0-9_\']{2,24})',
        r'maintained(?:\s+for\s+[A-Za-z0-9_]+)?\s+by\s+([A-Za-z][A-Za-z0-9_\']{2,24})',
        r'updated\s+by\s*[:\-]?\s*([A-Za-z][A-Za-z0-9_\']{2,24})',
    ]
    for pat in pats:
        for m in re.finditer(pat, head, re.I):
            nm = m.group(1).strip()
            if nm.lower() in _AUTH_STOP or nm.lower() in _MONTHS: continue
            if any(nm.lower() == a.lower() for a in authors): continue
            authors.append(nm)
    return authors[:12]

def extract_required(text):
    req = []
    for m in re.finditer(r'(?:required|optional)\s+plugins?\s*[:\-]?\s*(.+)', text[:4000], re.I):
        for p in re.findall(r'MQ2[A-Za-z0-9_]+', m.group(1)):
            if p not in req: req.append(p)
    for p in re.findall(r'/plugin\s+(MQ2[A-Za-z0-9_]+)', text):
        if p not in req: req.append(p)
    return req[:20]

def categorize(name, desc):
    s = (name + " " + (desc or "")).lower()
    for cat, kws in CATS:
        if any(k in s for k in kws): return cat
    return "Utility & Info"

def scan_file(full, rootkey, root, is_lua):
    text = read_text(full)
    name = os.path.basename(full)
    rel = os.path.relpath(full, root).replace("\\", "/")
    typ = "lua" if is_lua else ("inc" if name.lower().endswith(".inc") else "mac")
    hlines = header_lines(text, is_lua)
    desc = extract_desc(hlines, name)
    usage = []
    for h in hlines:
        for m in re.finditer(r'(/(?:mac(?:ro)?|lua)\s+[^\r\n\'"|]{1,80})', h):
            u = re.sub(r'\s{2,}.*$', '', m.group(1).strip()).strip(" .,)(")
            if u and u not in usage: usage.append(u)
    events   = sorted(set(re.findall(r'#Event\s+([A-Za-z0-9_]+)', text)))[:60]
    includes = sorted(set(re.findall(r'#include\s+<?([A-Za-z0-9_\.]+\.inc)>?', text, re.I)))[:40]
    if is_lua:
        commands = sorted(set(re.findall(r"""mq\.bind\(\s*['"](/[A-Za-z0-9_]+)""", text)))[:40]
    else:
        commands = sorted(set(re.findall(r'/bind\s+\S+\s+(/[A-Za-z0-9_]+)', text)))[:40]
    loc = text.count("\n") + 1
    base = re.sub(r'\.(mac|inc|lua)$', '', name, flags=re.I)
    slug = re.sub(r'[^A-Za-z0-9]+', '_', rel).strip('_').lower()
    return {"slug": slug, "name": name, "base": base, "type": typ,
            "category": categorize(name, desc), "desc": desc,
            "usage": usage[:6], "authors": extract_authors(text), "required": extract_required(text),
            "includes": includes, "events": events, "commands": commands,
            "loc": loc, "rootkey": rootkey, "path": rel}

def main():
    entries = []
    if os.path.isdir(MAC_ROOT):
        for fn in sorted(os.listdir(MAC_ROOT)):
            if fn.lower().endswith((".mac", ".inc")):
                entries.append(scan_file(os.path.join(MAC_ROOT, fn), "macros", MAC_ROOT, False))
    if os.path.isdir(LUA_ROOT):
        for r, _d, fns in os.walk(LUA_ROOT):
            rl = (r.lower() + os.sep).replace("\\", "\\")
            if any(s in (r.lower() + os.sep) for s in LUA_SKIP):
                continue
            for fn in sorted(fns):
                if fn.lower().endswith(".lua"):
                    entries.append(scan_file(os.path.join(r, fn), "lua", LUA_ROOT, True))
    # de-dup slugs
    seen = {}
    for e in entries:
        s = e["slug"]; n = seen.get(s, 0); seen[s] = n + 1
        if n: e["slug"] = "%s_%d" % (s, n)
    entries.sort(key=lambda e: (e["category"], e["name"].lower()))
    json.dump({"generated": int(time.time()),
               "roots": {"macros": os.path.abspath(MAC_ROOT), "lua": os.path.abspath(LUA_ROOT)},
               "macros": entries},
              open(OUT, "w", encoding="utf-8"), indent=1)
    cats = {}
    for e in entries: cats[e["category"]] = cats.get(e["category"], 0) + 1
    print("macros: %d entries -> %s" % (len(entries), OUT))
    for c, n in sorted(cats.items()): print("   %-22s %d" % (c, n))

if __name__ == "__main__":
    main()
