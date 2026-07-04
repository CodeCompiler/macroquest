#!/usr/bin/env python3
"""
build_wiki.py -- scan the MacroQuest plugin tree (+ core) and emit wiki.json for the
MMOPlugins plugin wiki. For each plugin it captures: a description, the slash-commands it
registers (AddCommand "/..."), and its source-file list (path + LOC). The web app reads
wiki.json and serves the source on demand from each plugin's recorded directory.

    python build_wiki.py [pluginsDir] [outJson]
Defaults: C:\\MQ2\\macroquest\\plugins  ->  C:\\mmoplugins\\wiki.json
"""
import os, re, json, sys, time

PLUGINS = sys.argv[1] if len(sys.argv) > 1 else r"C:\MQ2\macroquest\plugins"
CORE    = r"C:\MQ2\macroquest\src\main"
OUT     = sys.argv[2] if len(sys.argv) > 2 else r"C:\mmoplugins\wiki.json"

ADDCMD_RE = re.compile(r'AddCommand\s*\(\s*"(/?[A-Za-z0-9_]+)"')
SRC_EXT   = (".cpp", ".h", ".hpp", ".cxx", ".cc")
SKIP_DIRS = ("\\x64\\", "\\.vs\\", "\\obj\\", "\\debug\\", "\\release\\", "\\.git\\", "\\vcpkg")


def read_text(p):
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except Exception:
        return ""


def extract_desc(plugdir, name):
    # 1) a README in the plugin dir
    try:
        for fn in os.listdir(plugdir):
            if fn.lower() in ("readme.md", "readme.txt", "readme"):
                txt = read_text(os.path.join(plugdir, fn))
                for para in re.split(r'\n\s*\n', txt):
                    s = para.strip()
                    if not s:
                        continue
                    # drop heading/badge/image lines, keep the first real prose
                    lines = [l for l in s.splitlines()
                             if l.strip() and not l.strip().startswith("#")
                             and not l.strip().startswith("![") and not l.strip().startswith("[!")]
                    s = " ".join(lines).strip()
                    if len(s) >= 20:
                        return s[:700]
    except Exception:
        pass
    # 2) top comment block of the main .cpp
    main = os.path.join(plugdir, name + ".cpp")
    if os.path.exists(main):
        txt = read_text(main)
        m = re.search(r'/\*(.*?)\*/', txt, re.S)
        if m:
            body = re.sub(r'^\s*\*?', '', m.group(1), flags=re.M).strip()
            if len(body) >= 20:
                return body[:700]
        lines = []
        for l in txt.splitlines():
            ls = l.strip()
            if ls.startswith("//"):
                lines.append(ls.lstrip("/ ").rstrip())
            elif not ls and not lines:
                continue
            else:
                break
        if lines:
            return " ".join(lines)[:700]
    return ""


_AUTH_STOP = {"updated", "fixed", "added", "initial", "release", "version", "build", "redguides",
              "exclusive", "auto", "feature", "string", "safety", "rewrite", "cleanup", "refactor",
              "the", "for", "and", "with", "now", "use", "via", "based", "fixed", "changed", "removed",
              "name", "names", "list", "full", "null", "true", "false", "char", "item", "mob", "all",
              "new", "old", "this", "that", "from", "code", "note", "todo", "fix", "see", "set", "get"}
_AUTH_MONTHS = {"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}

def extract_authors(plugdir, name):
    """Pull original author/credit names from the file header (version-history & 'by/author' lines)
    so creators keep credit. Conservative: only from dated/version lines or explicit author lines."""
    main = os.path.join(plugdir, name + ".cpp")
    text = read_text(main)[:6000] if os.path.exists(main) else ""
    authors = []
    pats = [r'v[\d.]+\s*[-–]\s*([A-Za-z][A-Za-z0-9_\']{2,18})',     # "v2.0 - Eqmule"
            r'([A-Za-z][A-Za-z0-9_\']{2,18})\s+\d{1,2}[-/]\d{1,2}[-/]\d',  # "Eqmule 11-23-2015"
            r'(?:author|by|created by|written by|coded by)\s*[:\-]?\s*([A-Za-z][A-Za-z0-9_\']{2,24})']
    for pat in pats:
        for m in re.finditer(pat, text, re.I):
            nm = m.group(1).strip()
            if nm.lower() in _AUTH_STOP or nm.lower() in _AUTH_MONTHS: continue
            if nm not in authors: authors.append(nm)
    return authors[:10]

def scan(plugdir, name):
    files = []
    commands = {}
    loc = 0
    for root, _dirs, fns in os.walk(plugdir):
        rl = root.lower() + "\\"
        if any(s in rl for s in SKIP_DIRS):
            continue
        for fn in fns:
            if not fn.lower().endswith(SRC_EXT):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, plugdir).replace("\\", "/")
            txt = read_text(full)
            n = txt.count("\n") + 1
            loc += n
            for m in ADDCMD_RE.finditer(txt):
                cmd = m.group(1)
                commands.setdefault(cmd, rel)
            files.append({"path": rel, "loc": n})
    files.sort(key=lambda x: x["path"])
    cmds = [{"cmd": c, "file": f} for c, f in sorted(commands.items())]
    return {"name": name, "dir": os.path.abspath(plugdir), "desc": extract_desc(plugdir, name),
            "authors": extract_authors(plugdir, name), "commands": cmds, "files": files, "loc": loc}


def has_source(d):
    for _r, _ds, fs in os.walk(d):
        if any(f.lower().endswith(SRC_EXT) for f in fs):
            return True
    return False


def main():
    plugins = []
    if os.path.isdir(CORE):
        core = scan(CORE, "MacroQuest")
        core["name"] = "MacroQuest (core)"
        core["core"] = True
        plugins.append(core)
    for d in sorted(os.listdir(PLUGINS)):
        full = os.path.join(PLUGINS, d)
        if os.path.isdir(full) and not d.startswith(".") and has_source(full):
            plugins.append(scan(full, d))
    for p in plugins:
        p["slug"] = re.sub(r'[^A-Za-z0-9]+', '_', p["name"]).strip('_')
    json.dump({"generated": int(time.time()), "plugins": plugins},
              open(OUT, "w", encoding="utf-8"), indent=1)
    tot_cmd = sum(len(p["commands"]) for p in plugins)
    print("wiki: %d plugins, %d commands -> %s" % (len(plugins), tot_cmd, OUT))


if __name__ == "__main__":
    main()
