#!/usr/bin/env python3
"""
eqmq_paths.py  --  shared, portable path resolver for the EQMQ offset toolkit.

Every other script (offsettool.py, superbaseline.py) imports these values instead
of hard-coding C:\\... paths, so the kit runs unchanged on anyone's machine.

For each external path the resolver tries, in order:
    1) an environment variable        (EQMQ_GHIDRA / EQMQ_JDK21 / EQMQ_EQ_EXE / EQMQ_MQ_SRC)
    2) eqmq.config.ini next to this file, section [paths]
    3) auto-detection of common install locations

WORKSPACE is always this file's own folder, so you can copy the whole
02-offset-toolkit\\ directory anywhere and the scripts keep working.

CLI (used by the .bat / .ps1 wrappers, and handy for debugging):
    python eqmq_paths.py check                 # report every resolved path + exist?
    python eqmq_paths.py get EQGAME_H          # print one resolved path (for scripts)
    python eqmq_paths.py write-config          # write a starter eqmq.config.ini from detection
"""

import os, sys, glob

try:
    import configparser
except ImportError:                       # very old python; we target 3.x so this is belt-and-braces
    configparser = None

WORKSPACE = os.path.dirname(os.path.abspath(__file__))
CFG_PATH  = os.path.join(WORKSPACE, "eqmq.config.ini")

VERSIONS  = os.path.join(WORKSPACE, "versions")
OUT       = os.path.join(WORKSPACE, "out")
PROJECTS  = os.path.join(WORKSPACE, "ghidra_projects")
DB_PATH   = os.path.join(WORKSPACE, "baseline_db.json")


# ----------------------------------------------------------------- config file
def _load_cfg():
    cfg = configparser.ConfigParser() if configparser else None
    if cfg is not None and os.path.exists(CFG_PATH):
        try:
            cfg.read(CFG_PATH, encoding="utf-8")
        except Exception as e:
            print("[eqmq_paths] WARNING: could not read %s (%s)" % (CFG_PATH, e))
    return cfg

_CFG = _load_cfg()

def _from_cfg(key):
    if _CFG is not None and _CFG.has_option("paths", key):
        v = _CFG.get("paths", key).strip().strip('"').strip("'")
        if v:
            return v
    return None


# ----------------------------------------------------------------- detection
def _newest_glob(patterns):
    """Return the lexicographically-greatest match (version dirs sort so newest wins)."""
    best = None
    for pat in patterns:
        for hit in glob.glob(pat):
            if best is None or hit > best:
                best = hit
    return best

def _detect_ghidra():
    return _newest_glob([
        r"C:\Users\*\Documents\Ghidra\ghidra_*_PUBLIC\support\analyzeHeadless.bat",
        r"C:\Users\*\ghidra_*_PUBLIC\support\analyzeHeadless.bat",
        r"C:\ghidra\ghidra_*_PUBLIC\support\analyzeHeadless.bat",
        r"C:\ghidra_*_PUBLIC\support\analyzeHeadless.bat",
        r"C:\Program Files\ghidra_*_PUBLIC\support\analyzeHeadless.bat",
        r"C:\tools\ghidra_*\support\analyzeHeadless.bat",
        # Chocolatey / chocoportable installs (choco install ghidra)
        r"C:\ProgramData\choco*\lib\ghidra\tools\ghidra_*_PUBLIC\support\analyzeHeadless.bat",
        r"C:\ProgramData\choco*\lib\ghidra*\tools\ghidra_*_PUBLIC\support\analyzeHeadless.bat",
        r"D:\ghidra_*_PUBLIC\support\analyzeHeadless.bat",
    ])

def _detect_jdk21():
    return _newest_glob([
        r"C:\Program Files\Eclipse Adoptium\jdk-21*",
        r"C:\Program Files\Java\jdk-21*",
        r"C:\Program Files\Microsoft\jdk-21*",
        r"C:\Program Files\Amazon Corretto\jdk21*",
        r"C:\Program Files\Zulu\zulu-21*",
        r"C:\Program Files\BellSoft\LibericaJDK-21*",
    ])

def _detect_eq_exe():
    return _newest_glob([
        r"C:\Users\Public\Daybreak Game Company\Installed Games\EverQuest\eqgame.exe",
        r"C:\Users\Public\Sony Online Entertainment\Installed Games\EverQuest\eqgame.exe",
        r"C:\Program Files (x86)\Sony\EverQuest\eqgame.exe",
        r"C:\Program Files\Sony\EverQuest\eqgame.exe",
        r"C:\EverQuest\eqgame.exe",
        r"C:\Games\EverQuest\eqgame.exe",
        r"D:\*\EverQuest\eqgame.exe",
    ])

def _detect_mq_src():
    rel = os.path.join("src", "eqlib", "include", "eqlib", "offsets", "eqgame.h")
    for pat in [r"C:\MQ2\macroquest", r"C:\macroquest", r"C:\*\macroquest",
                r"C:\Users\*\source\repos\macroquest", r"C:\Users\*\macroquest",
                r"D:\*\macroquest"]:
        for hit in glob.glob(pat):
            if os.path.exists(os.path.join(hit, rel)):
                return hit
    return None


# ----------------------------------------------------------------- resolved values
GHIDRA_HEADLESS = (os.environ.get("EQMQ_GHIDRA") or _from_cfg("ghidra_headless") or _detect_ghidra())
JDK21           = (os.environ.get("EQMQ_JDK21")  or _from_cfg("jdk21_home")     or _detect_jdk21())
EQ_EXE          = (os.environ.get("EQMQ_EQ_EXE") or _from_cfg("eq_exe")         or _detect_eq_exe())
MQ_SRC          = (os.environ.get("EQMQ_MQ_SRC") or _from_cfg("macroquest_src") or _detect_mq_src())

# eqgame.h is derived from the macroquest source root unless explicitly overridden.
_eqh_override = os.environ.get("EQMQ_EQGAME_H") or _from_cfg("eqgame_h")
if _eqh_override:
    EQGAME_H = _eqh_override
elif MQ_SRC:
    EQGAME_H = os.path.join(MQ_SRC, "src", "eqlib", "include", "eqlib", "offsets", "eqgame.h")
else:
    EQGAME_H = None

ANALYSIS_TIMEOUT = os.environ.get("EQMQ_ANALYSIS_TIMEOUT") or _from_cfg("analysis_timeout") or "0"

_NAMES = {
    "GHIDRA_HEADLESS": GHIDRA_HEADLESS,
    "JDK21": JDK21,
    "EQ_EXE": EQ_EXE,
    "MQ_SRC": MQ_SRC,
    "EQGAME_H": EQGAME_H,
    "WORKSPACE": WORKSPACE,
}


def require(*names):
    """Validate the named paths resolved and exist on disk; print guidance if not.
    Returns True if all good, else False (callers decide whether to abort)."""
    missing = []
    for n in names:
        v = _NAMES.get(n)
        if not v or not os.path.exists(v):
            missing.append((n, v))
    if missing:
        print("[eqmq_paths] These required paths are missing or could not be resolved:")
        for n, v in missing:
            print("    %-16s = %s" % (n, v if v else "(not found)"))
        print("[eqmq_paths] Fix one of:")
        print("    - run  prerequisites\\Detect-Environment.ps1   (writes eqmq.config.ini for you)")
        print("    - or edit %s  ([paths] section)" % CFG_PATH)
        print("    - or set the matching EQMQ_* environment variable")
        return False
    return True


# ----------------------------------------------------------------- CLI
def _cmd_check():
    print("EQMQ resolved paths (workspace = %s)" % WORKSPACE)
    print("-" * 70)
    order = ["GHIDRA_HEADLESS", "JDK21", "EQ_EXE", "MQ_SRC", "EQGAME_H"]
    allok = True
    for n in order:
        v = _NAMES.get(n)
        ok = bool(v) and os.path.exists(v)
        allok = allok and ok
        print("  [%s] %-16s %s" % ("ok " if ok else "MISS", n, v if v else "(not found)"))
    print("-" * 70)
    print("config file: %s  (%s)" % (CFG_PATH, "present" if os.path.exists(CFG_PATH) else "absent - using detection"))
    print("ALL REQUIRED PRESENT" if allok else "SOME PATHS MISSING - see above")
    return 0 if allok else 1

def _cmd_get(name):
    v = _NAMES.get(name)
    if v:
        sys.stdout.write(v)
        return 0
    return 3

def _cmd_write_config():
    if configparser is None:
        print("configparser unavailable"); return 1
    cfg = configparser.ConfigParser()
    cfg["paths"] = {
        "ghidra_headless": GHIDRA_HEADLESS or "",
        "jdk21_home":      JDK21 or "",
        "eq_exe":          EQ_EXE or "",
        "macroquest_src":  MQ_SRC or "",
        "eqgame_h":        "",          # leave blank = derive from macroquest_src
        "analysis_timeout": "0",
    }
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        f.write("; EQMQ offset toolkit paths. Edit any value that detection got wrong.\n")
        f.write("; Blank eqgame_h = derived from macroquest_src.\n\n")
        cfg.write(f)
    print("[eqmq_paths] wrote %s" % CFG_PATH)
    return _cmd_check()

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "check":
        sys.exit(_cmd_check())
    elif len(sys.argv) == 3 and sys.argv[1] == "get":
        sys.exit(_cmd_get(sys.argv[2]))
    elif len(sys.argv) >= 2 and sys.argv[1] == "write-config":
        sys.exit(_cmd_write_config())
    else:
        print(__doc__)
        sys.exit(1)
