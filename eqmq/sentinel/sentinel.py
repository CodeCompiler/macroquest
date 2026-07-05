#!/usr/bin/env python3
"""
sentinel.py  --  EQMQ Sentinel: patch-day watchdog + auto-patcher orchestrator.

Sentinel is the "something changed -> act" layer on top of the offset toolkit.
It watches for a new EverQuest client build, then drives the existing pipeline
(update_from_exe.py analyze -> gate -> apply) with safety rails, archiving and
Discord notifications at every stage. Designed to run unattended on a VPS as a
scheduled task.

DETECTORS (any combination, all configurable in sentinel.config.json):
  1. exe watch    -- hash/stamp of a local EverQuest install's eqgame.exe
                     (the box patches EQ via the launcher; Sentinel notices).
  2. inbox watch  -- any *.exe dropped into sentinel/inbox/ (e.g. by a web
                     submission flow or an scp from another machine).
  3. url watch    -- optional: any URL whose ETag/Last-Modified/body-hash change
                     means "patch day". Alert-only (tells you a patch landed
                     before you have the binary).

PIPELINE (per detected build):
  quarantine copy -> analyze (Ghidra, SLOW) -> coverage gate -> apply (only if
  auto_apply AND coverage >= apply_min_coverage; update_from_exe has its own
  >10%-missing abort on top) -> optional build_command -> archive client +
  header + coverage into versions/archive/<date>/ -> history record + webhook.

SAFETY DEFAULTS: auto_apply=false (analyze + report, human runs `approve`),
lockfile so two ticks can't stack Ghidra runs, free-disk check before analysis.

USAGE:
  python sentinel.py tick            # one detection pass (what the scheduled task runs)
  python sentinel.py tick --dry-run  # detect + report only; never analyze/apply
  python sentinel.py watch [--interval 600]   # loop forever (foreground service)
  python sentinel.py status          # state summary: last tick, last build, pending
  python sentinel.py approve         # apply a gated/pending analysis + archive + notify
  python sentinel.py simulate <exe>  # force the pipeline on a specific exe (testing)
  python sentinel.py test-notify     # send a test webhook message

No secrets in this file or the repo: the Discord webhook comes from the
SENTINEL_WEBHOOK env var or sentinel/webhook.txt (gitignored).
"""
import os, sys, re, json, csv, time, shutil, hashlib, subprocess, argparse, datetime

HERE    = os.path.dirname(os.path.abspath(__file__))
TOOLKIT = os.path.abspath(os.path.join(HERE, "..", "offset-toolkit"))
sys.path.insert(0, TOOLKIT)

import eqmq_paths as P            # noqa: E402  (toolkit path resolver)
import jsonstore                  # noqa: E402  (crash-safe JSON persistence)

CONFIG_PATH  = os.path.join(HERE, "sentinel.config.json")
EXAMPLE_PATH = os.path.join(HERE, "sentinel.config.example.json")
STATE_PATH   = os.path.join(HERE, "sentinel.state.json")
HISTORY_PATH = os.path.join(HERE, "sentinel.history.jsonl")
LOCK_PATH    = os.path.join(HERE, "sentinel.lock")
LOG_DIR      = os.path.join(HERE, "logs")
QUAR_DIR     = os.path.join(HERE, "quarantine")

LOCK_STALE_SECS = 6 * 3600        # a Ghidra run can take 1-3h; >6h = crashed run

DEFAULTS = {
    "watch_eq_exe":       True,    # detector 1: local EQ install
    "eq_exe":             "",      # blank = resolve via eqmq_paths (EQMQ_EQ_EXE / config.ini / detection)
    "inbox_dir":          "inbox", # detector 2: relative to sentinel/ unless absolute
    "watch_url":          "",      # detector 3: optional URL to fingerprint (alert-only)
    "auto_analyze":       True,    # run the Ghidra analyze automatically on detection
    "auto_apply":         False,   # write eqgame.h automatically when coverage clears the gate
    "apply_min_coverage": 0.92,    # matched/total needed before auto-apply is even considered
    "auto_build":         False,   # run build_command after a successful apply
    "build_command":      "",      # e.g. powershell -File C:\\path\\to\\Build-MacroQuest.ps1 -Plugins
    "archive_clients":    True,    # keep exe+header+coverage in versions\\archive\\<date>\\
    "webhook_env":        "SENTINEL_WEBHOOK",
    "webhook_file":       "webhook.txt",   # relative to sentinel/ (gitignored)
    "min_free_gb":        10,      # refuse to start an analysis with less free disk than this
    "history_keep":       200,     # trim sentinel.history.jsonl beyond this many records
}


# ----------------------------------------------------------------- small utils
def log(msg):
    print("[sentinel] %s" % msg, flush=True)


def now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sha256_file(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def load_config():
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        try:
            cfg.update(jsonstore.safe_load(CONFIG_PATH))
        except Exception as e:
            log("WARNING: bad sentinel.config.json (%s) - using defaults" % e)
    return cfg


def load_state():
    return jsonstore.safe_load(STATE_PATH, default={})


def save_state(state):
    jsonstore.atomic_dump(state, STATE_PATH, indent=2)


def append_history(record, keep):
    record["at"] = now_iso()
    lines = []
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH, encoding="utf-8") as f:
            lines = [ln for ln in f.read().split("\n") if ln.strip()]
    lines.append(json.dumps(record))
    lines = lines[-keep:]
    tmp = HISTORY_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, HISTORY_PATH)


def notify(cfg, msg):
    """Post to the Discord webhook if configured; always echo to console/log."""
    log("NOTIFY: %s" % msg)
    url = os.environ.get(cfg.get("webhook_env") or "", "").strip()
    if not url:
        wf = cfg.get("webhook_file") or ""
        if wf and not os.path.isabs(wf):
            wf = os.path.join(HERE, wf)
        if wf and os.path.exists(wf):
            url = open(wf, encoding="utf-8").read().strip()
    if not url:
        return False
    try:
        import sentinel_notify
        return sentinel_notify.post(url, msg)
    except Exception as e:
        log("webhook post failed: %s" % e)
        return False


# ----------------------------------------------------------------- lockfile
def acquire_lock():
    if os.path.exists(LOCK_PATH):
        try:
            age = time.time() - os.path.getmtime(LOCK_PATH)
        except OSError:
            age = 0
        if age < LOCK_STALE_SECS:
            log("another Sentinel run holds the lock (%.0f min old) - skipping this tick." % (age / 60))
            return False
        log("stale lock (%.1f h old) - previous run likely crashed; taking over." % (age / 3600))
    with open(LOCK_PATH, "w", encoding="utf-8") as f:
        f.write("pid=%d at=%s\n" % (os.getpid(), now_iso()))
    return True


def release_lock():
    try:
        if os.path.exists(LOCK_PATH):
            os.remove(LOCK_PATH)
    except OSError:
        pass


# ----------------------------------------------------------------- detectors
def detect_stamp(exe):
    """Client build date/time/ClientDate. Reuses the toolkit's detector."""
    try:
        import update_from_exe
        return update_from_exe.detect_stamp(exe)
    except Exception:
        # minimal fallback so detection still works if the toolkit import breaks
        try:
            text = open(exe, "rb").read().decode("latin-1", "ignore")
            m = re.search(r'([A-Z][a-z]{2} [ 0-9][0-9] 20[0-9]{2})', text)
            return {"date": m.group(1) if m else None, "time": None, "client_num": None}
        except Exception:
            return {"date": None, "time": None, "client_num": None}


def fingerprint_exe(exe):
    st = os.stat(exe)
    return {"sha256": sha256_file(exe), "size": st.st_size,
            "mtime": int(st.st_mtime), "stamp": detect_stamp(exe)}


def check_eq_exe(cfg, state):
    """Detector 1: has the local EQ install's eqgame.exe changed since last seen?"""
    exe = (cfg.get("eq_exe") or "").strip() or (P.EQ_EXE or "")
    if not exe or not os.path.exists(exe):
        return None
    st = os.stat(exe)
    last = state.get("eq_exe", {})
    # cheap pre-check: same size+mtime as last time -> no hash needed
    if last.get("size") == st.st_size and last.get("mtime") == int(st.st_mtime):
        return None
    fp = fingerprint_exe(exe)
    if fp["sha256"] == last.get("sha256"):
        state["eq_exe"] = fp          # mtime drifted (revalidated file), remember it
        return None
    state["eq_exe"] = fp
    if not last:                       # first run: baseline, don't fire the pipeline
        log("baselined eq_exe %s (build %s)" % (exe, fp["stamp"].get("date")))
        return None
    return {"source": "eq_exe", "exe": exe, "fp": fp}


def check_inbox(cfg, state):
    """Detector 2: a new *.exe dropped into the inbox folder."""
    inbox = cfg.get("inbox_dir") or "inbox"
    if not os.path.isabs(inbox):
        inbox = os.path.join(HERE, inbox)
    if not os.path.isdir(inbox):
        return None
    seen = state.setdefault("inbox_seen", {})
    for fn in sorted(os.listdir(inbox)):
        if not fn.lower().endswith(".exe"):
            continue
        path = os.path.join(inbox, fn)
        # skip files still being written (size changing)
        s1 = os.path.getsize(path); time.sleep(1.0); s2 = os.path.getsize(path)
        if s1 != s2:
            log("inbox: %s still growing - will pick it up next tick" % fn)
            continue
        digest = sha256_file(path)
        if seen.get(fn) == digest:
            continue
        seen[fn] = digest
        return {"source": "inbox", "exe": path,
                "fp": {"sha256": digest, "size": s2, "mtime": int(os.path.getmtime(path)),
                       "stamp": detect_stamp(path)}}
    return None


def check_url(cfg, state):
    """Detector 3 (alert-only): fingerprint a URL; a change means 'patch day'."""
    url = (cfg.get("watch_url") or "").strip()
    if not url:
        return None
    try:
        import urllib.request
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "eqmq-sentinel/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            etag = r.headers.get("ETag") or ""
            lastmod = r.headers.get("Last-Modified") or ""
            body = r.read(1024 * 1024)          # first 1MB is plenty for a manifest
        digest = hashlib.sha256(body).hexdigest()
    except Exception as e:
        log("url watch failed (%s) - ignoring this tick" % e)
        return None
    fp = {"etag": etag, "last_modified": lastmod, "sha256": digest}
    last = state.get("url", {})
    state["url"] = fp
    if not last:
        log("baselined watch_url (etag=%s last-modified=%s)" % (etag or "-", lastmod or "-"))
        return None
    if fp != last:
        return {"source": "url", "url": url, "fp": fp}
    return None


# ----------------------------------------------------------------- pipeline
def free_gb(path):
    try:
        usage = shutil.disk_usage(os.path.splitdrive(os.path.abspath(path))[0] + os.sep)
        return usage.free / (1024 ** 3)
    except Exception:
        return None


def parse_coverage():
    """Read the toolkit's coverage report -> dict(total, matched, high, medium, unmatched, coverage)."""
    for name in ("coverage_report.csv", "offset_report.csv"):
        p = os.path.join(P.OUT, name)
        if not os.path.exists(p):
            continue
        total = matched = high = medium = unmatched = 0
        with open(p, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                total += 1
                nv = (r.get("new_va") or "").strip()
                conf = (r.get("confidence") or r.get("status") or "").strip().lower()
                if nv and conf not in ("", "unmatched"):
                    matched += 1
                    if conf == "high":
                        high += 1
                    elif conf == "medium":
                        medium += 1
                else:
                    unmatched += 1
        cov = (matched / total) if total else 0.0
        return {"report": name, "total": total, "matched": matched, "high": high,
                "medium": medium, "unmatched": unmatched, "coverage": round(cov, 4)}
    return None


def run_step(label, args, logfile):
    """Run a pipeline subprocess, teeing output to a per-build log. Returns exit code."""
    log("%s: %s" % (label, " ".join(args)))
    with open(logfile, "a", encoding="utf-8", errors="replace") as lf:
        lf.write("\n===== %s @ %s =====\n" % (label, now_iso()))
        lf.flush()
        proc = subprocess.Popen(args, cwd=TOOLKIT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace")
        for line in proc.stdout:
            lf.write(line)
        proc.wait()
        lf.write("===== %s exit %d =====\n" % (label, proc.returncode))
    return proc.returncode


def build_tag(fp):
    stamp = fp.get("stamp") or {}
    return stamp.get("client_num") or fp.get("sha256", "unknown")[:12]


def archive_build(cfg, exe, tag):
    """Keep exe + proposed header + coverage report under versions\\archive\\<tag>\\."""
    if not cfg.get("archive_clients", True):
        return None
    dest = os.path.join(P.VERSIONS, "archive", tag)
    os.makedirs(dest, exist_ok=True)
    shutil.copy2(exe, os.path.join(dest, "eqgame.exe"))
    for fn in ("eqgame_new.h", "coverage_report.csv", "offset_report.csv", "incoming_stamp.json"):
        src = os.path.join(P.OUT, fn)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(dest, fn))
    log("archived build -> %s" % dest)
    return dest


def run_pipeline(cfg, state, hit, dry_run=False):
    """The full detected-build flow. `hit` comes from a detector."""
    exe, fp = hit["exe"], hit["fp"]
    stamp = fp.get("stamp") or {}
    tag = build_tag(fp)
    desc = "%s %s (ClientDate %s, source: %s)" % (
        stamp.get("date") or "?", stamp.get("time") or "", stamp.get("client_num") or "?", hit["source"])

    notify(cfg, ":satellite: **Sentinel: new EverQuest client build detected** - %s" % desc)
    record = {"event": "detected", "tag": tag, "source": hit["source"],
              "sha256": fp.get("sha256"), "stamp": stamp}

    if dry_run:
        record["event"] = "detected(dry-run)"
        append_history(record, cfg["history_keep"])
        log("dry-run: stopping after detection.")
        return

    # quarantine copy: the pipeline works from OUR copy, never the live install's file
    os.makedirs(QUAR_DIR, exist_ok=True)
    qdir = os.path.join(QUAR_DIR, tag)
    os.makedirs(qdir, exist_ok=True)
    qexe = os.path.join(qdir, "eqgame.exe")
    shutil.copy2(exe, qexe)

    os.makedirs(LOG_DIR, exist_ok=True)
    logfile = os.path.join(LOG_DIR, "sentinel-%s.log" % tag)

    if not cfg.get("auto_analyze", True):
        state["pending"] = {"tag": tag, "exe": qexe, "phase": "awaiting-analyze", "desc": desc}
        record["event"] = "detected(awaiting-analyze)"
        append_history(record, cfg["history_keep"])
        notify(cfg, ":inbox_tray: Sentinel: build **%s** quarantined. auto_analyze is off - run "
                    "`python sentinel.py approve` (or update_from_exe.py analyze) when ready." % tag)
        return

    fg = free_gb(TOOLKIT)
    if fg is not None and fg < cfg.get("min_free_gb", 10):
        notify(cfg, ":warning: Sentinel: only %.1f GB free - refusing to start the Ghidra "
                    "analysis for build %s. Free disk and re-run `sentinel.py tick`." % (fg, tag))
        state["pending"] = {"tag": tag, "exe": qexe, "phase": "blocked-disk", "desc": desc}
        record["event"] = "blocked-disk"
        append_history(record, cfg["history_keep"])
        return

    # ---- analyze (Ghidra, the slow part) ----------------------------------
    notify(cfg, ":hourglass: Sentinel: Ghidra analysis started for **%s** (typically 1-3h)..." % tag)
    rc = run_step("analyze", [sys.executable, os.path.join(TOOLKIT, "update_from_exe.py"),
                              "analyze", qexe], logfile)
    if rc != 0:
        state["pending"] = {"tag": tag, "exe": qexe, "phase": "analyze-failed", "desc": desc}
        record.update(event="analyze-failed", exit=rc)
        append_history(record, cfg["history_keep"])
        notify(cfg, ":x: Sentinel: analysis **FAILED** (exit %d) for build %s. "
                    "See sentinel/logs/sentinel-%s.log. eqgame.h untouched." % (rc, tag, tag))
        return

    cov = parse_coverage() or {}
    record["coverage"] = cov
    cov_line = "%d/%d relocated (%.1f%%), %d high / %d medium confidence, %d unmatched" % (
        cov.get("matched", 0), cov.get("total", 0), 100 * cov.get("coverage", 0),
        cov.get("high", 0), cov.get("medium", 0), cov.get("unmatched", 0))

    # ---- gate --------------------------------------------------------------
    threshold = cfg.get("apply_min_coverage", 0.92)
    if not cfg.get("auto_apply", False) or cov.get("coverage", 0) < threshold:
        why = ("auto_apply is off" if not cfg.get("auto_apply", False)
               else "coverage %.1f%% < gate %.1f%%" % (100 * cov.get("coverage", 0), 100 * threshold))
        state["pending"] = {"tag": tag, "exe": qexe, "phase": "awaiting-approve",
                            "desc": desc, "coverage": cov}
        record["event"] = "gated"
        append_history(record, cfg["history_keep"])
        notify(cfg, ":pause_button: Sentinel: build **%s** analyzed - %s.\n"
                    "GATED (%s). Review out\\coverage_report.csv, then `python sentinel.py approve`."
               % (tag, cov_line, why))
        return

    # ---- apply + optional build + archive ----------------------------------
    _apply_and_finish(cfg, state, record, tag, qexe, cov_line, logfile)


def _apply_and_finish(cfg, state, record, tag, qexe, cov_line, logfile):
    rc = run_step("apply", [sys.executable, os.path.join(TOOLKIT, "update_from_exe.py"), "apply"],
                  logfile)
    if rc != 0:
        state["pending"] = {"tag": tag, "exe": qexe, "phase": "apply-gated", "coverage": record.get("coverage")}
        record.update(event="apply-gated", exit=rc)
        append_history(record, cfg["history_keep"])
        notify(cfg, ":no_entry: Sentinel: apply was **blocked by the toolkit's own safety gate** "
                    "(exit %d) for build %s - eqgame.h untouched. %s" % (rc, tag, cov_line))
        return

    built = None
    if cfg.get("auto_build") and (cfg.get("build_command") or "").strip():
        notify(cfg, ":hammer: Sentinel: offsets applied for **%s** - starting build..." % tag)
        brc = run_step("build", ["powershell", "-NoProfile", "-Command", cfg["build_command"]],
                       logfile)
        built = (brc == 0)
        record["build_exit"] = brc

    archive_build(cfg, qexe, tag)
    state.pop("pending", None)
    record["event"] = "applied"
    append_history(record, cfg["history_keep"])

    tail = {None:  "auto_build off - rebuild MacroQuest manually and verify in-game.",
            True:  "build **succeeded** - VERIFY in-game on a throwaway login before trusting.",
            False: "build **FAILED** - offsets applied+stamped but source needs a human "
                   "(usually struct/API drift). See the build log."}[built]
    notify(cfg, ":white_check_mark: Sentinel: build **%s** offsets APPLIED (%s). %s"
           % (tag, cov_line, tail))


# ----------------------------------------------------------------- commands
def cmd_tick(dry_run=False):
    cfg = load_config()
    if not acquire_lock():
        return 0
    try:
        state = load_state()
        state["last_tick"] = now_iso()
        hit = None
        if cfg.get("watch_eq_exe", True):
            hit = check_eq_exe(cfg, state)
        if hit is None:
            hit = check_inbox(cfg, state)
        url_hit = check_url(cfg, state)
        save_state(state)                      # persist baselines even when nothing fired

        if url_hit:
            notify(cfg, ":rotating_light: Sentinel: **watch_url changed** - patch day is likely LIVE. "
                        "Waiting for the new eqgame.exe (local install patch or inbox drop).")
            append_history({"event": "url-changed", "fp": url_hit["fp"]}, cfg["history_keep"])

        if hit is None:
            log("tick: no new client build.")
            return 0

        run_pipeline(cfg, state, hit, dry_run=dry_run)
        save_state(state)
        return 0
    finally:
        release_lock()


def cmd_watch(interval):
    log("watch mode: tick every %ds (Ctrl+C to stop)" % interval)
    while True:
        try:
            cmd_tick()
        except Exception as e:
            log("tick raised: %s" % e)
        time.sleep(interval)


def cmd_status():
    cfg = load_config()
    state = load_state() if os.path.exists(STATE_PATH) else {}
    print("EQMQ Sentinel status")
    print("-" * 64)
    print("  config:        %s" % ("sentinel.config.json" if os.path.exists(CONFIG_PATH)
                                   else "(defaults - copy sentinel.config.example.json)"))
    print("  last tick:     %s" % state.get("last_tick", "(never)"))
    eq = state.get("eq_exe", {})
    st = eq.get("stamp", {})
    print("  eq_exe seen:   %s %s (sha %s)" % (st.get("date", "-"), st.get("time", "") or "",
                                               (eq.get("sha256") or "")[:12] or "-"))
    print("  auto_analyze:  %s    auto_apply: %s (gate %.0f%%)    auto_build: %s" % (
        cfg.get("auto_analyze"), cfg.get("auto_apply"),
        100 * cfg.get("apply_min_coverage", 0.92), cfg.get("auto_build")))
    pend = state.get("pending")
    if pend:
        print("  PENDING:       build %s - %s" % (pend.get("tag"), pend.get("phase")))
        cov = pend.get("coverage") or {}
        if cov:
            print("                 coverage %.1f%% (%d/%d, %d unmatched)" % (
                100 * cov.get("coverage", 0), cov.get("matched", 0),
                cov.get("total", 0), cov.get("unmatched", 0)))
        print("                 -> review out\\coverage_report.csv then: python sentinel.py approve")
    else:
        print("  pending:       (none)")
    if os.path.exists(HISTORY_PATH):
        lines = [ln for ln in open(HISTORY_PATH, encoding="utf-8").read().split("\n") if ln.strip()]
        print("  history:       %d records; last 3:" % len(lines))
        for ln in lines[-3:]:
            try:
                r = json.loads(ln)
                print("                 %s  %-22s %s" % (r.get("at"), r.get("event"), r.get("tag", "")))
            except Exception:
                pass
    lock = os.path.exists(LOCK_PATH)
    print("  lock:          %s" % ("HELD (run in progress)" if lock else "free"))
    return 0


def cmd_approve():
    """Human said 'the coverage looks good' - run apply for the pending analysis."""
    cfg = load_config()
    state = load_state() if os.path.exists(STATE_PATH) else {}
    pend = state.get("pending")
    if not pend:
        log("nothing pending to approve."); return 1
    tag = pend.get("tag", "unknown")
    if pend.get("phase") == "awaiting-analyze" or not os.path.exists(os.path.join(P.OUT, "eqgame_new.h")):
        # analysis never ran (auto_analyze off, disk block, or failed) - do it now
        if not acquire_lock():
            return 1
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            logfile = os.path.join(LOG_DIR, "sentinel-%s.log" % tag)
            notify(cfg, ":hourglass: Sentinel: approve -> running analysis for **%s** first..." % tag)
            rc = run_step("analyze", [sys.executable, os.path.join(TOOLKIT, "update_from_exe.py"),
                                      "analyze", pend["exe"]], logfile)
            if rc != 0:
                notify(cfg, ":x: Sentinel: analysis failed (exit %d) - see the log." % rc)
                return rc
        finally:
            release_lock()
    cov = parse_coverage() or {}
    cov_line = "%d/%d relocated (%.1f%%), %d unmatched" % (
        cov.get("matched", 0), cov.get("total", 0), 100 * cov.get("coverage", 0), cov.get("unmatched", 0))
    record = {"event": "approved", "tag": tag, "coverage": cov}
    os.makedirs(LOG_DIR, exist_ok=True)
    logfile = os.path.join(LOG_DIR, "sentinel-%s.log" % tag)
    _apply_and_finish(cfg, state, record, tag, pend.get("exe", ""), cov_line, logfile)
    save_state(state)
    return 0


def cmd_simulate(exe):
    """Force the full pipeline on a given exe - the end-to-end test knob."""
    if not os.path.exists(exe):
        log("exe not found: %s" % exe); return 2
    cfg = load_config()
    if not acquire_lock():
        return 1
    try:
        state = load_state() if os.path.exists(STATE_PATH) else {}
        hit = {"source": "simulate", "exe": exe, "fp": fingerprint_exe(exe)}
        run_pipeline(cfg, state, hit)
        save_state(state)
        return 0
    finally:
        release_lock()


def cmd_test_notify():
    cfg = load_config()
    ok = notify(cfg, ":wave: Sentinel test message - webhook wiring works. (%s)" % now_iso())
    log("webhook %s" % ("OK" if ok else "NOT CONFIGURED or failed (set %s or sentinel/%s)"
                        % (cfg.get("webhook_env"), cfg.get("webhook_file"))))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="EQMQ Sentinel patch-day watchdog")
    sub = ap.add_subparsers(dest="cmd")
    t = sub.add_parser("tick");  t.add_argument("--dry-run", action="store_true")
    w = sub.add_parser("watch"); w.add_argument("--interval", type=int, default=600)
    sub.add_parser("status")
    sub.add_parser("approve")
    s = sub.add_parser("simulate"); s.add_argument("exe")
    sub.add_parser("test-notify")
    a = ap.parse_args()
    if a.cmd == "tick":
        sys.exit(cmd_tick(dry_run=a.dry_run))
    elif a.cmd == "watch":
        cmd_watch(a.interval)
    elif a.cmd == "status":
        sys.exit(cmd_status())
    elif a.cmd == "approve":
        sys.exit(cmd_approve())
    elif a.cmd == "simulate":
        sys.exit(cmd_simulate(a.exe))
    elif a.cmd == "test-notify":
        sys.exit(cmd_test_notify())
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
