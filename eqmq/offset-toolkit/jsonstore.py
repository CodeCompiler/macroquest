#!/usr/bin/env python3
"""
jsonstore.py -- crash-safe JSON persistence for the MMOPlugins engine.

Two problems this fixes (both real permanent-loss surfaces in the offset pipeline):
  1. Non-atomic writes: `json.dump(obj, open(path, "w"))` truncates `path` to zero and
     then streams into it. A crash / power-loss / disk-full mid-write leaves a truncated
     (corrupt) file -- and for kb.json (the cross-version knowledge base) or ai_names.json
     (paid AI output) that is irreplaceable accumulated value.
  2. Swallow-then-reseed-empty: loaders that do `try: json.load(...) except: return {}`
     turn a *corrupt* file into an *empty* default, and the next write then persists the
     empty object -- silently destroying everything that WAS there.

API:
  atomic_dump(obj, path, indent=None)      -- temp-write + fsync + os.replace (atomic),
                                              keeping the prior file as path + ".bak".
  dump_guarded(obj, path, count_fn, ...)   -- atomic_dump that REFUSES to overwrite a
                                              populated file with a (near-)empty one.
  safe_load(path, default=..., ...)        -- load; on corruption fall back to .bak and
                                              RESTORE it; if neither is usable, raise
                                              (fail loud) instead of silently returning {}.

Pure stdlib (json, os, shutil, tempfile) so it runs anywhere the pipeline runs.
"""
import os, json, shutil, tempfile

_MISSING = object()


def atomic_dump(obj, path, indent=None, keep_bak=True):
    """Write `obj` as JSON to `path` atomically. `path` always points at either the old
    complete file or the new complete file -- never a truncated one. Keeps the previous
    contents at `path + '.bak'` (last-known-good) so a bad run is recoverable."""
    path = os.path.abspath(path)
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    # keep the current file as .bak BEFORE we touch anything (copy, not move -> no gap)
    if keep_bak and os.path.exists(path):
        try:
            shutil.copy2(path, path + ".bak")
        except Exception:
            pass  # a missing .bak must never block a write
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)          # atomic on the same volume
        tmp = None
    finally:
        if tmp and os.path.exists(tmp):
            try: os.remove(tmp)
            except Exception: pass


def dump_guarded(obj, path, count_fn, indent=None, allow_empty=False):
    """atomic_dump, but refuses to overwrite a populated file with an empty object -- the
    classic 'silent reseed empty' data-loss bug. `count_fn(obj) -> int` counts the payload
    (e.g. len(kb['entries'])). Pass allow_empty=True (or env MMO_ALLOW_EMPTY=1) to override."""
    new_n = count_fn(obj)
    if new_n == 0 and not allow_empty and os.environ.get("MMO_ALLOW_EMPTY") != "1" and os.path.exists(path):
        try:
            old_n = count_fn(json.load(open(path, encoding="utf-8")))
        except Exception:
            old_n = 0
        if old_n > 0:
            raise RuntimeError(
                "jsonstore: REFUSING to write empty %s over %d existing items (likely a bug). "
                "Set allow_empty / MMO_ALLOW_EMPTY=1 if this is intentional." % (path, old_n))
    atomic_dump(obj, path, indent=indent)


def safe_load(path, default=_MISSING, restore_bak=True):
    """Load JSON from `path`. Missing file -> `default` (or FileNotFoundError if no default,
    the normal first-run case). If the file EXISTS but is corrupt, fall back to `path.bak`
    and RESTORE it over the corrupt main; if neither parses, raise RuntimeError (fail loud)
    so we never silently treat accumulated data as empty."""
    if not os.path.exists(path):
        if default is _MISSING:
            raise FileNotFoundError(path)
        return default
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception as e:
        bak = path + ".bak"
        if restore_bak and os.path.exists(bak):
            try:
                data = json.load(open(bak, encoding="utf-8"))
                shutil.copy2(bak, path)   # heal the corrupt main from the good backup
                return data
            except Exception:
                pass
        raise RuntimeError(
            "jsonstore: %s is corrupt and no usable .bak exists -- refusing to continue "
            "(would lose data). Restore from a backup zip in C:\\mmoplugins-backups." % path) from e


if __name__ == "__main__":
    # tiny self-test
    import sys
    p = os.path.join(tempfile.gettempdir(), "_jsonstore_selftest.json")
    atomic_dump({"entries": {"a": 1, "b": 2}}, p, indent=1)
    assert safe_load(p)["entries"]["b"] == 2
    try:
        dump_guarded({"entries": {}}, p, lambda o: len(o.get("entries", {})))
        print("FAIL: empty-write guard did not fire"); sys.exit(1)
    except RuntimeError:
        pass
    os.remove(p)
    if os.path.exists(p + ".bak"): os.remove(p + ".bak")
    print("jsonstore self-test OK")
