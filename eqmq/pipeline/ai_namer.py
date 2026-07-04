#!/usr/bin/env python3
"""
ai_namer.py -- AI classification/naming of the ~17k UNLABELED eqgame.exe functions.

For each unlabeled function it feeds Claude the evidence we have -- decompiled C, referenced
string literals, data-ref count, size -- and asks for a proposed name, category, one-line
purpose, and a CONFIDENCE score. Results land in ai_names.json and are consumed by
crossversion_db.py at the lowest source priority (so human/RTTI/observed labels always win),
which means an AI guess is a starting point a reviewer can confirm via the existing review queue,
never an authoritative overwrite.

Model: claude-opus-4-8 with adaptive thinking + structured output (json_schema). Scale path uses
the Message Batches API (50% cost, async). Requires ANTHROPIC_API_KEY in the environment.

    python ai_namer.py sync   [N]      name N unlabeled funcs synchronously (proof / small runs)
    python ai_namer.py batch-create [N] create a Batches job for up to N unlabeled funcs -> ai_batch.json
    python ai_namer.py batch-collect    poll the saved batch + merge results into ai_names.json
"""
import os, sys, csv, json, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jsonstore   # crash-safe atomic writes (protects ai_names.json = paid AI output)

MMO        = r"C:\mmoplugins"
FUNC_CSV   = os.path.join(MMO, "function_catalog.csv")      # va,label,source,strings,size,datarefs
DECOMPILED = os.path.join(MMO, "decompiled.json")           # va -> C
XVER       = os.path.join(MMO, "crossversion_labels.json")  # va -> {label,...} (already-labelled)
OUT        = os.path.join(MMO, "ai_names.json")             # va -> {name,category,purpose,confidence,model}
BATCH_REF  = os.path.join(MMO, "ai_batch.json")             # {batch_id, cidmap:{...}}
CONFIG     = os.path.join(MMO, "mmoplugins.config.json")    # VPS-only; holds anthropic_api_key + ai_model

def _cfg():
    try: return json.load(open(CONFIG, encoding="utf-8"))
    except Exception: return {}

def _client():
    """Anthropic client using ANTHROPIC_API_KEY env, else the key saved in mmoplugins.config.json."""
    import anthropic
    key = os.environ.get("ANTHROPIC_API_KEY") or _cfg().get("anthropic_api_key")
    return anthropic.Anthropic(api_key=key) if key else anthropic.Anthropic()

# naming is an easy task -> default to the cheap model; override via config "ai_model"
MODEL = _cfg().get("ai_model") or "claude-haiku-4-5"
CATEGORIES = ["Combat, Skills & Casting", "Spells & Casting", "Alternate Advancement (AA)",
              "Items & Inventory", "Spawns & Actors", "Character & Profile", "UI / Windows",
              "Core Game", "Other / Unclassified"]

SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Proposed function name, Class::method or snake_case. Empty if no idea."},
        "category": {"type": "string", "enum": CATEGORIES},
        "purpose": {"type": "string", "description": "One concise sentence on what the function does."},
        "confidence": {"type": "number", "description": "0.0-1.0 confidence the name/category are correct."},
    },
    "required": ["name", "category", "purpose", "confidence"],
    "additionalProperties": False,
}
SYSTEM = (
    "You are a reverse-engineering analyst labelling functions in EverQuest's game client "
    "(eqgame.exe, MSVC x64). You are given the evidence recovered for ONE unnamed function: its "
    "decompiled C pseudocode, the string literals it references, how many data globals it touches, "
    "and its size. Propose the most likely function name (prefer a C++ `Class::method` form when the "
    "evidence implies a class, else a descriptive snake_case name), pick the best category, and write "
    "one concise sentence on its purpose. Set confidence honestly: 0.8+ only when strings or call "
    "patterns make it clear; 0.3-0.6 for an educated guess; <=0.2 and an empty name when the evidence "
    "is too thin. Never invent specifics the evidence doesn't support."
)

def load_json(p, d):
    try: return json.load(open(p, encoding="utf-8"))
    except Exception: return d

def is_placeholder(name):
    return (not name) or bool(re.match(r"^(FUN_|LAB_|SUB_|thunk_)", name or ""))

def select_unlabeled(limit):
    """Pick not-yet-properly-named functions (catalog source 'inferred' or 'unlabeled') with the
    most signal (decompiled C and/or referenced strings) first. 'inferred' funcs only carry a raw
    string fragment as a label, so they're prime targets for a real AI name."""
    labeled = set(k.lower() for k in load_json(XVER, {}).keys())
    dec = load_json(DECOMPILED, {})
    cands = []
    if not os.path.exists(FUNC_CSV):
        return [], dec
    for r in csv.DictReader(open(FUNC_CSV, encoding="utf-8", errors="replace", newline="")):
        va = (r.get("va") or "").strip().lower()
        if not va or va in labeled: continue
        src = (r.get("source") or "").strip().lower()
        if src not in ("inferred", "unlabeled"):     # named/observed/rtti/vtable/carried already labelled
            continue
        strings = r.get("strings", "") or ""
        has_c = va in dec
        signal = (2 if has_c else 0) + (1 if strings else 0)
        if signal == 0: continue   # no decompiled C and no strings -> nothing to go on yet
        cands.append((signal, len(strings), va, r))
    cands.sort(key=lambda x: (-x[0], -x[1]))
    return cands[:limit], dec

def build_user(va, row, dec):
    strings = (row.get("strings", "") or "").replace("|", " | ")
    parts = ["function VA: %s" % va,
             "size: %s bytes" % (row.get("size", "?")),
             "data refs: %s" % (len((row.get("datarefs", "") or "").split("|")) if row.get("datarefs") else 0)]
    if strings:
        parts.append("referenced strings: " + strings[:1500])
    c = dec.get(va) or dec.get(va.lower())
    if c:
        parts.append("decompiled C:\n" + (c[:6000]))
    return "\n".join(parts)

_THINKS = ("claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-sonnet-4-6", "claude-fable-5")

def make_params(va, row, dec):
    p = {
        "model": MODEL, "max_tokens": 1500,
        "system": SYSTEM,
        "output_config": {"format": {"type": "json_schema", "schema": SCHEMA}},
        "messages": [{"role": "user", "content": build_user(va, row, dec)}],
    }
    # adaptive thinking + effort are 4.6+/Opus/Sonnet/Fable features; Haiku 4.5 rejects them (400)
    if any(MODEL.startswith(m) for m in _THINKS):
        p["thinking"] = {"type": "adaptive"}
        p["output_config"]["effort"] = "low"
    return p

def parse_result(text):
    try:
        d = json.loads(text)
        return {"name": (d.get("name") or "").strip(), "category": d.get("category") or "Other / Unclassified",
                "purpose": (d.get("purpose") or "").strip(), "confidence": float(d.get("confidence", 0.0) or 0.0),
                "model": MODEL}
    except Exception:
        return None

def cmd_sync(limit):
    client = _client()
    cands, dec = select_unlabeled(limit)
    out = load_json(OUT, {})
    done = 0
    for _sig, _slen, va, row in cands:
        p = make_params(va, row, dec)
        try:
            resp = client.messages.create(**p)
            text = next((b.text for b in resp.content if b.type == "text"), "")
            r = parse_result(text)
            if r and r["name"]:
                out[va] = r; done += 1
                print("  %-14s -> %-40s (%.2f) %s" % (va, r["name"], r["confidence"], r["category"]))
        except Exception as e:
            print("  %-14s ERROR %s" % (va, e))
    jsonstore.dump_guarded(out, OUT, len, indent=1)   # atomic + never wipe names to empty
    print("ai_namer sync: named %d / %d candidates -> %s" % (done, len(cands), OUT))

def cmd_batch_create(limit):
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request
    client = _client()
    cands, dec = select_unlabeled(limit)
    if not cands:
        print("ai_namer batch-create: no unlabeled candidates with signal."); return
    reqs, cidmap = [], {}
    for _sig, _slen, va, row in cands:
        cid = va.replace("0x", "")[:64]            # bare hex (va is always lowercase 0x...)
        cidmap[cid] = va                            # lossless map back to the exact catalog key
        reqs.append(Request(custom_id=cid, params=MessageCreateParamsNonStreaming(**make_params(va, row, dec))))
    batch = client.messages.batches.create(requests=reqs)
    jsonstore.atomic_dump({"batch_id": batch.id, "cidmap": cidmap}, BATCH_REF)
    print("ai_namer batch-create: submitted %d functions, batch=%s status=%s"
          % (len(reqs), batch.id, batch.processing_status))

def cmd_batch_collect():
    client = _client()
    ref = load_json(BATCH_REF, {})
    bid = ref.get("batch_id")
    if not bid:
        print("ai_namer batch-collect: no saved batch (run batch-create first)."); return
    batch = client.messages.batches.retrieve(bid)
    print("batch %s status=%s" % (bid, batch.processing_status))
    if batch.processing_status != "ended":
        counts = batch.request_counts
        print("  not finished yet: processing=%s succeeded=%s errored=%s -- retry batch-collect later"
              % (counts.processing, counts.succeeded, counts.errored)); return
    cidmap = ref.get("cidmap", {})
    out = load_json(OUT, {})
    done = 0
    for result in client.messages.batches.results(bid):
        if result.result.type != "succeeded": continue
        msg = result.result.message
        text = next((b.text for b in msg.content if getattr(b, "type", "") == "text"), "")
        r = parse_result(text)
        if r and r["name"]:
            va = cidmap.get(result.custom_id) or ("0x" + result.custom_id)
            out[va] = r; done += 1
    jsonstore.dump_guarded(out, OUT, len, indent=1)   # atomic + never wipe names to empty
    print("ai_namer batch-collect: merged %d names -> %s" % (done, OUT))

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "sync"
    arg = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else None
    if cmd == "sync": cmd_sync(arg or 10)
    elif cmd == "batch-create": cmd_batch_create(arg or 5000)
    elif cmd == "batch-collect": cmd_batch_collect()
    else: print("usage: ai_namer.py [sync N | batch-create N | batch-collect]")

if __name__ == "__main__":
    main()
