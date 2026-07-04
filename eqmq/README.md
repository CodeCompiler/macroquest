# EQMQ Offset Toolkit

Reverse-engineering + **offset-relocation ("patcher")** tooling that keeps
[MacroQuest](https://github.com/macroquest/macroquest) compiling across EverQuest client
patches — the moment Daybreak ships a new `eqgame.exe`, this turns it back into a working
`eqgame.h` with minimal human effort.

🌐 **[mmoplugins.com](https://mmoplugins.com)** &nbsp;·&nbsp; 💬 **[Discord](https://discord.gg/35zf9zNH32)** — browse the live catalogs (offsets, functions, opcodes, structures), submit a client to get a header/build back, and get help.

> Scope: **official-patch maintenance only.** It relocates the memory offsets MacroQuest
> already needs and rebuilds the tool — it ships offsets + our own compiled binaries, never
> the game client and never any character/account data. Generated data, secrets, and
> per-character files are intentionally excluded from this repo.

---

## The patcher — what it does

**The problem.** Every EverQuest patch relinks `eqgame.exe`, so every hardcoded address in
MacroQuest's `eqlib/offsets/eqgame.h` moves. Until those ~1,800 offsets are updated, MacroQuest
won't build or run. Done by hand in a disassembler, that's hours of tedious re-identification
on every patch day.

**The idea.** A function's *machine code* barely changes across a patch even though its
*address* does. So we fingerprint each known function by a **masked byte signature** (opcodes
kept, address/immediate operands wildcarded) plus its size. On the new binary we find each
function by its signature and read off its new address — offsets relocate themselves.

**The flow** (`offset-toolkit/update_from_exe.py`):

```
python update_from_exe.py analyze  <new eqgame.exe>
    # 1. detect the client build/version stamp from the binary
    # 2. Ghidra headless-analyzes the new client (the slow part)
    # 3. relocate offsets:
    #      - from the signature fingerprint DB (superbaseline.py), OR
    #      - bootstrap by diffing against the newest archived known-good client
    # -> out/eqgame_new.h              (proposed header)
    #    out/coverage_report.csv       (name, old_va, new_va, kind, confidence)
    #    out/incoming_stamp.json       (detected version date/time)

python update_from_exe.py apply
    # backs up eqgame.h, writes the proposed offsets, and bumps
    # __ExpectedVersionDate / __ExpectedVersionTime / __ClientDate.
    # SAFETY: refuses to apply a header that lost >10% of its offsets (a bad/partial
    # analysis), so a garbage relocation can never overwrite a good header.
```

Then you rebuild MacroQuest and verify in-game. Only *offsets* + the version stamp are
auto-generated; genuine struct/API drift (a renamed eqlib field) still surfaces at build time
for a human — by design.

### Patcher components (`offset-toolkit/`)
| File | Role |
|---|---|
| `update_from_exe.py` | end-to-end orchestrator: analyze → relocate → apply |
| `superbaseline.py` | the signature **fingerprint DB** + relocation engine |
| `offsettool.py` | Ghidra snapshot / diff / suggest operations |
| `offset_update_server.py` | web endpoint to submit a client binary and get a header back |
| `ghidra_export.py`, `ghidra_export.java`, `ghidra_deep_export.java`, `decompile_export.java` | Ghidra headless exporters (functions, RTTI, struct/vtable layouts, decompiled C) |
| `Auto-Update-Build.ps1`, `Diff-Offsets.ps1`, `Archive-Offsets.ps1`, `Archive-Client.ps1` | patch-day automation, offset diffs, and known-good client/offset archiving |
| `eqmq_paths.py` | portable path resolver (Ghidra/JDK/EQ/MQ), so the kit runs anywhere |
| `jsonstore.py` | crash-safe atomic JSON writes (protects the knowledge base) |

## The catalog pipeline (`pipeline/`)
Turns the Ghidra exports into a browsable, self-improving catalog:

- `crossversion_db.py` — the **self-sufficiency core**: keys every labelled function by
  signature into a durable knowledge base (`kb.json`) so names/classes learned on one client
  are **carried forward** to every future client automatically — you never re-label twice.
- `build_funcatalog.py` / `build_structs.py` / `build_structheaders.py` — whole-game function
  catalog, struct catalog, and downloadable C++ struct headers.
- `build_wiki.py` / `build_macros.py` — plugin + macro/lua library builders.
- `refresh_prep.py` / `refresh.ps1` — the driver that runs the pipeline end to end.
- `ai_namer.py` — optional AI-assisted naming of the still-unlabeled functions (Anthropic
  Batches API); names land at the lowest priority so any human/RTTI label always wins.
  Requires `ANTHROPIC_API_KEY` in the environment.

## Requirements
- **Ghidra** (headless) + **JDK 21**
- **Python 3.x** (stdlib only for the toolkit; `anthropic` for the optional AI naming)
- **MSVC v143** toolchain to rebuild MacroQuest

Paths default to a reference Windows layout; override the constants at the top of each script,
or point `eqmq_paths.py` at your install (env vars / `eqmq.config.ini`).

## What is *not* here
Generated artifacts (`kb.json`, `decompiled.json`, catalogs), secrets/config, and any
character/account data are gitignored and never committed — this repo is source only.

## Community & links
- **Website:** [mmoplugins.com](https://mmoplugins.com) — live offset/function/opcode/struct
  catalogs, per-symbol browsing, submit-a-client → get an `eqgame.h`/build, and the shared
  per-patch MacroQuest compile.
- **Discord:** [discord.gg/35zf9zNH32](https://discord.gg/35zf9zNH32) — updates, help, and
  transparency on what the engine is doing each patch day.
