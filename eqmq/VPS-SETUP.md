# EQMQ on your own VPS — complete setup guide

This walks you from a **blank Windows VPS** to a self-running offset platform:
the moment EverQuest patches, **Sentinel** notices, Ghidra-analyzes the new
client, relocates every MacroQuest offset by byte-signature, gates the result
behind a coverage check, (optionally) applies + rebuilds, archives the build,
and posts every step to your Discord.

🌐 [mmoplugins.com](https://mmoplugins.com) · 💬 [Discord](https://discord.gg/35zf9zNH32)
— the reference deployment of this exact stack, and where to get help.

```
                         ┌──────────────────────────────────────────────┐
  EQ patches ──────────► │ SENTINEL (scheduled task, every 10 min)      │
                         │  detectors: local eqgame.exe hash            │
  eqgame.exe dropped ──► │             inbox/ folder                    │
  into inbox/            │             optional URL fingerprint         │
                         └──────────────┬───────────────────────────────┘
                                        │ new build detected
                                        ▼
   quarantine copy ─► Ghidra analyze (1–3 h) ─► signature relocation
                                        │
                                        ▼
                          coverage gate (default 92%)
                          │                        │
              gated: Discord ping,        cleared + auto_apply=true:
              human runs `approve`        apply → optional build
                          │                        │
                          └──────────┬─────────────┘
                                     ▼
                 eqgame.h updated + version-stamped, client archived,
                 ✅ posted to Discord — rebuild/verify in-game
```

---

## 1. VPS requirements

| Resource | Minimum | Recommended | Why |
|---|---|---|---|
| OS | Windows Server 2019 | Windows Server 2022 | toolkit is Windows-native (schtasks, PowerShell, MSVC) |
| CPU | 4 cores | 8 cores | Ghidra headless analysis is the bottleneck |
| RAM | 8 GB | 16 GB | Ghidra wants 4–8 GB heap for a ~60 MB client binary |
| Disk | 60 GB | 150+ GB SSD | each archived client ≈ 100 MB; Ghidra projects grow to GBs |
| Network | any | any | only needed for webhook posts + (optional) URL watch |

A patch analysis takes **1–3 hours** on 4 cores; roughly half that on 8.

## 2. Install prerequisites

All installs below are one-time. Elevated PowerShell:

```powershell
# --- Git + Python 3.11+ (any 3.x works; toolkit is stdlib-only) ---
winget install --id Git.Git -e
winget install --id Python.Python.3.12 -e

# --- JDK 21 (Temurin) — required by Ghidra headless ---
winget install --id EclipseAdoptium.Temurin.21.JDK -e

# --- Ghidra (11.x or 12.x) ---
# Download the release zip from https://github.com/NationalSecurityAgency/ghidra/releases
# and extract, e.g. to C:\ghidra\ghidra_12.1.2_PUBLIC
Expand-Archive ghidra_12.1.2_PUBLIC_*.zip -DestinationPath C:\ghidra
```

Optional (only if the VPS should also **compile MacroQuest** after applying
offsets): install Visual Studio 2022 Build Tools with the *Desktop development
with C++* workload (MSVC v143) + Windows SDK.

Optional (only for the AI-assisted naming in the catalog pipeline):
`pip install anthropic` and set `ANTHROPIC_API_KEY` in the environment.

## 3. Get the code

```powershell
git clone https://github.com/macroquest/macroquest.git C:\MQ2\macroquest
cd C:\MQ2\macroquest
git submodule update --init --recursive
```

Everything in this guide lives under `eqmq\`:

```
eqmq\
├── offset-toolkit\    the patcher: analyze / relocate / apply
├── sentinel\          the patch-day watchdog (this guide, section 5)
├── pipeline\          optional: browsable catalogs + cross-version KB
├── README.md          what the patcher is and how it works
└── VPS-SETUP.md       this file
```

## 4. Configure paths

The toolkit resolves every external path (Ghidra, JDK, EverQuest, MacroQuest
source) via `offset-toolkit\eqmq_paths.py` — in order: **environment variable →
`eqmq.config.ini` → auto-detection**.

```powershell
cd C:\MQ2\macroquest\eqmq\offset-toolkit
python eqmq_paths.py check          # shows what resolved and what's missing
python eqmq_paths.py write-config   # writes a starter eqmq.config.ini to edit
```

Example `eqmq.config.ini` for a VPS that has an EverQuest install (so it can
self-detect patches) — every value can also be set via the matching `EQMQ_*`
environment variable:

```ini
[paths]
ghidra_headless = C:\ghidra\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat
jdk21_home      = C:\Program Files\Eclipse Adoptium\jdk-21.0.5.11-hotspot
eq_exe          = C:\EverQuest\eqgame.exe
macroquest_src  = C:\MQ2\macroquest
eqgame_h        =                       ; blank = derived from macroquest_src
analysis_timeout = 0
```

> **No EQ install on the VPS?** Fine — leave `eq_exe` blank and feed Sentinel
> through its **inbox** instead (scp/robocopy the new `eqgame.exe` into
> `eqmq\sentinel\inbox\` from any machine that has the game; Sentinel does the
> rest). Never commit or redistribute the client binary itself.

Re-run `python eqmq_paths.py check` until everything you need shows `[ok ]`.

## 5. Seed the baseline (one-time)

The relocation engine needs a **known-good pair** — a client binary whose
offsets in `src\eqlib\include\eqlib\offsets\eqgame.h` are correct — to build
its signature fingerprint DB (`baseline_db.json`). With the current MacroQuest
source checked out, the current live client *is* that pair:

```powershell
cd C:\MQ2\macroquest\eqmq\offset-toolkit
# archive the current known-good client (also your rollback point)
powershell -File .\Archive-Client.ps1

# 1) Ghidra-analyze the CURRENT client under a label (the slow, one-time part)
python offsettool.py snapshot baseline

# 2) fingerprint every offset in eqgame.h against that export
#    (eqgame.h MUST match the client version you just snapshotted)
python superbaseline.py seed baseline
```

When it finishes, `baseline_db.json` exists and every future patch relocates
from signatures in minutes of CPU (after the one Ghidra analysis of the new
binary). Without a seeded DB the toolkit falls back to bootstrap-diffing
against the newest archived client — slower (two Ghidra runs) but works.

## 6. Install Sentinel

```powershell
cd C:\MQ2\macroquest\eqmq\sentinel
powershell -ExecutionPolicy Bypass -File .\Install-Sentinel.ps1
```

That registers scheduled task **`eqmq-sentinel`** (SYSTEM, every 10 min,
`python sentinel.py tick`), creates `inbox\` / `logs\` / `quarantine\`, and
seeds `sentinel.config.json` from the example. A tick with nothing new is a
sub-second hash check — the heavy work only fires on a real patch. The first
tick **baselines** your current client so only *future* patches trigger.

### Configuration reference (`sentinel.config.json`)

| Key | Default | Meaning |
|---|---|---|
| `watch_eq_exe` | `true` | watch the local EQ install's `eqgame.exe` for changes |
| `eq_exe` | `""` | override the exe to watch (blank = resolve via `eqmq_paths`) |
| `inbox_dir` | `"inbox"` | folder watched for dropped `*.exe` (relative to `sentinel\`) |
| `watch_url` | `""` | optional URL; ETag/Last-Modified/body change ⇒ "patch is live" alert (alert-only) |
| `auto_analyze` | `true` | start the Ghidra analysis automatically on detection |
| `auto_apply` | `false` | **the big switch** — write `eqgame.h` automatically when the gate clears |
| `apply_min_coverage` | `0.92` | fraction of offsets that must relocate before auto-apply is considered |
| `auto_build` | `false` | run `build_command` after a successful apply |
| `build_command` | `""` | e.g. `powershell -File C:\path\to\Build-MacroQuest.ps1 -Plugins` |
| `archive_clients` | `true` | keep exe + header + coverage under `versions\archive\<tag>\` |
| `webhook_env` / `webhook_file` | `SENTINEL_WEBHOOK` / `webhook.txt` | where the Discord webhook URL comes from |
| `min_free_gb` | `10` | refuse to start an analysis with less free disk |
| `history_keep` | `200` | records kept in `sentinel.history.jsonl` |

**Recommended posture:** run your first two or three patch days with
`auto_apply: false`. Sentinel detects, analyzes, and posts the coverage to
Discord; you eyeball `offset-toolkit\out\coverage_report.csv` and run
`python sentinel.py approve`. Once you trust the coverage numbers, flip
`auto_apply` (and optionally `auto_build`) to `true` for a fully hands-off
patch day. Two independent safety gates always remain: Sentinel's coverage
threshold **and** the toolkit's own refuse-to-apply-if->10%-missing abort.

## 7. Discord notifications

1. In your Discord server: *Server Settings → Integrations → Webhooks → New
   Webhook*, pick the channel, copy the URL.
2. On the VPS, either:
   ```powershell
   Set-Content C:\MQ2\macroquest\eqmq\sentinel\webhook.txt "https://discord.com/api/webhooks/..."
   ```
   or set a system-wide `SENTINEL_WEBHOOK` environment variable.
3. Test: `python sentinel.py test-notify`

`webhook.txt` is gitignored — the URL is a secret (anyone holding it can post
to your channel). Never commit it.

## 8. Verify the whole pipeline

```powershell
cd C:\MQ2\macroquest\eqmq\sentinel

python sentinel.py status              # state summary: last tick, baselines, pending
python sentinel.py tick --dry-run      # detection pass that never analyzes/applies

# full end-to-end rehearsal against a binary you already have
# (re-analyzing the CURRENT client is a valid test: expect ~100% coverage)
python sentinel.py simulate C:\EverQuest\eqgame.exe
```

`Sentinel-Status.ps1` gives the ops view: task state + sentinel state + tail
of the newest per-build log in `logs\`.

## 9. What patch day looks like

With the default (gated) posture:

1. `:rotating_light:` *(only if `watch_url` set)* — patch detected as live.
2. `:satellite:` **new client build detected** — Sentinel found the new exe
   (install watch or inbox drop), quarantined a copy.
3. `:hourglass:` **analysis started** — Ghidra headless, 1–3 h.
4. `:pause_button:` **GATED** — coverage summary posted
   (`1742/1800 relocated (96.8%), 1650 high / 92 medium, 58 unmatched`).
   You review `out\coverage_report.csv`, then:
   ```powershell
   python sentinel.py approve
   ```
5. `:white_check_mark:` **offsets APPLIED** — `eqgame.h` backed up, rewritten,
   version-stamped; client archived. Rebuild MacroQuest and **verify in-game
   on a throwaway login** before trusting the build.

With `auto_apply` + `auto_build` on, steps 4–5 collapse into an automatic
apply + build, and the only human step left is the in-game verification.

Struct/API drift (a renamed eqlib field, a changed struct layout) is **out of
scope by design** — offsets and version stamp are automated; if the patch also
changed source-level APIs, the build fails loudly and a human fixes the source.

## 10. Optional: the catalog pipeline + submission endpoint

- `pipeline\refresh.ps1` — rebuilds the browsable catalogs (functions, opcodes,
  structs, downloadable headers) from the Ghidra exports, and carries every
  learned function name forward across versions via `kb.json`.
- `offset-toolkit\offset_update_server.py` — a minimal web endpoint where users
  submit a client binary and get a proposed header back (the self-serve version
  of Sentinel's inbox). Put it behind a reverse proxy (Caddy/nginx) with TLS
  and auth if you expose it publicly.

Both are optional — Sentinel + the toolkit are fully functional without them.

## 11. Hardening & operations checklist

- **Secrets:** webhook URLs, API keys, and any credentials live in env vars or
  gitignored files (`webhook.txt`, `eqmq.config.ini`) — never in the repo.
- **Never commit:** the game client, generated data, or anything
  character/account-related. The provided `.gitignore` already enforces this.
- **Firewall:** the base platform needs **no inbound ports**. Only open 443
  (behind a reverse proxy) if you deploy the optional submission endpoint.
- **Backups:** back up `baseline_db.json`, `kb.json`, `versions\archive\`, and
  `sentinel\sentinel.history.jsonl` — that's the accumulated knowledge. A daily
  zip to a second disk/bucket is plenty (state files are written atomically
  with last-known-good `.bak` siblings via `jsonstore.py`).
- **Disk watch:** archives + Ghidra projects grow; Sentinel refuses to start an
  analysis under `min_free_gb`, but prune `ghidra_projects\` and old archives
  periodically.
- **Updates:** `git pull` the MacroQuest source before applying offsets on
  patch day, so upstream source fixes and your relocated header land together.

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `eqmq_paths` shows `MISS` for Ghidra/JDK | set the path in `eqmq.config.ini` or the `EQMQ_GHIDRA` / `EQMQ_JDK21` env var |
| Sentinel never detects the patch | `eq_exe` unresolved (check `sentinel.py status` baselines), or the launcher hasn't actually patched — drop the exe in `inbox\` to force it |
| tick says "another Sentinel run holds the lock" | an analysis is in progress (normal, 1–3 h). Locks >6 h are treated as stale and taken over automatically |
| analysis FAILED in the log | almost always Ghidra/JDK pathing or heap — open `logs\sentinel-<tag>.log`; test Ghidra alone with `analyzeHeadless.bat` |
| coverage far below the gate | client changed more than usual, or the baseline DB is stale — reseed `superbaseline.py seed` from the last known-good pair, review unmatched rows in `coverage_report.csv` |
| apply exits 5 | the toolkit's own safety abort: proposed header lost >10% of offsets — a bad/partial analysis; nothing was written |
| build fails after a clean apply | struct/API drift — a source-level change needs a human fix; offsets are already applied + stamped |
| no Discord posts | `python sentinel.py test-notify`; check `webhook.txt` / `SENTINEL_WEBHOOK`, and that outbound HTTPS isn't blocked |

---

*Questions, or want to see this stack running live? [mmoplugins.com](https://mmoplugins.com) · [discord.gg/35zf9zNH32](https://discord.gg/35zf9zNH32)*
