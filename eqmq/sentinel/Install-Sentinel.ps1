<#
  Install-Sentinel.ps1 -- register EQMQ Sentinel as a Windows scheduled task.

  Creates the runtime folders (inbox/, logs/, quarantine/), seeds
  sentinel.config.json from the example if absent, then registers a task that
  runs `python sentinel.py tick` every N minutes as SYSTEM. The tick is cheap
  (hash checks); the Ghidra analysis only fires when a new client build shows
  up, and Sentinel's lockfile keeps overlapping ticks from stacking runs.

  Usage (elevated PowerShell):
    .\Install-Sentinel.ps1                          # every 10 min, task "eqmq-sentinel"
    .\Install-Sentinel.ps1 -IntervalMinutes 5
    .\Install-Sentinel.ps1 -Python "C:\Python312\python.exe"
    .\Install-Sentinel.ps1 -Uninstall
#>
param(
    [int]$IntervalMinutes = 10,
    [string]$TaskName = "eqmq-sentinel",
    [string]$Python = "",
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot

if ($Uninstall) {
    schtasks /Delete /TN $TaskName /F
    Write-Host "[sentinel] task '$TaskName' removed."
    exit 0
}

# --- resolve python -----------------------------------------------------------
if (-not $Python) {
    $cands = @()
    try { $cands += (Get-Command python.exe -ErrorAction Stop).Source } catch {}
    $cands += Get-ChildItem "C:\Python3*\python.exe" -ErrorAction SilentlyContinue |
              Sort-Object FullName -Descending | Select-Object -ExpandProperty FullName
    $Python = $cands | Where-Object { $_ } | Select-Object -First 1
}
if (-not $Python -or -not (Test-Path $Python)) {
    Write-Host "[sentinel] python.exe not found - pass -Python C:\path\to\python.exe"
    exit 1
}
Write-Host "[sentinel] python: $Python"

# --- runtime folders + config -------------------------------------------------
foreach ($d in @("inbox", "logs", "quarantine")) {
    $p = Join-Path $here $d
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}
$cfg = Join-Path $here "sentinel.config.json"
if (-not (Test-Path $cfg)) {
    Copy-Item (Join-Path $here "sentinel.config.example.json") $cfg
    Write-Host "[sentinel] seeded sentinel.config.json from the example - review it."
}

# --- sanity: toolkit paths ------------------------------------------------------
& $Python (Join-Path (Split-Path $here) "offset-toolkit\eqmq_paths.py") check
if ($LASTEXITCODE -ne 0) {
    Write-Host "[sentinel] WARNING: some toolkit paths unresolved (see above)."
    Write-Host "           Sentinel will still detect+quarantine builds, but analyze/apply"
    Write-Host "           need Ghidra/JDK/eqgame.h resolvable. Fix via eqmq.config.ini or EQMQ_* env vars."
}

# --- scheduled task -------------------------------------------------------------
$action = "`"$Python`" `"$here\sentinel.py`" tick"
schtasks /Create /F /TN $TaskName /SC MINUTE /MO $IntervalMinutes /RU SYSTEM /RL HIGHEST /TR $action
if ($LASTEXITCODE -ne 0) { Write-Host "[sentinel] schtasks create FAILED"; exit 1 }
Write-Host "[sentinel] task '$TaskName' -> tick every $IntervalMinutes min as SYSTEM."

# first tick now (baselines the current client so only FUTURE patches fire)
schtasks /Run /TN $TaskName | Out-Null
Start-Sleep -Seconds 5
& $Python (Join-Path $here "sentinel.py") status
Write-Host ""
Write-Host "[sentinel] installed. Next steps:"
Write-Host "  1. Put the Discord webhook in sentinel\webhook.txt (or set SENTINEL_WEBHOOK system-wide)."
Write-Host "  2. Test it:              python sentinel.py test-notify"
Write-Host "  3. End-to-end test:      python sentinel.py simulate C:\path\to\eqgame.exe"
Write-Host "  4. On patch day, watch Discord; approve gated applies with: python sentinel.py approve"
