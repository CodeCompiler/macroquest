<#
  Diff-Offsets.ps1  --  compare two cataloged eqgame.h snapshots and report exactly which
  offsets moved, were added, or were removed between two EverQuest client builds. This is
  how you "find where injection changes happen" across a patch.

  USAGE:
    .\Diff-Offsets.ps1                       # diff the two NEWEST cataloged builds
    .\Diff-Offsets.ps1 2026-03-10 2026-06-24 # diff two specific dated snapshots

  Reads offset-history\<date>\eqgame.h. Writes a report to offset-history\diffs\.
#>
param([string]$From = "", [string]$To = "")
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$HIST = Join-Path $here "offset-history"
$DIFFS = Join-Path $HIST "diffs"

if (-not (Test-Path $HIST)) { Write-Host "No offset-history yet. Run Archive-Offsets.ps1 first." -ForegroundColor Red; exit 1 }

# pick newest two dated dirs if not specified
$dirs = Get-ChildItem $HIST -Directory | Where-Object { Test-Path (Join-Path $_.FullName "eqgame.h") } | Sort-Object Name
if (-not $From -or -not $To) {
    if ($dirs.Count -lt 2) { Write-Host "Need at least 2 cataloged builds to diff (have $($dirs.Count))." -ForegroundColor Yellow; exit 1 }
    $From = $dirs[-2].Name; $To = $dirs[-1].Name
}
$fH = Join-Path $HIST "$From\eqgame.h"
$tH = Join-Path $HIST "$To\eqgame.h"
if (-not (Test-Path $fH)) { Write-Host "Not cataloged: $From" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $tH)) { Write-Host "Not cataloged: $To"   -ForegroundColor Red; exit 1 }

function Parse-Offsets($path) {
    $h = @{}
    foreach ($line in (Get-Content $path)) {
        $m = [regex]::Match($line, '^#define\s+(\S+)\s+(0x[0-9A-Fa-f]+)')
        if ($m.Success) { $h[$m.Groups[1].Value] = $m.Groups[2].Value }
    }
    return $h
}
function Stamp($path, $pat) { $m = [regex]::Match((Get-Content $path -Raw), $pat); if ($m.Success) { $m.Groups[1].Value } else { "" } }

$a = Parse-Offsets $fH
$b = Parse-Offsets $tH

$changed = @(); $added = @(); $removed = @()
foreach ($k in $a.Keys) {
    if ($b.ContainsKey($k)) { if ($a[$k] -ne $b[$k]) { $changed += [pscustomobject]@{ name=$k; old=$a[$k]; new=$b[$k] } } }
    else { $removed += $k }
}
foreach ($k in $b.Keys) { if (-not $a.ContainsKey($k)) { $added += $k } }

$fStamp = Stamp $fH '__ExpectedVersionDate\s+"([^"]+)"'
$tStamp = Stamp $tH '__ExpectedVersionDate\s+"([^"]+)"'

Write-Host ""
Write-Host "Offset diff: $From ($fStamp)  ->  $To ($tStamp)" -ForegroundColor Cyan
Write-Host ("  total offsets:  {0} -> {1}" -f $a.Count, $b.Count)
Write-Host ("  CHANGED (moved): {0}" -f $changed.Count) -ForegroundColor Yellow
Write-Host ("  ADDED:           {0}" -f $added.Count)   -ForegroundColor Green
Write-Host ("  REMOVED:         {0}" -f $removed.Count) -ForegroundColor Red
Write-Host ("  unchanged:       {0}" -f ($a.Count - $changed.Count - $removed.Count))

# write report
New-Item -ItemType Directory -Force $DIFFS | Out-Null
$report = Join-Path $DIFFS ("{0}__to__{1}.md" -f $From, $To)
$md = @()
$md += "# Offset diff: $From -> $To"
$md += ""
$md += "- **$From**  build ``$fStamp``  ($($a.Count) offsets)"
$md += "- **$To**  build ``$tStamp``  ($($b.Count) offsets)"
$md += ""
$md += "**Changed (moved): $($changed.Count) | Added: $($added.Count) | Removed: $($removed.Count) | Unchanged: $($a.Count - $changed.Count - $removed.Count)**"
$md += ""
if ($changed.Count) {
    $md += "## Changed offsets (injection points that moved)"
    $md += ""
    $md += "| offset | old VA | new VA |"
    $md += "|---|---|---|"
    foreach ($c in ($changed | Sort-Object name)) { $md += "| $($c.name) | $($c.old) | $($c.new) |" }
    $md += ""
}
if ($added.Count)   { $md += "## Added offsets"; $md += ""; foreach ($k in ($added | Sort-Object))   { $md += "- $k" }; $md += "" }
if ($removed.Count) { $md += "## Removed offsets"; $md += ""; foreach ($k in ($removed | Sort-Object)) { $md += "- $k" }; $md += "" }
$md -join "`r`n" | Out-File $report -Encoding utf8

Write-Host "`nReport -> $report" -ForegroundColor Cyan
