<#
  Archive-Offsets.ps1  --  catalog a dated snapshot of eqgame.h (the offsets header)
  plus any "additionals" (source patches you had to apply for that client build) so the
  whole offset/injection-change history is preserved IN the kit and diffable later.

  Layout it maintains (all inside the toolkit, portable):
    offset-history\<YYYY-MM-DD>\eqgame.h          the offsets for that client build
    offset-history\<YYYY-MM-DD>\notes.md          stamps, sha, count, provenance
    offset-history\<YYYY-MM-DD>\patches\...        copies of additional files you patched
    offset-history\CATALOG.csv                     machine-readable index
    offset-history\CATALOG.md                      human-readable index (auto-rebuilt)

  USAGE:
    .\Archive-Offsets.ps1                                   # archive the CURRENT eqgame.h
    .\Archive-Offsets.ps1 -Source "RedGuides eqlib live @ f883eec"
    .\Archive-Offsets.ps1 -EqgameH C:\some\eqgame.h -Source "..." -Notes "..."
    .\Archive-Offsets.ps1 -Extra C:\MQ2\macroquest\src\main\MQ2WindowInspector.cpp -Notes "API-drift fix"

  eqgame.h is open-source offsets (e.g. from the RedGuides eqlib fork) - safe to keep here.
  The game CLIENT binary (eqgame.exe) is NOT stored here - use Archive-Client.ps1 for that.
#>
param(
    [string]$EqgameH = "",
    [string]$Source  = "",
    [string]$Notes   = "",
    [string[]]$Extra,
    [string]$DateOverride = ""
)
$ErrorActionPreference = "Stop"
$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$HIST    = Join-Path $here "offset-history"
$CSV     = Join-Path $HIST "CATALOG.csv"
New-Item -ItemType Directory -Force $HIST | Out-Null

if (-not $EqgameH) {
    $EqgameH = (& python (Join-Path $here "eqmq_paths.py") get EQGAME_H) 2>$null
}
if (-not $EqgameH -or -not (Test-Path $EqgameH)) {
    Write-Host "Could not resolve eqgame.h. Pass -EqgameH or run: python eqmq_paths.py check" -ForegroundColor Red
    exit 1
}

$text = Get-Content $EqgameH -Raw
function Grab($pat) { $m = [regex]::Match($text, $pat); if ($m.Success) { return $m.Groups[1].Value } return "" }
$clientNum  = Grab '__ClientDate\s+(\d{8})u'
$verDate    = Grab '__ExpectedVersionDate\s+"([^"]+)"'
$verTime    = Grab '__ExpectedVersionTime\s+"([^"]+)"'

# derive folder date (prefer the numeric __ClientDate -> YYYY-MM-DD)
if ($DateOverride) {
    $iso = $DateOverride
} elseif ($clientNum -match '^(\d{4})(\d{2})(\d{2})$') {
    $iso = "$($Matches[1])-$($Matches[2])-$($Matches[3])"
} elseif ($verDate) {
    try { $iso = ([datetime]::ParseExact(($verDate -replace '\s+',' ').Trim(),'MMM d yyyy',[Globalization.CultureInfo]::InvariantCulture)).ToString('yyyy-MM-dd') }
    catch { $iso = "unknown_" + (Get-Item $EqgameH).LastWriteTime.ToString('yyyyMMdd') }
} else {
    $iso = "unknown_" + (Get-Item $EqgameH).LastWriteTime.ToString('yyyyMMdd')
}

$sha   = (Get-FileHash $EqgameH -Algorithm SHA256).Hash
$count = ([regex]::Matches($text, '(?m)^#define\s+\S+\s+0x[0-9A-Fa-f]+')).Count

$folder = Join-Path $HIST $iso
New-Item -ItemType Directory -Force $folder | Out-Null
Copy-Item $EqgameH (Join-Path $folder "eqgame.h") -Force

# additionals -> <date>\patches\
if ($Extra) {
    $pdir = Join-Path $folder "patches"
    New-Item -ItemType Directory -Force $pdir | Out-Null
    foreach ($x in $Extra) {
        if (Test-Path $x) { Copy-Item $x (Join-Path $pdir (Split-Path $x -Leaf)) -Force; Write-Host "[offsets] +additional $(Split-Path $x -Leaf)" -ForegroundColor Green }
        else { Write-Host "[offsets] additional not found: $x" -ForegroundColor Yellow }
    }
}

# notes.md
$archivedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
@"
# eqgame.h snapshot - $iso

| field | value |
|-------|-------|
| client build (__ExpectedVersionDate) | $verDate |
| client time  (__ExpectedVersionTime) | $verTime |
| __ClientDate | $clientNum |
| offset #defines | $count |
| eqgame.h sha256 | $sha |
| source / provenance | $Source |
| archived at | $archivedAt |

$Notes
"@ | Out-File (Join-Path $folder "notes.md") -Encoding utf8

# CATALOG.csv (idempotent on iso+sha)
if (-not (Test-Path $CSV)) {
    "archived_at,client_date_iso,client_build,client_time,client_date_num,offset_count,eqgame_h_sha256,source,notes" | Out-File $CSV -Encoding utf8
}
$dup = $false
foreach ($r in (Import-Csv $CSV)) { if ($r.client_date_iso -eq $iso -and $r.eqgame_h_sha256 -eq $sha) { $dup = $true; break } }
if ($dup) {
    Write-Host "[offsets] catalog already has $iso (sha match) - notes/files refreshed." -ForegroundColor DarkGray
} else {
    $nClean = ($Notes -replace '[\r\n]+',' ' -replace '"','''')
    $sClean = ($Source -replace '"','''')
    ('"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}"' -f $archivedAt,$iso,$verDate,$verTime,$clientNum,$count,$sha,$sClean,$nClean) | Out-File $CSV -Encoding utf8 -Append
    Write-Host "[offsets] cataloged $iso ($verDate, $count offsets) -> $folder" -ForegroundColor Green
}

# rebuild CATALOG.md from CSV
$rows = @(Import-Csv $CSV | Sort-Object client_date_num)
$md = @()
$md += "# Offset history catalog"
$md += ""
$md += "Dated snapshots of ``eqgame.h`` (and any source patches) per EverQuest client build."
$md += "Use ``Diff-Offsets.ps1 <from> <to>`` to see exactly which offsets moved between two builds."
$md += ""
$md += "| client build | date | offsets | source | eqgame.h sha (short) |"
$md += "|---|---|---|---|---|"
foreach ($r in $rows) {
    $md += "| $($r.client_build) | $($r.client_date_iso) | $($r.offset_count) | $($r.source) | $($r.eqgame_h_sha256.Substring(0,12)) |"
}
$md += ""
$md += "_Rebuilt $archivedAt by Archive-Offsets.ps1._"
$md -join "`r`n" | Out-File (Join-Path $HIST "CATALOG.md") -Encoding utf8

Write-Host "[offsets] catalog now has $($rows.Count) build(s)." -ForegroundColor Cyan
