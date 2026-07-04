<#
  Archive-Client.ps1  --  keep DATED copies of eqgame.exe so you always have prior
  client binaries on hand (baselines/bootstrap inputs for the offset toolkit).

  Each build is stored in its OWN dated folder:
        versions\archive\<YYYY-MM-DD>\eqgame.exe
  (if two different binaries share a build date, the later one gets <date>_<sha8>).
  A row per build is appended to versions\archive\manifest.csv. Idempotent: a binary
  already archived (same SHA-256) is skipped.

  USAGE:
    .\Archive-Client.ps1                       # archive the live client (auto-resolved)
    .\Archive-Client.ps1 -Source "D:\old\eqgame.exe"
    .\Archive-Client.ps1 -Source a\eqgame.exe,b\eqgame.exe   # several at once

  NOTE: eqgame.exe is YOUR copyrighted EverQuest client. This archive is for your own
  use only and is NEVER part of the shareable kit (see .gitignore).
#>
param([string[]]$Source)

$ErrorActionPreference = "Stop"
$here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$ARCHIVE  = Join-Path $here "versions\archive"
$MANIFEST = Join-Path $ARCHIVE "manifest.csv"
New-Item -ItemType Directory -Force $ARCHIVE | Out-Null

function Get-BuildInfo($exe) {
    $date = (Select-String -Path $exe -Pattern "[A-Z][a-z]{2} [ 0-9][0-9] 2[0-9]{3}" -AllMatches `
             -ErrorAction SilentlyContinue).Matches.Value | Select-Object -Unique -First 1
    $times = (Select-String -Path $exe -Pattern "[0-2][0-9]:[0-5][0-9]:[0-5][0-9]" -AllMatches `
             -ErrorAction SilentlyContinue).Matches.Value | Select-Object -Unique -First 5
    $iso = $null
    if ($date) {
        $norm = ($date -replace '\s+',' ').Trim()
        try { $iso = ([datetime]::ParseExact($norm,'MMM d yyyy',[Globalization.CultureInfo]::InvariantCulture)).ToString('yyyy-MM-dd') } catch {}
    }
    if (-not $iso) { $iso = "unknown_" + (Get-Item $exe).LastWriteTime.ToString('yyyyMMdd') }
    [pscustomobject]@{ Date=$date; Iso=$iso; Times=($times -join ' / ') }
}

function Archive-One($exe) {
    if (-not (Test-Path $exe)) { Write-Host "[archive] not found: $exe" -ForegroundColor Yellow; return }
    $info = Get-BuildInfo $exe
    $sha  = (Get-FileHash $exe -Algorithm SHA256).Hash

    # already archived anywhere (same sha)? skip.
    $existing = Get-ChildItem $ARCHIVE -Recurse -Filter eqgame.exe -ErrorAction SilentlyContinue |
                Where-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash -eq $sha } | Select-Object -First 1
    if ($existing) { Write-Host "[archive] already have build '$($info.Date)' (sha match) -> $($existing.FullName)" -ForegroundColor DarkGray; return }

    $folder = Join-Path $ARCHIVE $info.Iso
    if (Test-Path (Join-Path $folder "eqgame.exe")) { $folder = "$folder`_$($sha.Substring(0,8))" }
    New-Item -ItemType Directory -Force $folder | Out-Null
    $dest = Join-Path $folder "eqgame.exe"
    Copy-Item $exe $dest
    Write-Host "[archive] saved build '$($info.Date)' -> $dest" -ForegroundColor Green

    if (-not (Test-Path $MANIFEST)) {
        "archived_at,build_date,build_date_iso,build_times,sha256,dest,source" | Out-File $MANIFEST -Encoding utf8
    }
    $row = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}"' -f `
        (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $info.Date, $info.Iso, $info.Times, $sha, $dest, $exe
    $row | Out-File $MANIFEST -Encoding utf8 -Append
}

# default source = the live client (resolved by eqmq_paths.py)
if (-not $Source) {
    $live = (& python (Join-Path $here "eqmq_paths.py") get EQ_EXE) 2>$null
    if (-not $live) { Write-Host "[archive] could not resolve live client. Run: python eqmq_paths.py check"; exit 1 }
    $Source = @($live)
}

foreach ($s in $Source) { Archive-One $s }

Write-Host "`n[archive] dated builds kept:"
Get-ChildItem $ARCHIVE -Directory | ForEach-Object {
    $e = Join-Path $_.FullName "eqgame.exe"
    if (Test-Path $e) { "  {0,-22} {1} MB" -f $_.Name, [math]::Round((Get-Item $e).Length/1MB,1) }
}
