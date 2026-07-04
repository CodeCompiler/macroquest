<#
  Auto-Update-Build.ps1  --  hands-off "drop a new eqgame.exe -> compiled MacroQuest".
  Chains: analyze+relocate offsets (Ghidra) -> apply to eqgame.h + bump version stamp
          (with the >10%-missing safety abort) -> build MacroQuest (+plugins).

  Stops at the first failure. If APPLY is gated (bad/partial relocation) it does NOT build.
  If the BUILD fails it's almost always a struct/API-drift change that needs a human source
  fix (offsets were still applied + stamped) -- see 01-build/patches/api-drift-notes.md.

  Usage:  .\Auto-Update-Build.ps1 -Exe "C:\path\to\new\eqgame.exe"
  This is the engine behind the web app's "Full auto" option.
#>
param([Parameter(Mandatory=$true)][string]$Exe)
$ErrorActionPreference = "Continue"
$tk  = $PSScriptRoot
$kit = Split-Path $tk
function Log($m){ Write-Host ("[auto] " + $m) }

if (-not (Test-Path $Exe)) { Log "exe not found: $Exe"; exit 1 }

Log "STEP 1/3  analyze + relocate offsets (Ghidra headless - SLOW, 1-3h)..."
python "$tk\update_from_exe.py" analyze "$Exe"
if ($LASTEXITCODE -ne 0) { Log "analyze FAILED ($LASTEXITCODE) - stopping, eqgame.h untouched."; exit 1 }

Log "STEP 2/3  apply offsets + version stamp (safety gate active)..."
python "$tk\update_from_exe.py" apply
if ($LASTEXITCODE -ne 0) { Log "apply FAILED/GATED ($LASTEXITCODE) - NOT building. Review out\coverage_report.csv."; exit 2 }

Log "STEP 3/3  build MacroQuest (+plugins)..."
& "$kit\01-build\Build-MacroQuest.ps1" -Plugins
$b = $LASTEXITCODE
if ($b -eq 0) {
    Log "AUTO-BUILD COMPLETE. Output in build\bin\release. VERIFY in-game on a throwaway login before trusting."
} else {
    Log "BUILD FAILED ($b). Offsets were applied + stamped, but compilation needs a manual fix -"
    Log "almost always a struct/API-drift change (a renamed/removed eqlib field). See api-drift-notes.md."
}
exit $b
