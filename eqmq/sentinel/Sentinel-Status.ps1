<#
  Sentinel-Status.ps1 -- one-shot health view: task state + sentinel.py status + recent log tail.
  Usage: .\Sentinel-Status.ps1
#>
param([string]$TaskName = "eqmq-sentinel", [string]$Python = "python")
$here = $PSScriptRoot

Write-Host "=== scheduled task ==="
schtasks /Query /TN $TaskName /FO LIST 2>$null | Select-String "TaskName|Status|Next Run Time|Last Run Time|Last Result"
if ($LASTEXITCODE -ne 0) { Write-Host "task '$TaskName' NOT INSTALLED (run Install-Sentinel.ps1)" }

Write-Host ""
Write-Host "=== sentinel state ==="
& $Python (Join-Path $here "sentinel.py") status

$logDir = Join-Path $here "logs"
if (Test-Path $logDir) {
    $last = Get-ChildItem $logDir -Filter *.log -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($last) {
        Write-Host ""
        Write-Host "=== tail of $($last.Name) ==="
        Get-Content $last.FullName -Tail 15
    }
}
