# refresh.ps1 -- on-demand engine refresh (launched detached by the admin "Rebuild" button).
# Full pipeline: discovered DB -> deep static export (RTTI/structs/vtables) -> cross-version
# carry-forward -> whole-game catalog + structures -> fold in AI names -> decompile.
$ErrorActionPreference = "Continue"
$log = "C:\mmoplugins\refresh.log"; $st = "C:\mmoplugins\refresh.status"
$py = "C:\Python314\python.exe"
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21.0.9.10-hotspot"
$gh = "C:\ProgramData\chocoportable\lib\ghidra\tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat"
$proj = "C:\EQMQ\02-offset-toolkit\ghidra_projects"
$scripts = "C:\EQMQ\02-offset-toolkit"
"running $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $st -Encoding ascii
"[refresh] start $(Get-Date)" | Out-File $log

# self-heal Ghidra project ownership: set OWNER to THIS run's context so headless can open the
# project regardless of which account last touched it (Ghidra compares OWNER to the JVM user.name).
$un = ""
try {
  $line = (& "$env:JAVA_HOME\bin\java.exe" -XshowSettings:properties -version 2>&1 | Select-String "user\.name")
  if ($line) { $un = ($line.ToString() -replace '.*user\.name\s*=\s*', '').Trim() }
} catch {}
if (-not $un) { $un = $env:USERNAME }
if ($un) {
  foreach ($rep in @("jun24.rep", "incoming.rep")) {
    $prp = Join-Path $proj "$rep\project.prp"
    if (Test-Path $prp) {
      (Get-Content $prp -Raw) | ForEach-Object { [regex]::Replace($_, '(NAME="OWNER"[^>]*VALUE=")[^"]*(")', ('${1}' + $un + '${2}')) } | Set-Content $prp -Encoding UTF8
    }
  }
  "[refresh] patched Ghidra project OWNER to '$un'" | Out-File $log -Append
}

"[1/6] rebuild discovered DB + VA list..." | Out-File $log -Append
& $py C:\mmoplugins\refresh_prep.py *>> $log

"[2/6] deep static export (RTTI verdict + DataTypeManager structs + vtables + classes)..." | Out-File $log -Append
New-Item -ItemType Directory -Force C:\mmoplugins\deep | Out-Null
& $gh $proj jun24 -process eqgame.exe -noanalysis -scriptPath $scripts -postScript ghidra_deep_export.java C:\mmoplugins\deep *>> $log

"[3/6] cross-version carry-forward (fuse rtti/vtable/observed/admin/ai -> kb.json + labels)..." | Out-File $log -Append
& $py C:\mmoplugins\crossversion_db.py *>> $log

"[4/6] fold in any completed AI naming batch (non-fatal if none / no API key)..." | Out-File $log -Append
& $py C:\mmoplugins\ai_namer.py batch-collect *>> $log
# re-run cross-version so freshly merged AI names propagate into the labels overlay
& $py C:\mmoplugins\crossversion_db.py *>> $log

"[5/6] regenerate whole-game catalog + structure catalog (overlays cross-version + deep structs)..." | Out-File $log -Append
& $py C:\mmoplugins\build_funcatalog.py *>> $log
& $py C:\mmoplugins\build_structs.py *>> $log

"[6/6] decompile (Ghidra, ~5-10 min)..." | Out-File $log -Append
& $gh $proj jun24 -process eqgame.exe -noanalysis -scriptPath $scripts -postScript decompile_export.java C:\mmoplugins\decompiled.json C:\eqmq-deploy\decomp_vas.txt *>> $log

"[refresh] DONE $(Get-Date)" | Out-File $log -Append
"done $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $st -Encoding ascii
