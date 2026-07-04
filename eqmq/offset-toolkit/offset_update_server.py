#!/usr/bin/env python3
"""
offset_update_server.py  --  local web app to UPLOAD a new eqgame.exe and update offsets.

Runs a small web server bound to 127.0.0.1 ONLY (localhost; not exposed to the network).
Open the printed URL, drag in the new eqgame.exe, and it drives update_from_exe.py:
   upload -> Ghidra analyze (slow) -> relocate/bootstrap -> review coverage -> Apply -> Build.

Start it from the Control Panel, or:  python offset_update_server.py
Stop it with Ctrl+C in its console.

SECURITY: localhost-bound; it runs the local toolkit scripts, so only start it on your own
machine. It updates OFFSETS + version stamp; struct/API-drift fixes still need a human at build.
"""
import os, sys, json, subprocess, threading, csv, html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
KIT  = os.path.dirname(HERE)
OUT  = os.path.join(HERE, "out")
VERS = os.path.join(HERE, "versions")
LOG  = os.path.join(OUT, "update.log")
UPDIR = os.path.join(VERS, "incoming_upload")
UPEXE = os.path.join(UPDIR, "eqgame.exe")
PORT = 8780

_lock = threading.Lock()
_proc = {"p": None, "what": "idle"}

def _spawn(args, what, append=False):
    os.makedirs(OUT, exist_ok=True)
    with _lock:
        if _proc["p"] and _proc["p"].poll() is None:
            return False
        lf = open(LOG, "a" if append else "w", encoding="utf-8")
        lf.write("\n=== %s ===\n" % what); lf.flush()
        _proc["p"] = subprocess.Popen([sys.executable, os.path.join(HERE, "update_from_exe.py")] + args,
                                      cwd=HERE, stdout=lf, stderr=subprocess.STDOUT)
        _proc["what"] = what
    return True

def _spawn_build():
    os.makedirs(OUT, exist_ok=True)
    ps1 = os.path.join(KIT, "01-build", "Build-MacroQuest.ps1")
    with _lock:
        if _proc["p"] and _proc["p"].poll() is None:
            return False
        lf = open(LOG, "a", encoding="utf-8"); lf.write("\n=== build ===\n"); lf.flush()
        _proc["p"] = subprocess.Popen(["powershell","-NoProfile","-ExecutionPolicy","Bypass","-File",ps1,"-Plugins"],
                                      cwd=KIT, stdout=lf, stderr=subprocess.STDOUT)
        _proc["what"] = "build"
    return True

def _spawn_auto():
    os.makedirs(OUT, exist_ok=True)
    ps1 = os.path.join(HERE, "Auto-Update-Build.ps1")
    with _lock:
        if _proc["p"] and _proc["p"].poll() is None:
            return False
        lf = open(LOG, "w", encoding="utf-8"); lf.write("\n=== AUTO: analyze + apply + build ===\n"); lf.flush()
        _proc["p"] = subprocess.Popen(["powershell","-NoProfile","-ExecutionPolicy","Bypass","-File",ps1,"-Exe",UPEXE],
                                      cwd=HERE, stdout=lf, stderr=subprocess.STDOUT)
        _proc["what"] = "auto (analyze+apply+build)"
    return True

def _running():
    with _lock:
        return bool(_proc["p"] and _proc["p"].poll() is None)

def _coverage():
    for name in ("coverage_report.csv", "offset_report.csv"):
        p = os.path.join(OUT, name)
        if os.path.exists(p):
            tot=matched=unm=0; samples=[]
            with open(p, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    tot+=1
                    nv=(r.get("new_va") or "").strip()
                    st=(r.get("status") or r.get("confidence") or "").strip().lower()
                    if nv and st not in ("unmatched",""): matched+=1
                    else:
                        unm+=1
                        if len(samples)<25: samples.append(r.get("name",""))
            return {"file":name,"total":tot,"matched":matched,"unmatched":unm,"unmatched_samples":samples}
    return None

PAGE = """<!doctype html><html><head><meta charset=utf-8><title>EQMQ Offset Updater</title>
<style>
body{background:#0d1117;color:#e6edf3;font:15px/1.5 Segoe UI,Arial;margin:0;padding:0 24px 40px;max-width:1000px}
h1{color:#58a6ff}a{color:#58a6ff}.mut{color:#8b949e}
#drop{border:2px dashed #30363d;border-radius:14px;padding:38px;text-align:center;background:#161b22;margin:18px 0;cursor:pointer}
#drop.hot{border-color:#58a6ff;background:#1f6feb22}
button{background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:10px 16px;font:14px Segoe UI;cursor:pointer;margin:4px}
button:hover{border-color:#58a6ff}button.go{border-color:#3fb95088}button.warn{border-color:#f0883e88}
button:disabled{opacity:.4;cursor:not-allowed}
pre{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px;max-height:46vh;overflow:auto;font:12px Consolas,monospace;white-space:pre-wrap}
.stat{display:inline-block;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:10px 16px;margin:6px}
.stat b{font-size:22px;color:#58a6ff;display:block}.warnbox{border-color:#f0883e88}
</style></head><body>
<h1>EQMQ &mdash; Offset Updater</h1>
<p class="mut">Drop a new <code>eqgame.exe</code> below. It runs a Ghidra analysis (<b>slow, ~1&ndash;3 hrs</b>),
relocates the offsets, and shows a coverage report. Nothing touches your real <code>eqgame.h</code>
until you click <b>Apply</b>. Struct/API-drift fixes still need a human at build time.</p>
<div id="drop">Drag <b>eqgame.exe</b> here, or click to pick a file
<div class="mut" id="fname"></div></div>
<input id="file" type="file" accept=".exe" style="display:none">
<div style="margin:6px 0"><label class="mut"><input type="checkbox" id="auto"> &#9889; <b>Full auto</b>: analyze &rarr; apply &rarr; build, hands-off (skips manual review &mdash; verify in-game after)</label></div>
<div>
  <button class="go" id="analyze" disabled>1. Analyze &amp; relocate offsets</button>
  <button class="warn" id="apply" disabled>2. Apply to eqgame.h + bump version stamp</button>
  <button id="build" disabled>3. Build MacroQuest (+plugins)</button>
  <span class="mut" id="phase"></span>
</div>
<div id="cov"></div>
<h3>Log</h3><pre id="log">(idle)</pre>
<script>
const f=document.getElementById('file'),drop=document.getElementById('drop'),fname=document.getElementById('fname');
const bA=document.getElementById('analyze'),bP=document.getElementById('apply'),bB=document.getElementById('build');
let chosen=null;
drop.onclick=()=>f.click();
f.onchange=()=>{chosen=f.files[0];fname.textContent=chosen?chosen.name+' ('+(chosen.size/1048576).toFixed(1)+' MB)':'';bA.disabled=!chosen;};
['dragover','dragenter'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add('hot');}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove('hot');}));
drop.addEventListener('drop',ev=>{chosen=ev.dataTransfer.files[0];fname.textContent=chosen?chosen.name+' ('+(chosen.size/1048576).toFixed(1)+' MB)':'';bA.disabled=!chosen;});
bA.onclick=async()=>{if(!chosen)return;bA.disabled=true;document.getElementById('log').textContent='uploading '+chosen.name+'...';
  const url='/upload'+(document.getElementById('auto').checked?'?auto=1':'');
  await fetch(url,{method:'POST',body:chosen});poll();};
bP.onclick=async()=>{if(!confirm('Back up eqgame.h, write the relocated offsets, and bump the version stamp?'))return;bP.disabled=true;await fetch('/apply',{method:'POST'});poll();};
bB.onclick=async()=>{if(!confirm('Build MacroQuest (long)?'))return;bB.disabled=true;await fetch('/build',{method:'POST'});poll();};
async function refreshCov(){const r=await fetch('/coverage');const c=await r.json();const d=document.getElementById('cov');
  if(!c){d.innerHTML='';return;}
  d.innerHTML='<div class="stat"><b>'+c.total+'</b>offsets</div><div class="stat"><b>'+c.matched+'</b>matched</div><div class="stat warnbox"><b>'+c.unmatched+'</b>need manual</div>'+
   (c.unmatched_samples&&c.unmatched_samples.length?'<p class="mut">unmatched (do by hand / seed more): '+c.unmatched_samples.join(', ')+'</p>':'');}
async function poll(){
  const s=await(await fetch('/status')).json();
  document.getElementById('log').textContent=s.log||'';
  document.getElementById('phase').textContent=s.running?('running: '+s.what+' ...'):'';
  if(s.have_new){bP.disabled=s.running;}
  if(s.built_ok!==undefined){}
  bB.disabled=s.running;
  await refreshCov();
  if(s.running) setTimeout(poll,2500);
}
poll();
</script></body></html>"""

class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE)
        elif self.path == "/status":
            log = open(LOG, encoding="utf-8", errors="replace").read() if os.path.exists(LOG) else ""
            self._send(200, json.dumps({"running": _running(), "what": _proc["what"],
                       "log": log[-12000:], "have_new": os.path.exists(os.path.join(OUT,"eqgame_new.h"))}),
                       "application/json")
        elif self.path == "/coverage":
            self._send(200, json.dumps(_coverage()), "application/json")
        else:
            self._send(404, "not found")
    def do_POST(self):
        if self.path.split("?")[0] == "/upload":
            n = int(self.headers.get("Content-Length", 0))
            os.makedirs(UPDIR, exist_ok=True)
            with open(UPEXE, "wb") as out:
                left = n
                while left > 0:
                    chunk = self.rfile.read(min(1 << 20, left))
                    if not chunk: break
                    out.write(chunk); left -= len(chunk)
            auto = "auto=1" in self.path
            ok = _spawn_auto() if auto else _spawn(["analyze", UPEXE], "analyze")
            self._send(200, json.dumps({"started": ok, "auto": auto}), "application/json")
        elif self.path == "/apply":
            ok = _spawn(["apply"], "apply", append=True)
            self._send(200, json.dumps({"started": ok}), "application/json")
        elif self.path == "/build":
            ok = _spawn_build()
            self._send(200, json.dumps({"started": ok}), "application/json")
        else:
            self._send(404, "not found")

def main():
    os.makedirs(OUT, exist_ok=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    url = "http://127.0.0.1:%d/" % PORT
    print("EQMQ Offset Updater running at %s  (Ctrl+C to stop)" % url)
    if not os.environ.get("EQMQ_NO_BROWSER"):
        try:
            import webbrowser; webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")

if __name__ == "__main__":
    main()
