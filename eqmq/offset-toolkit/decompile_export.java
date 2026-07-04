// decompile_export.java -- Ghidra HEADLESS post-script: decompile a list of functions to C.
// For each catalog VA in the list file, decompile the containing function and emit JSON:
//     { "0x140...": "<decompiled C>", ... }
// Used to power the source-code view in the MMOPlugins Learn/wiki pages.
//
//   -postScript decompile_export.java <out.json> <va_list.txt>

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class decompile_export extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("decompile_export: need <out.json> <va_list.txt>");
            return;
        }
        String outPath = args[0];
        String listPath = args[1];

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);

        PrintWriter w = new PrintWriter(new FileWriter(outPath));
        w.write("{\n");
        boolean first = true;
        int ok = 0, miss = 0;
        List<String> lines = Files.readAllLines(Paths.get(listPath));
        for (String ln : lines) {
            ln = ln.trim();
            if (ln.isEmpty()) continue;
            String hex = (ln.startsWith("0x") || ln.startsWith("0X")) ? ln.substring(2) : ln;
            long off;
            try { off = Long.parseLong(hex, 16); } catch (Exception e) { continue; }
            Address a = toAddr(off);
            if (a == null) { miss++; continue; }
            Function f = getFunctionContaining(a);
            if (f == null) f = getFunctionAt(a);
            if (f == null) { miss++; continue; }
            String c = "";
            try {
                DecompileResults res = dec.decompileFunction(f, 30, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    c = res.getDecompiledFunction().getC();
                }
            } catch (Exception e) { /* skip */ }
            if (c == null || c.isEmpty()) { miss++; continue; }
            String esc = c.replace("\\", "\\\\").replace("\"", "\\\"")
                          .replace("\r", "").replace("\n", "\\n").replace("\t", "  ");
            if (esc.length() > 8000) esc = esc.substring(0, 8000) + "\\n... (truncated) ...";
            if (!first) w.write(",\n");
            first = false;
            w.write("  \"0x" + Long.toHexString(off) + "\": \"" + esc + "\"");
            ok++;
        }
        w.write("\n}\n");
        w.close();
        println("decompile_export: wrote " + ok + " functions (" + miss + " skipped) -> " + outPath);
        dec.dispose();
    }
}
