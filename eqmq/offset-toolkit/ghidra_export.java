// ghidra_export.java -- Ghidra HEADLESS post-script (native Java GhidraScript).
//
// Ghidra 11.3+/12.x dropped the bundled Jython interpreter; .py GhidraScripts now
// require PyGhidra (a separately-configured CPython bridge). To stay dependency-free
// on any headless install, this exporter is written in Java -- Ghidra compiles it on
// the fly with the JDK already required to run.
//
// Exports every function in the analyzed program to a CSV:
//     va,name,strings,sig,datarefs
// where:
//   va       = function entry virtual address (hex, lowercase 0x...) -- matches eqgame.h VAs
//   name     = Ghidra's function name (usually FUN_xxxx since eqgame.exe has no symbols)
//   strings  = '|'-joined, de-duplicated, sorted list of string literals the function references
//   sig      = masked byte-pattern signature (FLIRT-style) of the function's first SIG_BUDGET
//              code bytes. Relocatable operand bytes (call/jmp rel32, RIP-relative disp32,
//              abs32/abs64 immediates that equal a reference target) are wildcarded as "??".
//              The concrete (non-??) opcode/structure bytes stay stable across EQ patches even
//              though addresses move, so a function relocates by matching its signature.
//   datarefs = '|'-joined, ordered, de-duplicated list of non-string DATA target VAs the
//              function references (globals/pointers/vtables).
//
// Both 'strings' and 'sig' are stable ANCHORS used to relocate a function across patches.
// 'sig' covers the ~83% of functions that reference no distinctive strings.
//
// Invoked by analyzeHeadless via:  -postScript ghidra_export.java <output_csv>

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.TreeSet;

public class ghidra_export extends GhidraScript {

    static final int SIG_BUDGET = 48;   // concrete+masked bytes captured per function signature

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ghidra_export: missing output path argument");
            return;
        }
        String outpath = args[0];
        // Optional 2nd arg: a file of catalog VAs to force-create as functions (recover funcs the
        // auto-analysis missed but that runtime vtables proved are real) before exporting.
        if (args.length >= 2) {
            forceCreate(args[1]);
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        PrintWriter f = new PrintWriter(new FileWriter(outpath));
        try {
            f.write("va,name,strings,sig,size,datarefs\n");
            int count = 0;
            FunctionIterator funcs = fm.getFunctions(true);
            while (funcs.hasNext()) {
                Function func = funcs.next();
                if (func.isThunk()) {
                    continue;
                }
                Address entry = func.getEntryPoint();
                String va = entry.toString();
                if (!va.startsWith("0x")) {
                    va = "0x" + va;
                }
                va = va.toLowerCase();
                String name = func.getName();

                TreeSet<String> seen = new TreeSet<String>();   // string anchors (sorted, set semantics)
                ArrayList<String> dataList = new ArrayList<String>();  // ordered, de-duped non-string data VAs
                HashSet<String> dataSeen = new HashSet<String>();

                AddressSetView body = func.getBody();
                InstructionIterator instrs = listing.getInstructions(body, true);
                while (instrs.hasNext()) {
                    Instruction instr = instrs.next();
                    for (Reference ref : instr.getReferencesFrom()) {
                        if (!ref.getReferenceType().isData()) {
                            continue;
                        }
                        Address target = ref.getToAddress();
                        Data data = listing.getDataAt(target);
                        if (data != null && data.hasStringValue()) {
                            Object val = data.getValue();
                            if (val != null) {
                                String s = val.toString();
                                if (s.length() >= 4) {           // keep meaningful anchors only
                                    seen.add(s);
                                }
                            }
                        } else {
                            String ta = target.toString();
                            if (!ta.startsWith("0x")) {
                                ta = "0x" + ta;
                            }
                            ta = ta.toLowerCase();
                            if (!dataSeen.contains(ta)) {
                                dataSeen.add(ta);
                                dataList.add(ta);
                            }
                        }
                    }
                }

                String sig = buildSignature(listing, body);

                String safeName = name.replace(',', ' ');
                StringBuilder sb = new StringBuilder();
                boolean first = true;
                for (String x : seen) {       // TreeSet iterates in sorted order
                    String cleaned = x.replace(',', ' ').replace('\n', ' ').replace('\r', ' ');
                    if (!first) {
                        sb.append('|');
                    }
                    sb.append(cleaned);
                    first = false;
                }
                StringBuilder db = new StringBuilder();
                for (int i = 0; i < dataList.size(); i++) {
                    if (i > 0) {
                        db.append('|');
                    }
                    db.append(dataList.get(i));
                }

                long fsize = func.getBody().getNumAddresses();   // function size in bytes
                f.write(va + "," + safeName + "," + sb.toString() + "," + sig + "," + fsize + "," + db.toString() + "\n");
                count++;
            }
            println("ghidra_export: wrote " + count + " functions to " + outpath);
        } finally {
            f.close();
        }
    }

    // Build a masked byte signature over the first SIG_BUDGET code bytes of the function.
    // Relocatable operand bytes (those equal to a reference target as rel32/abs32/abs64) are
    // wildcarded "??"; everything else is emitted as lowercase hex.
    private String buildSignature(Listing listing, AddressSetView body) {
        StringBuilder sig = new StringBuilder();
        int emitted = 0;
        InstructionIterator it = listing.getInstructions(body, true);
        while (it.hasNext() && emitted < SIG_BUDGET) {
            Instruction instr = it.next();
            byte[] ib;
            try {
                ib = instr.getBytes();
            } catch (Exception e) {
                break;   // unreadable bytes -> stop the signature here
            }
            if (ib == null || ib.length == 0) {
                continue;
            }
            boolean[] mask = new boolean[ib.length];
            long iaddr = instr.getAddress().getOffset();
            int ilen = ib.length;
            for (Reference ref : instr.getReferencesFrom()) {
                Address tgt = ref.getToAddress();
                if (tgt == null || !tgt.isMemoryAddress()) {
                    continue;
                }
                long t = tgt.getOffset();
                long rel = t - (iaddr + ilen);     // rel32 (call/jmp/RIP-relative)
                markDword(ib, mask, (int) rel);
                markDword(ib, mask, (int) t);       // abs32 (rare in x64)
                markQword(ib, mask, t);             // abs64 (mov reg, imm64)
            }
            for (int i = 0; i < ilen && emitted < SIG_BUDGET; i++) {
                if (mask[i]) {
                    sig.append("??");
                } else {
                    sig.append(String.format("%02x", ib[i] & 0xff));
                }
                emitted++;
            }
        }
        return sig.toString();
    }

    // Mask the first little-endian 4-byte run equal to val (skip val==0 to avoid masking real zeros).
    private void markDword(byte[] b, boolean[] mask, int val) {
        if (val == 0) {
            return;
        }
        for (int i = 0; i + 4 <= b.length; i++) {
            int v = (b[i] & 0xff) | ((b[i + 1] & 0xff) << 8) | ((b[i + 2] & 0xff) << 16) | ((b[i + 3] & 0xff) << 24);
            if (v == val) {
                mask[i] = mask[i + 1] = mask[i + 2] = mask[i + 3] = true;
                return;
            }
        }
    }

    // Mask the first little-endian 8-byte run equal to val.
    private void markQword(byte[] b, boolean[] mask, long val) {
        if (val == 0) {
            return;
        }
        for (int i = 0; i + 8 <= b.length; i++) {
            long v = 0;
            for (int k = 0; k < 8; k++) {
                v |= ((long) (b[i + k] & 0xff)) << (8 * k);
            }
            if (v == val) {
                for (int k = 0; k < 8; k++) {
                    mask[i + k] = true;
                }
                return;
            }
        }
    }

    // Force-create functions at a list of catalog VAs (one "0x..." per line). Recovers functions the
    // auto-analyzer missed but that live vtables proved real, so they get signatures/sizes on export.
    private void forceCreate(String listPath) {
        int created = 0, already = 0, failed = 0;
        try {
            java.util.List<String> lines = java.nio.file.Files.readAllLines(java.nio.file.Paths.get(listPath));
            for (String ln : lines) {
                ln = ln.trim();
                if (ln.isEmpty()) continue;
                String hex = (ln.startsWith("0x") || ln.startsWith("0X")) ? ln.substring(2) : ln;
                long off;
                try { off = Long.parseLong(hex, 16); } catch (Exception e) { continue; }
                Address a = toAddr(off);
                if (a == null) { failed++; continue; }
                if (getFunctionAt(a) != null) { already++; continue; }
                try {
                    disassemble(a);
                    Function fn = createFunction(a, null);
                    if (fn != null) created++; else failed++;
                } catch (Exception e) { failed++; }
            }
        } catch (Exception e) {
            println("forceCreate: error reading " + listPath + ": " + e.getMessage());
            return;
        }
        println("forceCreate: created " + created + ", already " + already + ", failed " + failed);
    }
}
