// ghidra_deep_export.java -- Ghidra HEADLESS post-script (native Java GhidraScript).
//
// Deep static export to feed the MMOPlugins knowledge engine. In ONE pass over the
// already-analyzed program it answers the strategic question (does eqgame.exe retain RTTI?)
// and emits three artifacts the regex header-scrape can never produce:
//
//   structs.json   : every Structure in the DataTypeManager -> {size, fields:[{off,name,type,size}]}
//                    (the client's REAL layouts incl. macro-defined classes Ghidra recovered)
//   vtables.json   : each "vftable" symbol -> {class, va, methods:[func VA,...]}
//                    (pairs 1:1 with MQ2FuncCat's runtime vtable capture)
//   classes.json   : each GhidraClass namespace -> {methods:[{va,name},...]}  (RTTI-named classes)
//   deep_summary.json : counts + the RTTI verdict
//
// Addresses are emitted at the program image base (0x140000000 preferred base) to match eqgame.h.
//
//   -postScript ghidra_deep_export.java <out_dir>
// Run fast against the existing analysis with:  -process eqgame.exe -noanalysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.listing.GhidraClass;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Iterator;

public class ghidra_deep_export extends GhidraScript {

    static final int MAX_VTABLE_ENTRIES = 4000;

    private String hexAddr(Address a) {
        String s = a.toString();
        if (!s.startsWith("0x")) s = "0x" + s;
        return s.toLowerCase();
    }

    private String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "").replace("\n", "\\n").replace("\t", "  ");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { println("ghidra_deep_export: need <out_dir>"); return; }
        String dir = args[0];
        if (!dir.endsWith("\\") && !dir.endsWith("/")) dir = dir + "\\";

        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Memory mem = currentProgram.getMemory();
        long ptr = currentProgram.getDefaultPointerSize();   // 8 on x64

        int nFuncs = fm.getFunctionCount();

        // -------- structs.json (DataTypeManager) --------
        int nStructs = 0, nSized = 0;
        PrintWriter sw = new PrintWriter(new FileWriter(dir + "structs.json"));
        sw.write("{\n");
        boolean firstS = true;
        Iterator<Structure> sit = dtm.getAllStructures();
        while (sit.hasNext()) {
            Structure str = sit.next();
            String name = str.getName();
            int len = str.getLength();
            StringBuilder fb = new StringBuilder();
            int nc = str.getNumComponents();
            for (int i = 0; i < nc; i++) {
                DataTypeComponent c = str.getComponent(i);
                if (c == null) continue;
                String fn = c.getFieldName();
                DataType cdt = c.getDataType();
                String tn = (cdt != null) ? cdt.getName() : "?";
                if (i > 0) fb.append(",");
                fb.append("{\"off\":").append(c.getOffset())
                  .append(",\"name\":\"").append(jsonEsc(fn == null ? "" : fn))
                  .append("\",\"type\":\"").append(jsonEsc(tn))
                  .append("\",\"size\":").append(c.getLength()).append("}");
            }
            if (!firstS) sw.write(",\n");
            firstS = false;
            sw.write("  \"" + jsonEsc(name) + "\": {\"size\":" + len + ",\"fields\":[" + fb.toString() + "]}");
            nStructs++;
            if (len > 0) nSized++;
        }
        sw.write("\n}\n");
        sw.close();

        // -------- classes.json (GhidraClass namespaces -> methods) --------
        // One pass over functions, bucket by parent class namespace. RTTI gives these real names.
        java.util.TreeMap<String, StringBuilder> classMethods = new java.util.TreeMap<String, StringBuilder>();
        int nClassFns = 0;
        Iterator<Function> fns = fm.getFunctions(true);
        while (fns.hasNext()) {
            Function fn = fns.next();
            Namespace ns = fn.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;
            if (!(ns instanceof GhidraClass)) continue;
            String cn = ns.getName(true);   // fully-qualified class name
            StringBuilder b = classMethods.get(cn);
            if (b == null) { b = new StringBuilder(); classMethods.put(cn, b); }
            if (b.length() > 0) b.append(",");
            b.append("{\"va\":\"").append(hexAddr(fn.getEntryPoint()))
             .append("\",\"name\":\"").append(jsonEsc(fn.getName())).append("\"}");
            nClassFns++;
        }
        int nClasses = classMethods.size();
        PrintWriter cw = new PrintWriter(new FileWriter(dir + "classes.json"));
        cw.write("{\n");
        boolean firstC = true;
        for (java.util.Map.Entry<String, StringBuilder> e : classMethods.entrySet()) {
            if (!firstC) cw.write(",\n");
            firstC = false;
            cw.write("  \"" + jsonEsc(e.getKey()) + "\": [" + e.getValue().toString() + "]");
        }
        cw.write("\n}\n");
        cw.close();

        // -------- vtables.json (vftable symbols -> pointed-to function VAs) --------
        int nVtables = 0, nVtMethods = 0;
        PrintWriter vw = new PrintWriter(new FileWriter(dir + "vtables.json"));
        vw.write("[\n");
        boolean firstV = true;
        SymbolIterator vsyms = st.getSymbolIterator("*vftable*", true);
        while (vsyms.hasNext()) {
            Symbol sym = vsyms.next();
            Address base = sym.getAddress();
            if (base == null || !base.isMemoryAddress()) continue;
            Namespace ns = sym.getParentNamespace();
            String cls = (ns != null && !ns.isGlobal()) ? ns.getName(true) : "";
            StringBuilder mb = new StringBuilder();
            int n = 0;
            for (int i = 0; i < MAX_VTABLE_ENTRIES; i++) {
                Address slot;
                long val;
                try {
                    slot = base.add((long) i * ptr);   // can throw AddressOutOfBoundsException near a block end
                    val = (ptr == 8) ? mem.getLong(slot) : (mem.getInt(slot) & 0xffffffffL);
                } catch (Exception ex) { break; }
                if (val == 0) break;
                Address tgt;
                try { tgt = toAddr(val); } catch (Exception ex) { break; }
                if (tgt == null) break;
                Function tf = getFunctionAt(tgt);
                if (tf == null) break;   // first non-function entry ends the vtable
                if (mb.length() > 0) mb.append(",");
                mb.append("\"").append(hexAddr(tgt)).append("\"");
                n++;
                nVtMethods++;
            }
            if (n == 0) continue;
            if (!firstV) vw.write(",\n");
            firstV = false;
            vw.write("  {\"class\":\"" + jsonEsc(cls) + "\",\"va\":\"" + hexAddr(base)
                     + "\",\"methods\":[" + mb.toString() + "]}");
            nVtables++;
        }
        vw.write("\n]\n");
        vw.close();

        // -------- deep_summary.json (RTTI verdict) --------
        boolean rtti = (nClasses > 0) || (nVtables > 0);
        PrintWriter dw = new PrintWriter(new FileWriter(dir + "deep_summary.json"));
        dw.write("{\n");
        dw.write("  \"functions\": " + nFuncs + ",\n");
        dw.write("  \"structs\": " + nStructs + ", \"structs_sized\": " + nSized + ",\n");
        dw.write("  \"rtti_classes\": " + nClasses + ", \"class_methods\": " + nClassFns + ",\n");
        dw.write("  \"vtables\": " + nVtables + ", \"vtable_methods\": " + nVtMethods + ",\n");
        dw.write("  \"rtti_present\": " + rtti + "\n");
        dw.write("}\n");
        dw.close();

        println("ghidra_deep_export: funcs=" + nFuncs + " structs=" + nStructs
                + " rtti_classes=" + nClasses + " vtables=" + nVtables
                + " RTTI_PRESENT=" + rtti + " -> " + dir);
    }
}
