# ghidra_export.py  -- Ghidra HEADLESS post-script (runs under Jython 2.7)
#
# Exports every function in the analyzed program to a CSV:
#     va,name,strings,datarefs
# where:
#   va       = function entry virtual address (hex, e.g. 0x14022c0d0) -- matches eqgame.h VAs
#   name     = Ghidra's function name (usually FUN_xxxx since eqgame.exe has no symbols)
#   strings  = '|'-joined, de-duplicated list of string literals the function references
#   datarefs = '|'-joined, ordered, de-duplicated list of DATA target VAs (0x... lowercase)
#              that the function references and that are NOT string data (globals/pointers).
#
# The 'strings' column is the ANCHOR: a function's set of referenced strings is stable
# across EQ patches even though its address moves, so we can match old<->new by it.
# The 'datarefs' column lets us resolve data/global offsets: a data/global is identified
# by WHICH function references it and at WHICH position in that function's dataref list.
#
# Invoked by analyzeHeadless via:  -postScript ghidra_export.py <output_csv>

import re

args = getScriptArgs()
if len(args) < 1:
    print("ghidra_export.py: missing output path argument")
else:
    outpath = args[0]
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()

    f = open(outpath, 'w')
    f.write("va,name,strings,datarefs\n")
    count = 0
    for func in fm.getFunctions(True):
        if func.isThunk():
            continue
        entry = func.getEntryPoint()
        va = entry.toString()                # e.g. "14022c0d0"
        if not va.startswith("0x"):
            va = "0x" + va
        name = func.getName()
        seen = {}            # string anchors (set semantics)
        data_list = []       # ordered, de-duped non-string data target VAs
        data_seen = {}
        body = func.getBody()
        instrs = listing.getInstructions(body, True)
        for instr in instrs:
            for ref in instr.getReferencesFrom():
                if not ref.getReferenceType().isData():
                    continue
                target = ref.getToAddress()
                data = listing.getDataAt(target)
                if data is not None and data.hasStringValue():
                    val = data.getValue()
                    if val is not None:
                        s = str(val)
                        # keep meaningful anchors only
                        if len(s) >= 4:
                            seen[s] = 1
                else:
                    # data/global address (pointer, global, vtable, etc.)
                    ta = target.toString()
                    if not ta.startswith("0x"):
                        ta = "0x" + ta
                    ta = ta.lower()
                    if ta not in data_seen:
                        data_seen[ta] = 1
                        data_list.append(ta)
        uniq = sorted(seen.keys())
        # sanitize for CSV (no commas / newlines in fields)
        safe_name = name.replace(',', ' ')
        safe_strs = '|'.join([x.replace(',', ' ').replace('\n', ' ').replace('\r', ' ') for x in uniq])
        safe_data = '|'.join(data_list)
        f.write('%s,%s,%s,%s\n' % (va.lower(), safe_name, safe_strs, safe_data))
        count += 1
    f.close()
    print("ghidra_export.py: wrote %d functions to %s" % (count, outpath))
