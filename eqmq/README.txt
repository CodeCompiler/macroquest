EQMQ Offset Toolkit
===================
Reverse-engineering + offset-relocation tooling for keeping MacroQuest compiling
across EverQuest client patches. Byte-signature relocation, Ghidra headless export
(RTTI / structs / vtables / decompile), cross-version carry-forward, and optional
AI-assisted naming of unlabeled functions.

  offset-toolkit/  relocation engine, Ghidra exporters, build/deploy scripts
  pipeline/        cross-version DB, catalog builders, AI naming (ai_namer.py)

Paths default to a reference Windows layout; edit the constants or use eqmq_paths.py.
Generated data, secrets, and any character/account files are intentionally excluded.
