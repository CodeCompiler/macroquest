// MQ2FuncCat.cpp -- Runtime function/struct cataloger for MacroQuest (MMOPlugins).
//
// As you play, every time you use an ability (kick, flying kick, backstab, bash, any combat
// skill -> CharacterZoneClient::UseSkill; melee swings -> PlayerZoneClient::DoAttack) this
// plugin records the game functions + the class vtables involved into a JSON document. Upload
// that document to MMOPlugins to match the addresses against the whole-game catalog and start
// naming every function / struct.
//
// HOW IT DISCOVERS FUNCTIONS:
//   * The hooked functions themselves get cataloged (already named, from eqgame.h) and tagged
//     with which action triggered them (so you confirm "Kick goes through UseSkill").
//   * On each action, the involved objects' VTABLES are dumped -- a vtable is a table of real
//     member-function pointers, so one action surfaces dozens of new function addresses with
//     class + slot context. Those are the entries you'll name on the site.
//
// SAFETY: read-only w.r.t. game memory. The only writes are two detours installed via
// MacroQuest's own framework on long-stable, signature-confirmed eqlib functions.
//
// Commands:  /funccat            status + document path
//            /funccat on|off     toggle auto-capture (default on)
//            /funccat dump       dump vtables of everything available right now (me/target/pet)
//            /funccat mark <txt> set a context label added to everything captured next
//            /funccat note 0xVA <Name>   manually name an address you've identified
//            /funccat save       flush the document now (also autosaves)
//            /funccat reset      clear the in-memory catalog

#include <mq/Plugin.h>

#include <windows.h>
#include <wininet.h>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <cstdint>

#pragma comment(lib, "wininet.lib")

PreSetup("MQ2FuncCat");
PLUGIN_VERSION(1.0);

namespace {

// -------- module geometry (to turn runtime addresses into preferred-base "catalog VAs") --------
uintptr_t g_modBase = 0;
uintptr_t g_modSize = 0;
uintptr_t g_prefBase = 0x140000000ULL;   // PE preferred ImageBase == what Ghidra analyzed at

void InitModuleInfo()
{
	HMODULE h = GetModuleHandleA(nullptr);
	g_modBase = reinterpret_cast<uintptr_t>(h);
	auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(g_modBase);
	auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(g_modBase + dos->e_lfanew);
	g_modSize = nt->OptionalHeader.SizeOfImage;
	// NOTE: in the injected process the in-memory OptionalHeader.ImageBase reflects the ASLR
	// runtime base, NOT the link-time preferred base -- so do NOT read it. Ghidra analyzes
	// eqgame.exe (x64) at the standard preferred base 0x140000000, and the whole-game catalog is
	// keyed to that, so hardcode it here so our catalog VAs match (VA = 0x140000000 + RVA).
	g_prefBase = 0x140000000ULL;
}

inline bool InModule(uintptr_t a) { return g_modBase && a >= g_modBase && a < g_modBase + g_modSize; }
inline uintptr_t CatVA(uintptr_t a) { return InModule(a) ? g_prefBase + (a - g_modBase) : 0; }

// -------- catalog state --------
struct FuncEntry
{
	std::string name;                 // assigned/known name
	std::string kind;                 // "named" | "vfunc" | "noted"
	std::string cls;                  // class/source context (for vfuncs)
	int index = -1;                   // vtable slot (for vfuncs)
	int hits = 0;
	std::string note;
	std::set<std::string> actions;    // action labels that surfaced/hit this function
};

std::map<uintptr_t, FuncEntry> g_funcs;   // catalogVA -> entry
std::set<uintptr_t> g_dumpedVtables;      // vtable catalogVAs already expanded
bool g_logging = true;
bool g_dirty = false;
int g_events = 0;
std::string g_context;                    // current "/funccat mark" label
std::string g_docPath;
uint64_t g_lastSave = 0;
uint64_t g_nextAutoDump = 0;   // periodic + post-zone silent auto-dumpall timer

// per-character identity (multi-box: every character writes its own document) ----
std::string g_charName;
std::string g_classCode;
int g_level = 0;

// upload-to-site config (config\MQ2FuncCat.ini) ----
std::string g_url = "https://mmoplugins.com/api/funccat";   // ingestion endpoint
std::string g_token;                                        // per-account token (from the site)
bool g_autoSend = true;                                     // auto-POST while playing
uint64_t g_lastSend = 0;
uint64_t g_sendIntervalMs = 300000;                         // throttle auto-send to every 5 minutes

std::string SanitizeFile(const std::string& s)
{
	std::string o;
	for (char c : s) o += (isalnum((unsigned char)c) ? c : '_');
	return o.empty() ? "char" : o;
}

// Resolve the per-character document path once we're in-game. Returns true when a path is set.
bool EnsureDocPath()
{
	if (!g_docPath.empty()) return true;
	if (!pLocalPlayer || !pLocalPlayer->Name[0]) return false;   // not in game yet
	g_charName = pLocalPlayer->Name;
	const char* cc = pLocalPlayer->GetClassThreeLetterCode();
	g_classCode = (cc && *cc) ? cc : "";
	g_level = pLocalPlayer->Level;
	char dir[MAX_PATH];
	sprintf_s(dir, "%s\\FuncCat", gPathConfig);
	CreateDirectoryA(dir, nullptr);
	char path[MAX_PATH];
	sprintf_s(path, "%s\\FuncCat\\funccat_%s.json", gPathConfig, SanitizeFile(g_charName).c_str());
	g_docPath = path;
	return true;
}

std::string JsonEsc(const std::string& s)
{
	std::string o;
	for (char c : s)
	{
		if (c == '"' || c == '\\') { o += '\\'; o += c; }
		else if (c == '\n' || c == '\r' || c == '\t') o += ' ';
		else o += c;
	}
	return o;
}

std::string HexVA(uintptr_t va)
{
	char buf[32];
	sprintf_s(buf, "0x%llx", static_cast<unsigned long long>(va));
	return buf;
}

std::string BuildDoc()
{
	std::ostringstream f;
	f << "{\n";
	f << "  \"tool\": \"MQ2FuncCat\",\n";
	f << "  \"character\": \"" << JsonEsc(g_charName) << "\",\n";
	f << "  \"class\": \"" << JsonEsc(g_classCode) << "\",\n";
	f << "  \"level\": " << g_level << ",\n";
	f << "  \"imageBase\": \"" << HexVA(g_prefBase) << "\",\n";
	f << "  \"events\": " << g_events << ",\n";
	// identify every plugin loaded on this character (so the site knows each account's setup)
	f << "  \"plugins\": [";
	bool p1 = true;
	for (MQPlugin* p = pPlugins; p; p = p->pNext)
	{
		if (!p1) f << ",";
		p1 = false;
		char vb[16]; sprintf_s(vb, "%.1f", p->fpVersion);
		f << "\"" << JsonEsc(p->name + " v" + vb) << "\"";
	}
	f << "],\n";
	f << "  \"functions\": [\n";
	bool first = true;
	for (auto& kv : g_funcs)
	{
		FuncEntry& e = kv.second;
		if (!first) f << ",\n";
		first = false;
		f << "    {\"va\":\"" << HexVA(kv.first) << "\""
		  << ",\"name\":\"" << JsonEsc(e.name) << "\""
		  << ",\"kind\":\"" << e.kind << "\""
		  << ",\"class\":\"" << JsonEsc(e.cls) << "\""
		  << ",\"index\":" << e.index
		  << ",\"hits\":" << e.hits
		  << ",\"note\":\"" << JsonEsc(e.note) << "\""
		  << ",\"actions\":[";
		bool a1 = true;
		for (auto& a : e.actions) { if (!a1) f << ","; a1 = false; f << "\"" << JsonEsc(a) << "\""; }
		f << "]}";
	}
	f << "\n  ]\n}\n";
	return f.str();
}

void SaveDoc()
{
	if (!EnsureDocPath()) return;
	std::ofstream f(g_docPath, std::ios::trunc);
	if (!f) return;
	f << BuildDoc();
	g_dirty = false;
	g_lastSave = GetTickCount64();
}

// POST the catalog JSON to the MMOPlugins ingestion endpoint with the account token.
bool HttpPostJson(const std::string& url, const std::string& body, const std::string& token, std::string& out)
{
	URL_COMPONENTSA uc = { sizeof(uc) };
	char host[256] = { 0 }, path[1024] = { 0 };
	uc.lpszHostName = host; uc.dwHostNameLength = sizeof(host);
	uc.lpszUrlPath = path; uc.dwUrlPathLength = sizeof(path);
	if (!InternetCrackUrlA(url.c_str(), 0, 0, &uc)) { out = "bad url"; return false; }
	bool https = (uc.nScheme == INTERNET_SCHEME_HTTPS);

	HINTERNET hNet = InternetOpenA("MQ2FuncCat", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
	if (!hNet) { out = "InternetOpen failed"; return false; }
	HINTERNET hCon = InternetConnectA(hNet, host, uc.nPort, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hCon) { InternetCloseHandle(hNet); out = "connect failed"; return false; }
	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | (https ? INTERNET_FLAG_SECURE : 0);
	HINTERNET hReq = HttpOpenRequestA(hCon, "POST", path, nullptr, nullptr, nullptr, flags, 0);
	if (!hReq) { InternetCloseHandle(hCon); InternetCloseHandle(hNet); out = "open request failed"; return false; }

	std::string headers = "Content-Type: application/json\r\nX-FuncCat-Token: " + token + "\r\n";
	BOOL ok = HttpSendRequestA(hReq, headers.c_str(), (DWORD)headers.size(),
	                           (LPVOID)body.data(), (DWORD)body.size());
	bool success = false;
	if (ok)
	{
		DWORD code = 0, len = sizeof(code);
		HttpQueryInfoA(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &len, nullptr);
		char buf[2048]; DWORD got = 0; std::string resp;
		while (InternetReadFile(hReq, buf, sizeof(buf) - 1, &got) && got) { buf[got] = 0; resp += buf; }
		success = (code >= 200 && code < 300);
		out = "HTTP " + std::to_string(code) + " " + resp.substr(0, 300);
	}
	else out = "send failed";
	InternetCloseHandle(hReq); InternetCloseHandle(hCon); InternetCloseHandle(hNet);
	return success;
}

void SendDoc(bool verbose)
{
	if (!EnsureDocPath()) { if (verbose) WriteChatf("\ag[FuncCat]\ax not in game yet."); return; }
	if (g_token.empty()) { if (verbose) WriteChatf("\ar[FuncCat]\ax no token. Set it in config\\MQ2FuncCat.ini (get it on your MMOPlugins account page)."); return; }
	std::string resp;
	bool ok = HttpPostJson(g_url, BuildDoc(), g_token, resp);
	g_lastSend = GetTickCount64();
	if (verbose || !ok)
		WriteChatf("%s[FuncCat]\ax send %s -> %s", ok ? "\ag" : "\ar", ok ? "OK" : "FAILED", resp.c_str());
}

void ReadConfig()
{
	char ini[MAX_PATH];
	sprintf_s(ini, "%s\\MQ2FuncCat.ini", gPathConfig);
	char buf[1024] = { 0 };
	GetPrivateProfileStringA("Settings", "Url", g_url.c_str(), buf, sizeof(buf), ini);
	g_url = buf;
	GetPrivateProfileStringA("Settings", "Token", "", buf, sizeof(buf), ini);
	g_token = buf;
	g_autoSend = GetPrivateProfileIntA("Settings", "AutoSend", 1, ini) != 0;
	g_sendIntervalMs = static_cast<uint64_t>(GetPrivateProfileIntA("Settings", "SendIntervalSec", 300, ini)) * 1000ULL;
	if (GetFileAttributesA(ini) == INVALID_FILE_ATTRIBUTES)   // first run: drop a template the user edits
	{
		WritePrivateProfileStringA("Settings", "Url", g_url.c_str(), ini);
		WritePrivateProfileStringA("Settings", "Token", "", ini);
		WritePrivateProfileStringA("Settings", "AutoSend", "1", ini);
		WritePrivateProfileStringA("Settings", "SendIntervalSec", "300", ini);
	}
}

// Expand an object's vtable into the catalog. obj's first qword is its vtable pointer.
void DumpVtable(void* obj, const char* cls, const std::string& action, bool silent = false)
{
	if (!obj) return;
	uintptr_t vptr = *reinterpret_cast<uintptr_t*>(obj);   // vptr lives in module .rdata
	if (!InModule(vptr)) return;
	uintptr_t vcat = CatVA(vptr);
	if (g_dumpedVtables.count(vcat)) return;
	g_dumpedVtables.insert(vcat);

	uintptr_t* vt = reinterpret_cast<uintptr_t*>(vptr);
	int added = 0;
	for (int i = 0; i < 96; ++i)                            // bounded scan; stop at first non-code entry
	{
		uintptr_t fn = vt[i];
		if (!InModule(fn)) break;                           // end of this vtable
		uintptr_t fcat = CatVA(fn);
		FuncEntry& e = g_funcs[fcat];
		if (e.kind.empty()) { e.kind = "vfunc"; e.cls = cls; e.index = i; }
		if (!action.empty()) e.actions.insert(action);
		++added;
	}
	if (added) { g_dirty = true; if (!silent) WriteChatf("\ag[FuncCat]\ax %s vtable @ %s: \ay%d\ax funcs", cls, HexVA(vcat).c_str(), added); }
}

// Record/confirm a known hooked function and harvest the objects it received.
void OnAction(const char* funcName, uintptr_t runtimeFuncAddr, void* thisObj, void* targetObj,
              const char* thisCls, const char* targetCls, int skill)
{
	if (!g_logging) return;

	std::string action = funcName;
	const char* sn = (skill >= 0) ? GetSkillName(skill) : nullptr;
	if (sn && *sn) action = std::string(funcName) + ": " + sn;
	else if (skill >= 0) { char b[16]; sprintf_s(b, " #%d", skill); action += b; }
	if (!g_context.empty()) action += " [" + g_context + "]";

	uintptr_t fcat = CatVA(runtimeFuncAddr);
	if (fcat)
	{
		FuncEntry& e = g_funcs[fcat];
		if (e.name.empty()) { e.name = funcName; e.kind = "named"; }
		e.hits++;
		e.actions.insert(action);
	}
	DumpVtable(thisObj, thisCls, action);
	DumpVtable(targetObj, targetCls, action);
	g_events++;
	g_dirty = true;
}

// Sweep every major game object / manager / window vtable available right now. Used by the
// /funccat dumpall command (verbose) and by the automatic capture (silent, periodic + on-zone).
int DumpAllManagers(const std::string& action, bool silent)
{
	int before = static_cast<int>(g_funcs.size());
	if (pLocalPlayer)       DumpVtable(pLocalPlayer, "PlayerClient", action, silent);
	if (pLocalPC)           DumpVtable(pLocalPC, "PcClient", action, silent);
	if (pControlledPlayer)  DumpVtable(pControlledPlayer, "PlayerClient(controlled)", action, silent);
	if (pCharData)          DumpVtable(pCharData, "PcClient(charData)", action, silent);
	if (pCharSpawn)         DumpVtable(pCharSpawn, "PlayerClient(charSpawn)", action, silent);
	if (pTarget)            DumpVtable(pTarget, "PlayerClient(target)", action, silent);
	if (pEverQuest)         DumpVtable(pEverQuest, "CEverQuest", action, silent);
	if (pSpawnManager)      DumpVtable(pSpawnManager, "PlayerManagerClient", action, silent);
	if (pSpellMgr)          DumpVtable(pSpellMgr, "ClientSpellManager", action, silent);
	if (pContainerMgr)      DumpVtable(pContainerMgr, "CContainerMgr", action, silent);
	if (pInvSlotMgr)        DumpVtable(pInvSlotMgr, "CInvSlotMgr", action, silent);
	if (pSidlMgr)           DumpVtable(pSidlMgr, "CSidlManager", action, silent);
	if (pCastingWnd)        DumpVtable(pCastingWnd, "CCastingWnd", action, silent);
	if (pInventoryWnd)      DumpVtable(pInventoryWnd, "CInventoryWnd", action, silent);
	if (pSpellBookWnd)      DumpVtable(pSpellBookWnd, "CSpellBookWnd", action, silent);
	if (pTargetWnd)         DumpVtable(pTargetWnd, "CTargetWnd", action, silent);
	if (pMerchantWnd)       DumpVtable(pMerchantWnd, "CMerchantWnd", action, silent);
	if (pCharacterListWnd)  DumpVtable(pCharacterListWnd, "CCharacterListWnd", action, silent);
	return static_cast<int>(g_funcs.size()) - before;
}

// -------- detours on the action functions --------
class CharacterHook
{
public:
	DETOUR_TRAMPOLINE_DEF(void, UseSkill_Trampoline, (uint8_t, PlayerZoneClient*, bool))
	void UseSkill_Detour(uint8_t skill, PlayerZoneClient* target, bool bAuto)
	{
		OnAction("CharacterZoneClient::UseSkill", CharacterZoneClient__UseSkill,
		         this, target, "CharacterZoneClient", "PlayerZoneClient(target)", skill);
		UseSkill_Trampoline(skill, target, bAuto);
	}
};

class AttackHook
{
public:
	DETOUR_TRAMPOLINE_DEF(bool, DoAttack_Trampoline, (uint8_t, uint8_t, PlayerZoneClient*, bool, bool, bool))
	bool DoAttack_Detour(uint8_t slot, uint8_t skill, PlayerZoneClient* target, bool a, bool b, bool c)
	{
		OnAction("PlayerZoneClient::DoAttack", PlayerZoneClient__DoAttack,
		         this, target, "PlayerZoneClient(self)", "PlayerZoneClient(target)", skill);
		return DoAttack_Trampoline(slot, skill, target, a, b, c);
	}
};

// -------- command --------
void FuncCatCmd(PlayerClient* pChar, const char* szLine)
{
	char szArg1[MAX_STRING] = { 0 };
	GetArg(szArg1, szLine, 1);

	if (!_stricmp(szArg1, "on") || !_stricmp(szArg1, "off"))
	{
		g_logging = !_stricmp(szArg1, "on");
		WriteChatf("\ag[FuncCat]\ax auto-capture %s", g_logging ? "\agON" : "\arOFF");
		return;
	}
	if (!_stricmp(szArg1, "save")) { SaveDoc(); WriteChatf("\ag[FuncCat]\ax saved -> %s", g_docPath.c_str()); return; }
	if (!_stricmp(szArg1, "send")) { SendDoc(true); return; }
	if (!_stricmp(szArg1, "reset")) { g_funcs.clear(); g_dumpedVtables.clear(); g_events = 0; g_dirty = true; WriteChatf("\ag[FuncCat]\ax catalog cleared."); return; }
	if (!_stricmp(szArg1, "mark"))
	{
		g_context = std::string(GetNextArg(szLine, 1));
		WriteChatf("\ag[FuncCat]\ax context = \ay%s", g_context.empty() ? "(none)" : g_context.c_str());
		return;
	}
	if (!_stricmp(szArg1, "note"))
	{
		char szVA[MAX_STRING] = { 0 };
		GetArg(szVA, szLine, 2);
		uintptr_t va = strtoull(szVA, nullptr, 0);
		std::string name = GetNextArg(szLine, 2);
		if (!va || name.empty()) { WriteChatf("\ag[FuncCat]\ax usage: /funccat note 0xVA <Name>"); return; }
		FuncEntry& e = g_funcs[va];
		e.name = name; if (e.kind.empty()) e.kind = "noted";
		g_dirty = true;
		WriteChatf("\ag[FuncCat]\ax noted %s = \ay%s", HexVA(va).c_str(), name.c_str());
		return;
	}
	if (!_stricmp(szArg1, "dump"))
	{
		int before = static_cast<int>(g_funcs.size());
		if (pLocalPlayer) DumpVtable(pLocalPlayer, "PlayerClient(me)", "manual dump");
		if (pLocalPC)     DumpVtable(pLocalPC, "PcClient(me)", "manual dump");
		if (pTarget)      DumpVtable(pTarget, "PlayerClient(target)", "manual dump");
		WriteChatf("\ag[FuncCat]\ax dump added \ay%d\ax functions (total %d).",
		           static_cast<int>(g_funcs.size()) - before, static_cast<int>(g_funcs.size()));
		SaveDoc();
		return;
	}
	if (!_stricmp(szArg1, "dumpall"))
	{
		int added = DumpAllManagers("dumpall", false);
		WriteChatf("\ag[FuncCat]\ax dumpall added \ay%d\ax functions (total %d). \ay/funccat send\ax to upload now.",
		           added, static_cast<int>(g_funcs.size()));
		SaveDoc();
		return;
	}

	// status
	int named = 0, vf = 0, noted = 0;
	for (auto& kv : g_funcs)
	{
		if (kv.second.kind == "named") named++;
		else if (kv.second.kind == "vfunc") vf++;
		else noted++;
	}
	WriteChatf("\ag[MQ2FuncCat]\ax capture %s · \ay%d\ax functions (%d named, %d vfunc, %d noted) · %d events",
	           g_logging ? "\agON\ax" : "\arOFF\ax", static_cast<int>(g_funcs.size()), named, vf, noted, g_events);
	WriteChatf("  doc: %s", g_docPath.empty() ? "(set when in game)" : g_docPath.c_str());
	WriteChatf("  upload: %s  token:%s  autosend:%s", g_url.c_str(), g_token.empty() ? "\arNOT SET\ax" : "\agset\ax", g_autoSend ? "on" : "off");
	WriteChatf("  use abilities to auto-catalog; \ay/funccat dumpall\ax (managers+windows), \ay/funccat send\ax, \ay/funccat dump\ax, \ay/funccat mark <txt>\ax, \ay/funccat note 0xVA <Name>\ax");
}

} // namespace

PLUGIN_API void InitializePlugin()
{
	InitModuleInfo();
	ReadConfig();
	// doc path is resolved per-character once in game (EnsureDocPath) so each box gets its own file

	EzDetour(CharacterZoneClient__UseSkill, &CharacterHook::UseSkill_Detour, &CharacterHook::UseSkill_Trampoline);
	EzDetour(PlayerZoneClient__DoAttack, &AttackHook::DoAttack_Detour, &AttackHook::DoAttack_Trampoline);

	AddCommand("/funccat", FuncCatCmd);
	WriteChatf("\ag[MQ2FuncCat]\ax loaded. Use abilities in-game to catalog functions. \ay/funccat\ax for status.");
}

PLUGIN_API void ShutdownPlugin()
{
	if (g_dirty) SaveDoc();
	RemoveCommand("/funccat");
	RemoveDetour(CharacterZoneClient__UseSkill);
	RemoveDetour(PlayerZoneClient__DoAttack);
}

PLUGIN_API void OnPulse()
{
	uint64_t now = GetTickCount64();
	if (g_dirty && now - g_lastSave > 8000)
		SaveDoc();

	// automatic broad capture: re-sweep all managers/windows on a timer (dedup makes repeats cheap),
	// so open windows + loaded subsystems get cataloged without anyone typing /funccat dumpall.
	if (g_logging && pLocalPlayer && now >= g_nextAutoDump)
	{
		DumpAllManagers("auto", true);
		g_nextAutoDump = now + 30000;   // every 30s
	}

	// auto-upload to the site when new data has accumulated (throttled)
	if (g_autoSend && !g_token.empty() && now - g_lastSend > g_sendIntervalMs)
	{
		static size_t s_sentFuncs = 0;
		static int s_sentEvents = 0;
		if (!g_funcs.empty() && (g_funcs.size() != s_sentFuncs || g_events != s_sentEvents))
		{
			SendDoc(false);
			s_sentFuncs = g_funcs.size();
			s_sentEvents = g_events;
		}
	}
}

// Every spawn that appears (mobs you fight, pets, NPCs, corpses) exposes its class vtable -> capture
// it silently. Dedup means each distinct spawn-class vtable is recorded once, from normal play/killing.
PLUGIN_API void OnAddSpawn(PSPAWNINFO pNewSpawn)
{
	if (g_logging && pNewSpawn) DumpVtable(pNewSpawn, "PlayerClient(spawn)", "spawn", true);
}

// After zoning, sweep managers/windows again once the new zone's state is loaded.
PLUGIN_API void OnZoned()
{
	g_nextAutoDump = GetTickCount64() + 4000;
}
