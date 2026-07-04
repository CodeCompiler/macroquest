// MQ2PacketLab.cpp -- runtime PACKET/OPCODE cataloger for MacroQuest (MMOPlugins).
//
// Read-only protocol observer. It detours the client's opcode (de)scramblers --
// CPacketScrambler::ntoh (incoming) and CPacketScrambler::hton (outgoing), both eqlib
// signature-confirmed offsets, the same kind of long-stable function MQ2FuncCat hooks. Every
// packet's wire opcode passes through these, so we record, per opcode, how many times it was
// received vs sent. Upload that to MMOPlugins to mark which opcodes are seen live and which
// direction they flow -- the dynamic half of the opcode catalog (esp. the RECEIVE side, which
// static analysis can't recover).
//
// SAFETY: strictly observe-only. Each detour records the opcode, then calls the original and
// returns its result unchanged. It NEVER drops, alters, delays, reorders, or injects a packet.
// There is no tampering, blocking, or evasion code here by design.
//
// Commands:  /packetlab            status
//            /packetlab on|off     toggle capture (default on)
//            /packetlab send       upload now
//            /packetlab reset      clear the in-memory catalog
//            /packetlab top        list the most-seen opcodes

#include <mq/Plugin.h>

#include <windows.h>
#include <wininet.h>
#include <fstream>
#include <sstream>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>

#pragma comment(lib, "wininet.lib")

PreSetup("MQ2PacketLab");
PLUGIN_VERSION(1.0);

namespace {

struct OpRec { int recv = 0; int send = 0; };
std::map<uint16_t, OpRec> g_ops;           // wire opcode -> recv/send counts
bool g_logging = true, g_dirty = false;
int  g_events = 0;
std::string g_charName, g_classCode; int g_level = 0;
std::string g_docPath;
uint64_t g_lastSave = 0, g_lastSend = 0;

// upload config (config\MQ2PacketLab.ini)
std::string g_url = "https://mmoplugins.com/api/packetlab";
std::string g_token;
bool g_autoSend = true;
uint64_t g_sendIntervalMs = 300000;

std::string JsonEsc(const std::string& s)
{
	std::string o;
	for (char c : s) { if (c == '"' || c == '\\') { o += '\\'; o += c; } else if (c=='\n'||c=='\r'||c=='\t') o+=' '; else o += c; }
	return o;
}
std::string SanitizeFile(const std::string& s) { std::string o; for (char c : s) o += (isalnum((unsigned char)c) ? c : '_'); return o.empty()?"char":o; }

bool EnsureDocPath()
{
	if (!g_docPath.empty()) return true;
	if (!pLocalPlayer || !pLocalPlayer->Name[0]) return false;
	g_charName = pLocalPlayer->Name;
	const char* cc = pLocalPlayer->GetClassThreeLetterCode();
	g_classCode = (cc && *cc) ? cc : "";
	g_level = pLocalPlayer->Level;
	char dir[MAX_PATH]; sprintf_s(dir, "%s\\PacketLab", gPathConfig); CreateDirectoryA(dir, nullptr);
	char path[MAX_PATH]; sprintf_s(path, "%s\\PacketLab\\packetlab_%s.json", gPathConfig, SanitizeFile(g_charName).c_str());
	g_docPath = path; return true;
}

std::string BuildDoc()
{
	std::ostringstream f;
	f << "{\n  \"tool\": \"MQ2PacketLab\",\n";
	f << "  \"character\": \"" << JsonEsc(g_charName) << "\",\n";
	f << "  \"class\": \"" << JsonEsc(g_classCode) << "\",\n";
	f << "  \"level\": " << g_level << ",\n";
	f << "  \"events\": " << g_events << ",\n";
	f << "  \"opcodes\": [\n";
	bool first = true;
	for (auto& kv : g_ops)
	{
		if (!first) f << ",\n"; first = false;
		char op[16]; sprintf_s(op, "0x%04x", kv.first);
		const char* dir = (kv.second.recv && kv.second.send) ? "both" : (kv.second.recv ? "recv" : "send");
		f << "    {\"opcode\":\"" << op << "\",\"hits\":" << (kv.second.recv + kv.second.send)
		  << ",\"recv\":" << kv.second.recv << ",\"send\":" << kv.second.send
		  << ",\"dir\":\"" << dir << "\"}";
	}
	f << "\n  ]\n}\n";
	return f.str();
}

void SaveDoc() { if (!EnsureDocPath()) return; std::ofstream f(g_docPath, std::ios::trunc); if (!f) return; f << BuildDoc(); g_dirty=false; g_lastSave=GetTickCount64(); }

bool HttpPostJson(const std::string& url, const std::string& body, const std::string& token, std::string& out)
{
	URL_COMPONENTSA uc = { sizeof(uc) };
	char host[256] = {0}, path[1024] = {0};
	uc.lpszHostName = host; uc.dwHostNameLength = sizeof(host);
	uc.lpszUrlPath = path; uc.dwUrlPathLength = sizeof(path);
	if (!InternetCrackUrlA(url.c_str(), 0, 0, &uc)) { out = "bad url"; return false; }
	bool https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
	HINTERNET hNet = InternetOpenA("MQ2PacketLab", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
	if (!hNet) { out = "InternetOpen failed"; return false; }
	HINTERNET hCon = InternetConnectA(hNet, host, uc.nPort, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hCon) { InternetCloseHandle(hNet); out = "connect failed"; return false; }
	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | (https ? INTERNET_FLAG_SECURE : 0);
	HINTERNET hReq = HttpOpenRequestA(hCon, "POST", path, nullptr, nullptr, nullptr, flags, 0);
	if (!hReq) { InternetCloseHandle(hCon); InternetCloseHandle(hNet); out = "open request failed"; return false; }
	std::string headers = "Content-Type: application/json\r\nX-PacketLab-Token: " + token + "\r\n";
	BOOL ok = HttpSendRequestA(hReq, headers.c_str(), (DWORD)headers.size(), (LPVOID)body.data(), (DWORD)body.size());
	bool success = false;
	if (ok) {
		DWORD code = 0, len = sizeof(code);
		HttpQueryInfoA(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &len, nullptr);
		char buf[2048]; DWORD got = 0; std::string resp;
		while (InternetReadFile(hReq, buf, sizeof(buf)-1, &got) && got) { buf[got]=0; resp += buf; }
		success = (code >= 200 && code < 300);
		out = "HTTP " + std::to_string(code) + " " + resp.substr(0,300);
	} else out = "send failed";
	InternetCloseHandle(hReq); InternetCloseHandle(hCon); InternetCloseHandle(hNet);
	return success;
}

void SendDoc(bool verbose)
{
	if (!EnsureDocPath()) { if (verbose) WriteChatf("\ag[PacketLab]\ax not in game yet."); return; }
	if (g_token.empty()) { if (verbose) WriteChatf("\ar[PacketLab]\ax no token. Set it in config\\MQ2PacketLab.ini (from your MMOPlugins account page)."); return; }
	std::string resp; bool ok = HttpPostJson(g_url, BuildDoc(), g_token, resp); g_lastSend = GetTickCount64();
	if (verbose || !ok) WriteChatf("%s[PacketLab]\ax send %s -> %s", ok?"\ag":"\ar", ok?"OK":"FAILED", resp.c_str());
}

void ReadConfig()
{
	char ini[MAX_PATH]; sprintf_s(ini, "%s\\MQ2PacketLab.ini", gPathConfig);
	char buf[1024] = {0};
	GetPrivateProfileStringA("Settings", "Url", g_url.c_str(), buf, sizeof(buf), ini); g_url = buf;
	GetPrivateProfileStringA("Settings", "Token", "", buf, sizeof(buf), ini); g_token = buf;
	g_autoSend = GetPrivateProfileIntA("Settings", "AutoSend", 1, ini) != 0;
	g_sendIntervalMs = (uint64_t)GetPrivateProfileIntA("Settings", "SendIntervalSec", 300, ini) * 1000ULL;
	if (GetFileAttributesA(ini) == INVALID_FILE_ATTRIBUTES) {
		WritePrivateProfileStringA("Settings", "Url", g_url.c_str(), ini);
		WritePrivateProfileStringA("Settings", "Token", "", ini);
		WritePrivateProfileStringA("Settings", "AutoSend", "1", ini);
		WritePrivateProfileStringA("Settings", "SendIntervalSec", "300", ini);
	}
}

inline void RecordOp(uint16_t opcode, bool recv)
{
	if (!g_logging) return;
	OpRec& r = g_ops[opcode];
	if (recv) r.recv++; else r.send++;
	g_events++; g_dirty = true;
}

// -------- the read-only detours: opcode (de)scramblers --------
// Both are CPacketScrambler members: (this=scrambler, uint32 opcode) -> opcode. We only read
// the opcode, then call the original untouched. ntoh = incoming, hton = outgoing.
class ScramblerHook
{
public:
	DETOUR_TRAMPOLINE_DEF(uint32_t, ntoh_Trampoline, (uint32_t))
	uint32_t ntoh_Detour(uint32_t opcode)
	{
		RecordOp((uint16_t)(opcode & 0xFFFF), true);    // incoming
		return ntoh_Trampoline(opcode);
	}
	DETOUR_TRAMPOLINE_DEF(uint32_t, hton_Trampoline, (uint32_t))
	uint32_t hton_Detour(uint32_t opcode)
	{
		RecordOp((uint16_t)(opcode & 0xFFFF), false);   // outgoing
		return hton_Trampoline(opcode);
	}
};

void PacketLabCmd(PlayerClient* pChar, const char* szLine)
{
	char a1[MAX_STRING] = {0}; GetArg(a1, szLine, 1);
	if (!_stricmp(a1, "on") || !_stricmp(a1, "off")) { g_logging = !_stricmp(a1, "on"); WriteChatf("\ag[PacketLab]\ax capture %s", g_logging?"\agON":"\arOFF"); return; }
	if (!_stricmp(a1, "send")) { SendDoc(true); return; }
	if (!_stricmp(a1, "save")) { SaveDoc(); WriteChatf("\ag[PacketLab]\ax saved -> %s", g_docPath.c_str()); return; }
	if (!_stricmp(a1, "reset")) { g_ops.clear(); g_events = 0; g_dirty = true; WriteChatf("\ag[PacketLab]\ax cleared."); return; }
	if (!_stricmp(a1, "top")) {
		std::vector<std::pair<uint16_t,int>> v; for (auto& kv : g_ops) v.push_back({kv.first, kv.second.recv + kv.second.send});
		std::sort(v.begin(), v.end(), [](auto&a,auto&b){return a.second>b.second;});
		WriteChatf("\ag[PacketLab]\ax top opcodes:");
		for (int i = 0; i < (int)v.size() && i < 15; ++i) { auto& r = g_ops[v[i].first]; WriteChatf("   0x%04x  %d (r%d/s%d)", v[i].first, v[i].second, r.recv, r.send); }
		return;
	}
	int recvN = 0, sendN = 0; for (auto& kv : g_ops) { recvN += kv.second.recv; sendN += kv.second.send; }
	WriteChatf("\ag[MQ2PacketLab]\ax capture %s · \ay%d\ax distinct opcodes · %d recv / %d sent",
		g_logging?"\agON\ax":"\arOFF\ax", (int)g_ops.size(), recvN, sendN);
	WriteChatf("  upload: %s  token:%s  autosend:%s", g_url.c_str(), g_token.empty()?"\arNOT SET\ax":"\agset\ax", g_autoSend?"on":"off");
	WriteChatf("  \ay/packetlab top\ax · \ay/packetlab send\ax · \ay/packetlab on|off\ax  (read-only protocol observer)");
}

} // namespace

PLUGIN_API void InitializePlugin()
{
	ReadConfig();
	EzDetour(CPacketScrambler__ntoh, &ScramblerHook::ntoh_Detour, &ScramblerHook::ntoh_Trampoline);
	EzDetour(CPacketScrambler__hton, &ScramblerHook::hton_Detour, &ScramblerHook::hton_Trampoline);
	AddCommand("/packetlab", PacketLabCmd);
	WriteChatf("\ag[MQ2PacketLab]\ax loaded (read-only). Play normally to catalog packet opcodes. \ay/packetlab\ax for status.");
}

PLUGIN_API void ShutdownPlugin()
{
	if (g_dirty) SaveDoc();
	RemoveCommand("/packetlab");
	RemoveDetour(CPacketScrambler__ntoh);
	RemoveDetour(CPacketScrambler__hton);
}

PLUGIN_API void OnPulse()
{
	uint64_t now = GetTickCount64();
	if (g_dirty && now - g_lastSave > 8000) SaveDoc();
	if (g_autoSend && !g_token.empty() && now - g_lastSend > g_sendIntervalMs)
	{
		static size_t s_sent = 0; static int s_evt = 0;
		if (!g_ops.empty() && (g_ops.size() != s_sent || g_events != s_evt)) { SendDoc(false); s_sent = g_ops.size(); s_evt = g_events; }
	}
}
