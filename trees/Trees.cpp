#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstdint>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "Signatures.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "winmm.lib")

#define DIAG_CAPTURE_FIRE 0

static volatile LONG g_inGameFired = 0;

static void LogPath(char* out, DWORD n)
{
    HMODULE self = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&LogPath), &self);
    GetModuleFileNameA(self, out, n);
    char* slash = strrchr(out, '\\');
    if (slash) strcpy_s(slash + 1, n - (DWORD)(slash + 1 - out), "trees.log");
}

static void RotateLogIfHuge()
{
    char p[MAX_PATH]; LogPath(p, MAX_PATH);
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExA(p, GetFileExInfoStandard, &fad)) return;
    ULONGLONG sz = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (sz < 50ULL * 1024 * 1024) return;
    char old_[MAX_PATH]; strcpy_s(old_, p);
    char* dot = strrchr(old_, '.');
    if (!dot) return;
    *dot = 0;
    strcat_s(old_, MAX_PATH, ".old.log");
    DeleteFileA(old_);
    MoveFileA(p, old_);
}

static int g_logEnabled = -1;
static void Log(const char* fmt, ...)
{
    if (g_logEnabled < 0) {
        char mp[MAX_PATH]; HMODULE self = nullptr;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&Log), &self);
        GetModuleFileNameA(self, mp, MAX_PATH);
        char* slash = strrchr(mp, '\\');
        if (slash) strcpy_s(slash + 1, MAX_PATH - (DWORD)(slash + 1 - mp), "forest_debug.txt");
        g_logEnabled = (GetFileAttributesA(mp) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
    }
    if (!g_logEnabled) return;
    char path[MAX_PATH]; LogPath(path, MAX_PATH);
    FILE* f = nullptr;
    if (fopen_s(&f, path, "a") != 0 || !f) return;
    SYSTEMTIME t; GetLocalTime(&t);
    fprintf(f, "[%02d:%02d:%02d.%03d pid=%lu] ",
            t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, GetCurrentProcessId());
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static volatile const char* g_uiModuleName = "app.dll";
static HMODULE FindPolUi()
{
    static const char* kNames[] = { "app.dll", "appEU.dll", "appJP.dll" };
    for (auto n : kNames) {
        HMODULE h = GetModuleHandleA(n);
        if (h) { g_uiModuleName = n; return h; }
    }
    return nullptr;
}

static void DllSibling(char* out, DWORD n, const char* leaf)
{
    LogPath(out, n);
    char* slash = strrchr(out, '\\');
    if (slash) strcpy_s(slash + 1, n - (DWORD)(slash + 1 - out), leaf);
}

static void PidPaths(char* out, char* fallback, DWORD n,
                     const char* prefix, const char* ext)
{
    char leaf[64];
    sprintf_s(leaf, "%s_%lu.%s", prefix, GetCurrentProcessId(), ext);
    DllSibling(out, n, leaf);
    sprintf_s(leaf, "%s.%s", prefix, ext);
    DllSibling(fallback, n, leaf);
}

static void WriteStatus(const char* state, const char* msg)
{
    char p[MAX_PATH]; char leaf[48];
    sprintf_s(leaf, "status_%lu.txt", GetCurrentProcessId());
    DllSibling(p, MAX_PATH, leaf);
    FILE* f = nullptr;
    if (fopen_s(&f, p, "w") != 0 || !f) return;
    SYSTEMTIME t; GetLocalTime(&t);
    fprintf(f, "%s|%s|%02d:%02d:%02d\n", state, msg ? msg : "",
            t.wHour, t.wMinute, t.wSecond);
    fclose(f);
}

static bool SafeRead(uintptr_t addr, void* dst, size_t n)
{
    __try
    {
        memcpy(dst, reinterpret_cast<const void*>(addr), n);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static uint32_t Deref(uintptr_t addr, bool& ok)
{
    uint32_t v = 0;
    ok = SafeRead(addr, &v, 4);
    return v;
}

static void ParsePattern(const char* pat, std::vector<uint8_t>& bytes,
                         std::vector<bool>& mask)
{
    for (const char* p = pat; *p; )
    {
        if (*p == ' ') { ++p; continue; }
        if (*p == '?')
        {
            bytes.push_back(0); mask.push_back(false);
            ++p; if (*p == '?') ++p;
        }
        else
        {
            bytes.push_back((uint8_t)strtoul(p, nullptr, 16));
            mask.push_back(true); p += 2;
        }
    }
}

static uint8_t* ScanModule(HMODULE mod, const char* pattern)
{
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return nullptr;

    std::vector<uint8_t> sig; std::vector<bool> mask;
    ParsePattern(pattern, sig, mask);
    if (sig.empty()) return nullptr;

    auto* base = reinterpret_cast<uint8_t*>(mi.lpBaseOfDll);
    uint8_t* end = base + mi.SizeOfImage - sig.size();

    for (uint8_t* p = base; p <= end; )
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(p, &mbi, sizeof(mbi))) { ++p; continue; }
        bool readable = (mbi.State == MEM_COMMIT) &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD);
        auto* regionEnd = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd > end + sig.size()) regionEnd = end + sig.size();
        if (readable)
            for (uint8_t* s = p; s + sig.size() <= regionEnd; ++s)
            {
                size_t i = 0;
                for (; i < sig.size(); ++i)
                    if (mask[i] && s[i] != sig[i]) break;
                if (i == sig.size()) return s;
            }
        p = regionEnd;
    }
    return nullptr;
}

typedef void (__thiscall* CharFeed)(void* self, int index, uint16_t* pwc);

static uintptr_t       g_fnApply  = 0;
static uintptr_t       g_fnBfc    = 0;
static wchar_t         g_pw[128]  = { 0 };
static int             g_pwLen    = 0;

typedef void (__thiscall* ApplyFn)(void* self);
typedef void (__thiscall* NotifyFn)(void* self, int result);

static bool LoadCred()
{
    char path[MAX_PATH], fb[MAX_PATH];
    PidPaths(path, fb, MAX_PATH, "cred", "bin");

    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        strcpy_s(path, MAX_PATH, fb);
        h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                        OPEN_EXISTING, 0, nullptr);
    }
    if (h == INVALID_HANDLE_VALUE) return false;
    BYTE enc[512]; DWORD got = 0;
    ReadFile(h, enc, sizeof(enc), &got, nullptr);
    CloseHandle(h);
    if (!got) return false;

    DATA_BLOB in{ got, enc }, out{ 0, nullptr };
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
    { Log("LoadCred: DPAPI decrypt failed (%lu).", GetLastError()); return false; }

    int n = MultiByteToWideChar(CP_UTF8, 0, (char*)out.pbData, out.cbData,
                                g_pw, 127);
    g_pwLen = n; g_pw[n] = 0;
    SecureZeroMemory(out.pbData, out.cbData); LocalFree(out.pbData);
    SecureZeroMemory(enc, sizeof(enc));
    DeleteFileA(path);
    Log("LoadCred: credential decrypted in-process (%d chars). Submit ARMED.", n);
    return n > 0;
}

static char g_totpSecret[128] = { 0 };
static bool g_haveTotp = false;

struct Sha1Ctx { uint32_t h[5]; uint64_t len; uint8_t buf[64]; int n; };
static uint32_t Rol(uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }
static void Sha1Blk(Sha1Ctx* c, const uint8_t* p)
{
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = (p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
    for (int i = 16; i < 80; ++i)
        w[i] = Rol(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
    uint32_t a=c->h[0],b=c->h[1],d=c->h[2],e=c->h[3],f=c->h[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t k, t;
        if      (i<20) { t=(b&d)|(~b&e);            k=0x5A827999; }
        else if (i<40) { t=b^d^e;                   k=0x6ED9EBA1; }
        else if (i<60) { t=(b&d)|(b&e)|(d&e);       k=0x8F1BBCDC; }
        else           { t=b^d^e;                   k=0xCA62C1D6; }
        uint32_t tmp = Rol(a,5)+t+f+k+w[i];
        f=e; e=d; d=Rol(b,30); b=a; a=tmp;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=d; c->h[3]+=e; c->h[4]+=f;
}
static void Sha1Init(Sha1Ctx* c)
{
    c->h[0]=0x67452301; c->h[1]=0xEFCDAB89; c->h[2]=0x98BADCFE;
    c->h[3]=0x10325476; c->h[4]=0xC3D2E1F0; c->len=0; c->n=0;
}
static void Sha1Upd(Sha1Ctx* c, const uint8_t* p, size_t len)
{
    c->len += len;
    while (len) {
        int take = 64 - c->n; if ((size_t)take > len) take = (int)len;
        memcpy(c->buf + c->n, p, take); c->n += take; p += take; len -= take;
        if (c->n == 64) { Sha1Blk(c, c->buf); c->n = 0; }
    }
}
static void Sha1Fin(Sha1Ctx* c, uint8_t out[20])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80; Sha1Upd(c, &pad, 1);
    uint8_t z = 0; while (c->n != 56) Sha1Upd(c, &z, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; ++i) lb[i] = (uint8_t)(bits >> (56 - i*8));
    Sha1Upd(c, lb, 8);
    for (int i = 0; i < 5; ++i) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}
static void HmacSha1(const uint8_t* key, int kl,
                     const uint8_t* msg, int ml, uint8_t out[20])
{
    uint8_t k[64] = { 0 };
    if (kl > 64) { Sha1Ctx c; Sha1Init(&c); Sha1Upd(&c,key,kl); Sha1Fin(&c,k); }
    else memcpy(k, key, kl);
    uint8_t ip[64], op[64];
    for (int i = 0; i < 64; ++i) { ip[i]=k[i]^0x36; op[i]=k[i]^0x5C; }
    uint8_t ih[20]; Sha1Ctx c;
    Sha1Init(&c); Sha1Upd(&c,ip,64); Sha1Upd(&c,msg,ml); Sha1Fin(&c,ih);
    Sha1Init(&c); Sha1Upd(&c,op,64); Sha1Upd(&c,ih,20); Sha1Fin(&c,out);
}
static int Base32Dec(const char* s, uint8_t* out, int cap)
{
    int bits = 0, val = 0, n = 0;
    for (; *s; ++s) {
        char ch = *s;
        if (ch=='='||ch==' ') continue;
        int v;
        if (ch>='A'&&ch<='Z') v = ch-'A';
        else if (ch>='a'&&ch<='z') v = ch-'a';
        else if (ch>='2'&&ch<='7') v = ch-'2'+26;
        else continue;
        val = (val<<5)|v; bits += 5;
        if (bits >= 8) { if (n<cap) out[n++] = (uint8_t)((val>>(bits-8))&0xFF);
                         bits -= 8; }
    }
    return n;
}

static bool TotpNow(char out[7])
{
    if (!g_haveTotp) return false;
    uint8_t key[64];
    int kl = Base32Dec(g_totpSecret, key, sizeof(key));
    if (kl <= 0) return false;
    uint64_t ctr = (uint64_t)time(nullptr) / 30;
    uint8_t msg[8];
    for (int i = 7; i >= 0; --i) { msg[i] = (uint8_t)(ctr & 0xFF); ctr >>= 8; }
    uint8_t h[20]; HmacSha1(key, kl, msg, 8, h);
    int o = h[19] & 0x0F;
    uint32_t bin = ((h[o]&0x7F)<<24)|((h[o+1]&0xFF)<<16)
                 | ((h[o+2]&0xFF)<<8)|(h[o+3]&0xFF);
    sprintf_s(out, 7, "%06u", bin % 1000000u);
    SecureZeroMemory(key, sizeof(key));
    return true;
}

static bool LoadTotp()
{
    char path[MAX_PATH], fb[MAX_PATH];
    PidPaths(path, fb, MAX_PATH, "totp", "bin");
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        strcpy_s(path, MAX_PATH, fb);
        h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                        OPEN_EXISTING, 0, nullptr);
    }
    if (h == INVALID_HANDLE_VALUE) return false;
    BYTE enc[512]; DWORD got = 0;
    ReadFile(h, enc, sizeof(enc), &got, nullptr);
    CloseHandle(h);
    if (!got) return false;
    DATA_BLOB in{ got, enc }, out{ 0, nullptr };
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
    { Log("LoadTotp: DPAPI decrypt failed (%lu).", GetLastError()); return false; }
    int n = out.cbData < 127 ? (int)out.cbData : 127;
    memcpy(g_totpSecret, out.pbData, n); g_totpSecret[n] = 0;
    SecureZeroMemory(out.pbData, out.cbData); LocalFree(out.pbData);
    SecureZeroMemory(enc, sizeof(enc));
    DeleteFileA(path);
    g_haveTotp = true;
    Log("LoadTotp: TOTP secret decrypted in-process (%d b32 chars). OTP ARMED.", n);
    return true;
}

struct FindCtx { DWORD pid; HWND hwnd; };
static BOOL CALLBACK EnumW(HWND h, LPARAM lp)
{
    auto* c = (FindCtx*)lp;
    DWORD wpid = 0; GetWindowThreadProcessId(h, &wpid);
    if (wpid != c->pid || !IsWindowVisible(h)) return TRUE;
    char t[64]; GetWindowTextA(h, t, sizeof(t));
    if (strstr(t, "PlayOnline")) { c->hwnd = h; return FALSE; }
    if (!c->hwnd) {
        char cls[64] = {0}; GetClassNameA(h, cls, sizeof(cls));
        if (strcmp(cls, "FFXiClass") != 0) {
            LONG style = GetWindowLongA(h, GWL_STYLE);
            if (!(style & WS_CHILD) && ((style & WS_CAPTION) || (style & WS_BORDER)) && !GetWindow(h, GW_OWNER)) {
                RECT r{};
                if (GetWindowRect(h, &r) && (r.right - r.left) >= 200 && (r.bottom - r.top) >= 100)
                    c->hwnd = h;
            }
        }
    }
    return TRUE;
}
static uintptr_t       g_bp[3]    = { 0, 0, 0 };
static uintptr_t       g_uiBase   = 0;
static PVOID           g_veh      = nullptr;
static uintptr_t       g_fnSelRow = 0;

static volatile uint32_t g_memberList = 0;
static volatile uint32_t g_rowVtbl    = 0;

#if DIAG_CAPTURE_FIRE
#define FIRE_BP_RING 64
#define FIRE_BP_STACK 8
static volatile uint32_t g_fireAct[FIRE_BP_RING] = { 0 };
static volatile uint32_t g_fireArg[FIRE_BP_RING] = { 0 };
static volatile uint32_t g_fireRet[FIRE_BP_RING] = { 0 };
static volatile uint32_t g_fireEsp[FIRE_BP_RING] = { 0 };
static volatile uint32_t g_fireStk[FIRE_BP_RING][FIRE_BP_STACK] = { { 0 } };
static volatile LONG     g_fireWr = 0;
static volatile LONG     g_fireRd = 0;
static void FireBpCapture(uint32_t act, uint32_t arg, uint32_t ret, uint32_t esp)
{
    LONG i = InterlockedIncrement(&g_fireWr) - 1;
    int idx = i % FIRE_BP_RING;
    g_fireAct[idx] = act;
    g_fireArg[idx] = arg;
    g_fireRet[idx] = ret;
    g_fireEsp[idx] = esp;
    __try {
        for (int k = 0; k < FIRE_BP_STACK; ++k)
            g_fireStk[idx][k] = *(uint32_t*)(esp + 4 + k * 4);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        for (int k = 0; k < FIRE_BP_STACK; ++k) g_fireStk[idx][k] = 0;
    }
}
static void FlushFireBpRing(uint32_t base)
{
    static uint32_t seenAct[128] = { 0 };
    static int      seenN       = 0;

    LONG wr = g_fireWr;
    while (g_fireRd < wr) {
        LONG idx = g_fireRd % FIRE_BP_RING;
        uint32_t act = g_fireAct[idx];
        uint32_t arg = g_fireArg[idx];
        uint32_t ret = g_fireRet[idx];
        ++g_fireRd;
        if (!act) continue;

        uint32_t vt = 0;
        __try { vt = *(uint32_t*)act; } __except (EXCEPTION_EXECUTE_HANDLER) {}
        uint32_t vtRva = (vt >= base && vt <= base + 0x600000)
                         ? (vt - base) : 0xFFFFFFFF;

        bool known = false;
        for (int i = 0; i < seenN; ++i)
            if (seenAct[i] == act) { known = true; break; }

        if (known) {
            Log("FIRE-BP: act=0x%08X (repeat) ret=0x%08X", act, ret);
            continue;
        }
        if (seenN < 128) seenAct[seenN++] = act;

        wchar_t nm[40] = { 0 }; int ni = 0;
        __try {
            for (; ni < 39; ++ni) {
                uint16_t wc = *(uint16_t*)(arg + ni * 2);
                if (!wc) break;
                nm[ni] = (wchar_t)wc;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        nm[ni] = 0;

        char an[40] = { 0 }; int ai = 0;
        __try {
            for (; ai < 39; ++ai) {
                char c = *(char*)(arg + ai);
                if (!c) break;
                if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E)
                { ai = 0; break; }
                an[ai] = c;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { ai = 0; }
        an[ai] = 0;

        Log("FIRE-BP: act=0x%08X vt-rva=0x%X arg=0x%08X ret=0x%08X "
            "name-w=[%.32ls] name-a=[%.32s]",
            act, vtRva, arg, ret, nm, an);

        uint32_t esp = g_fireEsp[idx];
        char stk[256]; int sp = 0;
        sp += sprintf_s(stk + sp, sizeof(stk) - sp, "  stk(esp=0x%08X):", esp);
        for (int k = 0; k < FIRE_BP_STACK; ++k) {
            uint32_t v = g_fireStk[idx][k];
            const char* tag = "";
            if (v >= base && v <= base + 0x600000) tag = "*";
            sp += sprintf_s(stk + sp, sizeof(stk) - sp, " %08X%s", v, tag);
        }
        Log("%s", stk);

        __try {
            for (int row = 0; row < 4; ++row) {
                uint32_t d0 = *(uint32_t*)(act + row * 16 + 0);
                uint32_t d1 = *(uint32_t*)(act + row * 16 + 4);
                uint32_t d2 = *(uint32_t*)(act + row * 16 + 8);
                uint32_t d3 = *(uint32_t*)(act + row * 16 + 12);
                Log("  act+0x%02X: %08X %08X %08X %08X",
                    row * 16, d0, d1, d2, d3);
            }
            for (int row = 0; row < 4; ++row) {
                char line[80]; int p = 0;
                p += sprintf_s(line + p, sizeof(line) - p,
                               "  act+0x%02X bytes:", row * 16);
                for (int col = 0; col < 16; ++col) {
                    uint8_t b = *(uint8_t*)(act + row * 16 + col);
                    p += sprintf_s(line + p, sizeof(line) - p, " %02X", b);
                }
                Log("%s", line);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("  (SEH while dumping act fields)");
        }
    }
}
#endif

#define VEH_CAP_RING 32
static volatile uint32_t g_selRowRing[VEH_CAP_RING] = { 0 };
static volatile uint32_t g_selRowArg[VEH_CAP_RING] = { 0 };
static volatile LONG     g_selRowWr   = 0;
static volatile LONG     g_selRowRd   = 0;
static void VehCapture(uint32_t ecx, uint32_t rowArg)
{
    LONG i = InterlockedIncrement(&g_selRowWr) - 1;
    g_selRowRing[i % VEH_CAP_RING] = ecx;
    g_selRowArg[i % VEH_CAP_RING] = rowArg;
}
static void FlushSelRowRing(uint32_t base)
{
    LONG wr = g_selRowWr;
    while (g_selRowRd < wr) {
        uint32_t ecx = g_selRowRing[g_selRowRd % VEH_CAP_RING];
        uint32_t row = g_selRowArg[g_selRowRd % VEH_CAP_RING];
        ++g_selRowRd;
        if (!ecx) continue;
        uint32_t vt = 0;
        __try { vt = *(uint32_t*)ecx; } __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (vt >= base && vt <= base + 0x600000)
            Log("VEH-selRow: ecx=0x%08X row=%d vt-rva=0x%X%s",
                ecx, (int)row, vt - base,
                (vt == base + 0x33219C) ? "  <-- matches row-container vt 0x33219C" : "");
        else
            Log("VEH-selRow: ecx=0x%08X row=%d vt=0x%08X (not in app.dll)", ecx, (int)row, vt);
    }
}

#define POL_STASH_WND 1

static void SetHwBp(int slot, uintptr_t addr)
{
    THREADENTRY32 te{ sizeof(te) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    DWORD me = GetCurrentProcessId(), self = GetCurrentThreadId();
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te))
    {
        if (te.th32OwnerProcessID != me || te.th32ThreadID == self) continue;
        HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                               THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (!th) continue;
        SuspendThread(th);
        CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(th, &c))
        {
            if      (slot == 0) { c.Dr0 = addr; c.Dr7 = (c.Dr7 & ~0xFUL)   | 0x1;  }
            else if (slot == 1) { c.Dr1 = addr; c.Dr7 = (c.Dr7 & ~0xF0UL)  | 0x4;  }
            else                { c.Dr2 = addr; c.Dr7 = (c.Dr7 & ~0xF00UL) | 0x10; }
            c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            SetThreadContext(th, &c);
        }
        ResumeThread(th);
        CloseHandle(th);
    }
    CloseHandle(snap);
}

static LONG CALLBACK Veh(EXCEPTION_POINTERS* ep)
{
    auto* er = ep->ExceptionRecord;
    auto* cx = ep->ContextRecord;
    if (er->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;

    uintptr_t at = (uintptr_t)er->ExceptionAddress;
    int slot = (at == g_bp[0]) ? 0 : (at == g_bp[1]) ? 1 : (at == g_bp[2]) ? 2 : -1;
    if (slot < 0) return EXCEPTION_CONTINUE_SEARCH;

#if DIAG_CAPTURE_FIRE
    if (slot == 0) {
        uint32_t arg = 0;
        __try { arg = *(uint32_t*)(cx->Esp + 4); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        uint32_t ret = 0;
        __try { ret = *(uint32_t*)cx->Esp; }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        FireBpCapture(cx->Ecx, arg, ret, cx->Esp);
        cx->Dr6 = 0; cx->EFlags |= 0x10000;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
#endif

    if (slot == 2) {
        uint32_t self = cx->Ecx;
        if (self) {
            uint32_t rowArg = 0;
            __try { rowArg = *(uint32_t*)(cx->Esp + 4); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            VehCapture(self, rowArg);
            uint32_t base = (uint32_t)g_uiBase;
            uint32_t vt = 0;
            __try { vt = *(uint32_t*)self; } __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (vt >= base && vt <= base + 0x600000) {
                if (g_rowVtbl == 0) g_rowVtbl = vt;
                if (vt == g_rowVtbl && g_memberList == 0) g_memberList = self;
            }
        }
        cx->Dr6 = 0;
        cx->EFlags |= 0x10000;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static volatile uint32_t g_mlOff[3]  = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
static volatile uint32_t g_mlInner    = 0;

static void ProbeMemberListInner(uint32_t base)
{
    if (g_mlOff[0] != 0xFFFFFFFF) return;

    __try {
        uint32_t frame = *(uint32_t*)(base + 0x5069C0);
        if (!frame || frame < 0x10000 || frame > 0x7FFE0000) return;
        if (*(uint32_t*)frame != base + 0x3CC4F4) return;
        if (!(*(uint8_t*)(frame + 0xF4) & 1)) return;

        const uint32_t target = base + 0x33219C;
        const uint32_t L1 = 0x400, L2 = 0x200, L3 = 0x100;

        auto looksLikePtr = [](uint32_t v) {
            return v >= 0x10000 && v <= 0x7FFE0000;
        };

        for (uint32_t a = 0; a < L1; a += 4) {
            uint32_t fld = *(uint32_t*)(frame + a);
            if (!looksLikePtr(fld)) continue;
            if (*(uint32_t*)fld == target) {
                g_mlOff[1] = 0xFFFFFFFF;
                g_mlOff[2] = 0xFFFFFFFF;
                g_mlOff[0] = a;
                g_mlInner = fld;
                Log("ML-INNER: FOUND depth-1: frame=0x%08X +0x%X -> "
                    "inner=0x%08X (vt=base+0x33219C)", frame, a, fld);
                return;
            }
        }

        for (uint32_t a = 0; a < L1; a += 4) {
            uint32_t mid = *(uint32_t*)(frame + a);
            if (!looksLikePtr(mid)) continue;
            uint32_t mvt = *(uint32_t*)mid;
            if (mvt < base || mvt > base + 0x600000) continue;
            for (uint32_t b = 0; b < L2; b += 4) {
                uint32_t fld = *(uint32_t*)(mid + b);
                if (!looksLikePtr(fld)) continue;
                if (*(uint32_t*)fld == target) {
                    g_mlOff[2] = 0xFFFFFFFF;
                    g_mlOff[1] = b;
                    g_mlOff[0] = a;
                    g_mlInner = fld;
                    Log("ML-INNER: FOUND depth-2: frame+0x%X (mid=0x%08X) "
                        "+0x%X -> inner=0x%08X", a, mid, b, fld);
                    return;
                }
            }
        }

        for (uint32_t a = 0; a < L1; a += 4) {
            uint32_t mid = *(uint32_t*)(frame + a);
            if (!looksLikePtr(mid)) continue;
            uint32_t mvt = *(uint32_t*)mid;
            if (mvt < base || mvt > base + 0x600000) continue;
            for (uint32_t b = 0; b < L2; b += 4) {
                uint32_t mid2 = *(uint32_t*)(mid + b);
                if (!looksLikePtr(mid2)) continue;
                uint32_t mvt2 = *(uint32_t*)mid2;
                if (mvt2 < base || mvt2 > base + 0x600000) continue;
                for (uint32_t c = 0; c < L3; c += 4) {
                    uint32_t fld = *(uint32_t*)(mid2 + c);
                    if (!looksLikePtr(fld)) continue;
                    if (*(uint32_t*)fld == target) {
                        g_mlOff[2] = c;
                        g_mlOff[1] = b;
                        g_mlOff[0] = a;
                        g_mlInner = fld;
                        Log("ML-INNER: FOUND depth-3: frame+0x%X "
                            "+0x%X +0x%X -> inner=0x%08X", a, b, c, fld);
                        return;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {   }
}

static uint32_t ResolveMemberListInner(uint32_t base)
{
    if (g_mlOff[0] == 0xFFFFFFFF) return 0;
    __try {
        uint32_t frame = *(uint32_t*)(base + 0x5069C0);
        if (!frame) return 0;
        uint32_t p = *(uint32_t*)(frame + g_mlOff[0]);
        if (g_mlOff[1] != 0xFFFFFFFF && p) p = *(uint32_t*)(p + g_mlOff[1]);
        if (g_mlOff[2] != 0xFFFFFFFF && p) p = *(uint32_t*)(p + g_mlOff[2]);
        if (p && *(uint32_t*)p == base + 0x33219C) return p;
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
    return 0;
}

static uint32_t ResolveField(uint32_t skw)
{
    bool k;
    uint32_t a = Deref(skw + 0x18C, k); if (!k) return 0;
    uint32_t b = Deref(a   + 0x228, k); if (!k) return 0;
    uint32_t o = Deref(b   + 0x1BC, k); if (!k) return 0;
    return o;
}

static void FeedSoftKbdField(uint32_t skw, const wchar_t* chars, int n, const char* what)
{
    __try
    {
        uint32_t fieldObj = ResolveField(skw);
        if (!fieldObj) { Log("nav: ResolveField failed (skw=0x%08X).", skw); return; }
        void** vt = *reinterpret_cast<void***>(fieldObj);
        CharFeed feed = reinterpret_cast<CharFeed>(vt[0x14 / 4]);
        for (int i = 0; i < n; ++i)
        { uint16_t wc = (uint16_t)chars[i]; feed((void*)fieldObj, i, &wc); }
        void* okThis = (void*)(skw - 0x2A8);
        if (g_fnApply) ((ApplyFn)g_fnApply)(okThis);
        if (g_fnBfc)   ((NotifyFn)g_fnBfc)(okThis, 1);
        Log("nav: %s fed (%d) + OK dispatched (no hook).", what, n);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { Log("nav: %s seq threw 0x%08X.", what, GetExceptionCode()); }
}

static void DoPasswordSeq(uint32_t skw)
{
    FeedSoftKbdField(skw, g_pw, g_pwLen, "password");
    SecureZeroMemory(g_pw, sizeof(g_pw));
}

static HWND PolWnd()
{
    FindCtx fc{ GetCurrentProcessId(), nullptr };
    EnumWindows(EnumW, (LPARAM)&fc);
    return fc.hwnd;
}

static volatile HWND g_fakeFocusHwnd = nullptr;
static volatile bool g_hideEnabled = true;
static volatile bool g_antiThrottle = true;
static volatile bool g_autoEnter = false;
static volatile int  g_charSlot = 1;
static volatile int  g_settleMs = 5000;
static volatile bool g_winEvLateActive = false;
static RECT g_polOrigRect = {};
static volatile bool g_polOrigSaved = false;

static void RememberPolRect(int x, int y, int w, int ht)
{
    if (x <= -30000 || y <= -30000 || w < 100 || ht < 100) return;
    g_polOrigRect.left = x; g_polOrigRect.top = y;
    g_polOrigRect.right = x + w; g_polOrigRect.bottom = y + ht;
    g_polOrigSaved = true;
}

struct FindAllCtx { DWORD pid; HWND arr[16]; int n; };
static BOOL CALLBACK EnumWAll(HWND h, LPARAM lp)
{
    auto* c = (FindAllCtx*)lp;
    DWORD wpid = 0; GetWindowThreadProcessId(h, &wpid);
    if (wpid != c->pid) return TRUE;
    char t[64]; GetWindowTextA(h, t, sizeof(t));
    if (strstr(t, "PlayOnline") && c->n < 16) c->arr[c->n++] = h;
    return TRUE;
}

static DWORD WINAPI EarlyStashThread(LPVOID)
{
    char p[MAX_PATH], fb[MAX_PATH];
    PidPaths(p, fb, MAX_PATH, "nohide", "txt");
    if (GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesA(fb) != INVALID_FILE_ATTRIBUTES)
        return 0;

    timeBeginPeriod(1);
    DWORD me = GetCurrentProcessId();
    HWND known[16] = {0};
    int  knownN = 0;
    const char* classes[] = { "PlayOnlineUS", "PlayOnlineMaskUS",
                              "PlayOnlineEU", "PlayOnlineJP" };
    ULONGLONG t0 = GetTickCount64();
    while (GetTickCount64() - t0 < 30000 && g_hideEnabled)
    {
        for (auto cls : classes) {
            HWND h = nullptr;
            while ((h = FindWindowExA(nullptr, h, cls, nullptr)) != nullptr) {
                DWORD wpid = 0;
                GetWindowThreadProcessId(h, &wpid);
                if (wpid != me) continue;
                bool isNew = true;
                for (int i = 0; i < knownN; ++i)
                    if (known[i] == h) { isNew = false; break; }
                if (isNew && knownN < 16) {
                    known[knownN++] = h;
                    LONG ex = GetWindowLongA(h, GWL_EXSTYLE);
                    SetWindowLongA(h, GWL_EXSTYLE, ex | WS_EX_LAYERED);
                    SetLayeredWindowAttributes(h, 0, 0, LWA_ALPHA);
                    RECT r{}; GetWindowRect(h, &r);
                    DWORD owntid = GetWindowThreadProcessId(h, nullptr);
                    Log("EarlyStash: NEW hwnd=0x%p cls=[%s] at %llums "
                        "tid=%lu vis=%d origRect=%ldx%ld+%ld+%ld -> "
                        "alpha=0 + off-screen", h, cls,
                        GetTickCount64() - t0, owntid, IsWindowVisible(h),
                        r.right - r.left, r.bottom - r.top, r.left, r.top);
                    if (IsWindowVisible(h)) g_fakeFocusHwnd = h;
                }
                RECT r2{}; GetWindowRect(h, &r2);
                if (r2.left > -30000)
                    SetWindowPos(h, HWND_BOTTOM, -32000, -32000, 0, 0,
                                 SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOZORDER);
            }
        }
        Sleep(1);
    }
    timeEndPeriod(1);
    return 0;
}

static HWND WINAPI Fake_GetForegroundWindow(void)
{ return (g_antiThrottle && g_fakeFocusHwnd) ? g_fakeFocusHwnd : GetForegroundWindow(); }
static HWND WINAPI Fake_GetActiveWindow(void)
{ return (g_antiThrottle && g_fakeFocusHwnd) ? g_fakeFocusHwnd : GetActiveWindow(); }
static HWND WINAPI Fake_GetFocus(void)
{ return (g_antiThrottle && g_fakeFocusHwnd) ? g_fakeFocusHwnd : GetFocus(); }
static BOOL WINAPI Fake_IsIconic(HWND h)
{ return (g_antiThrottle && g_fakeFocusHwnd && h == g_fakeFocusHwnd) ? FALSE : IsIconic(h); }
static BOOL WINAPI Fake_IsWindowVisible(HWND h)
{ return (g_antiThrottle && g_fakeFocusHwnd && h == g_fakeFocusHwnd) ? TRUE : IsWindowVisible(h); }

static bool OffscreenCandidate(HWND parent, DWORD style, int w, int h)
{
    if (!g_hideEnabled) return false;
    if (parent) return false;
    if (style & WS_CHILD) return false;
    if (!(style & WS_CAPTION) && !(style & WS_BORDER)) return false;
    if (w > 0 && w < 200) return false;
    if (h > 0 && h < 100) return false;
    return true;
}

static HWND WINAPI Fake_CreateWindowExA(
    DWORD dwExStyle, LPCSTR cls, LPCSTR name, DWORD style,
    int x, int y, int w, int h, HWND parent, HMENU menu,
    HINSTANCE inst, LPVOID lp)
{
    bool off = OffscreenCandidate(parent, style, w, h);
    if (off) { x = -32000; y = -32000; }
    HWND r = CreateWindowExA(dwExStyle, cls, name, style, x, y, w, h,
                             parent, menu, inst, lp);
    if (off && r)
        Log("Fake_CreateWindowExA: hwnd 0x%p forced off-screen class=[%s] name=[%s]",
            r, cls ? cls : "?", name ? name : "?");
    return r;
}

static HWND WINAPI Fake_CreateWindowExW(
    DWORD dwExStyle, LPCWSTR cls, LPCWSTR name, DWORD style,
    int x, int y, int w, int h, HWND parent, HMENU menu,
    HINSTANCE inst, LPVOID lp)
{
    bool off = OffscreenCandidate(parent, style, w, h);
    if (off) { x = -32000; y = -32000; }
    HWND r = CreateWindowExW(dwExStyle, cls, name, style, x, y, w, h,
                             parent, menu, inst, lp);
    if (off && r)
        Log("Fake_CreateWindowExW: hwnd 0x%p forced off-screen", r);
    return r;
}

static bool IsHideTarget(HWND h)
{
    if (!h) return false;
    DWORD wpid = 0;
    GetWindowThreadProcessId(h, &wpid);
    if (wpid != GetCurrentProcessId()) return false;
    LONG style = GetWindowLongA(h, GWL_STYLE);
    if (style & WS_CHILD) return false;
    if (!(style & WS_CAPTION) && !(style & WS_BORDER)) return false;
    if (GetWindow(h, GW_OWNER)) return false;
    RECT r{};
    if (!GetWindowRect(h, &r)) return false;
    int w = r.right - r.left, ht = r.bottom - r.top;
    return w >= 200 && ht >= 100;
}

static BOOL WINAPI Fake_ShowWindow(HWND h, int cmd)
{
    if (g_hideEnabled &&
        (cmd == SW_SHOW || cmd == SW_SHOWNORMAL || cmd == SW_SHOWDEFAULT) &&
        IsHideTarget(h))
    {
        SetWindowPos(h, HWND_BOTTOM, -32000, -32000, 0, 0,
                     SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOZORDER);
    }
    return ShowWindow(h, cmd);
}

static BOOL WINAPI Fake_SetWindowPos(HWND h, HWND after, int x, int y,
                                     int cx, int cy, UINT flags)
{
    if (g_hideEnabled && !(flags & SWP_NOMOVE) &&
        (x > -30000 || y > -30000) && IsHideTarget(h))
    {
        x = -32000;
        y = -32000;
    }
    return SetWindowPos(h, after, x, y, cx, cy, flags);
}

static BOOL WINAPI Fake_MoveWindow(HWND h, int x, int y, int w, int ht,
                                   BOOL repaint)
{
    if (g_hideEnabled && (x > -30000 || y > -30000) && IsHideTarget(h)) {
        x = -32000; y = -32000;
    }
    return MoveWindow(h, x, y, w, ht, repaint);
}

struct FakeFocusHook { const char* dll; const char* name; void* trampoline; };

typedef HRESULT (WINAPI *DDrawCreate_t)(GUID*, void**, IUnknown*);
typedef HRESULT (WINAPI *DDrawCreateEx_t)(GUID*, void**, REFIID, IUnknown*);

typedef HRESULT (STDMETHODCALLTYPE *SetCoopLvl_t)(void*, HWND, DWORD);
static volatile SetCoopLvl_t g_realSetCoopLvl = nullptr;
static volatile LONG g_ddrawVtblPatched = 0;
static uintptr_t* g_ddrawPatchedVt = nullptr;

static HRESULT STDMETHODCALLTYPE Fake_SetCooperativeLevel(void* self, HWND hwnd, DWORD flags)
{
    DWORD orig = flags;
    if (g_hideEnabled) {
        flags &= ~(0x00000001UL | 0x00000010UL | 0x00000040UL | 0x00000004UL);
        flags |= 0x00000008UL;
    }
    SetCoopLvl_t real = g_realSetCoopLvl;
    if (!real) return 0x80004005L;
    HRESULT hr = real(self, hwnd, flags);
    Log("Fake_SetCoopLvl: hwnd=0x%p flags=0x%08lX -> 0x%08lX hr=0x%08lX",
        hwnd, (unsigned long)orig, (unsigned long)flags, (unsigned long)hr);
    return hr;
}

static void PatchDDrawVtable(void* dd)
{
    if (!dd) return;
    __try {
        void** vtbl = *(void***)dd;
        if (!vtbl) return;
        uintptr_t* vt = (uintptr_t*)vtbl;
        uintptr_t origSlot = vt[20];
        if (origSlot == (uintptr_t)&Fake_SetCooperativeLevel) return;
        if (!g_realSetCoopLvl)
            g_realSetCoopLvl = (SetCoopLvl_t)origSlot;
        DWORD oldProt;
        if (VirtualProtect(&vt[20], sizeof(uintptr_t), PAGE_READWRITE, &oldProt)) {
            vt[20] = (uintptr_t)&Fake_SetCooperativeLevel;
            DWORD tmp;
            VirtualProtect(&vt[20], sizeof(uintptr_t), oldProt, &tmp);
            InterlockedIncrement(&g_ddrawVtblPatched);
            if (!g_ddrawPatchedVt) g_ddrawPatchedVt = vt;
            Log("PatchDDraw: vtable 0x%p slot20 patched (orig 0x%p saved)",
                vtbl, (void*)origSlot);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

static HMODULE g_ddrawMod = nullptr;
static DDrawCreate_t   g_realDDrawCreate   = nullptr;
static DDrawCreateEx_t g_realDDrawCreateEx = nullptr;

static HRESULT WINAPI Fake_DirectDrawCreate(GUID* g, void** ppDD, IUnknown* aggr)
{
    if (!g_realDDrawCreate) {
        if (!g_ddrawMod) g_ddrawMod = GetModuleHandleA("ddraw.dll");
        if (g_ddrawMod) g_realDDrawCreate = (DDrawCreate_t)
            GetProcAddress(g_ddrawMod, "DirectDrawCreate");
    }
    if (!g_realDDrawCreate) return 0x80004001L;
    HRESULT hr = g_realDDrawCreate(g, ppDD, aggr);
    if (SUCCEEDED(hr) && ppDD && *ppDD) {
        Log("Fake_DirectDrawCreate: got IDirectDraw 0x%p", *ppDD);
        PatchDDrawVtable(*ppDD);
    }
    return hr;
}

static HRESULT WINAPI Fake_DirectDrawCreateEx(GUID* g, void** ppDD, REFIID iid, IUnknown* aggr)
{
    if (!g_realDDrawCreateEx) {
        if (!g_ddrawMod) g_ddrawMod = GetModuleHandleA("ddraw.dll");
        if (g_ddrawMod) g_realDDrawCreateEx = (DDrawCreateEx_t)
            GetProcAddress(g_ddrawMod, "DirectDrawCreateEx");
    }
    if (!g_realDDrawCreateEx) return 0x80004001L;
    HRESULT hr = g_realDDrawCreateEx(g, ppDD, iid, aggr);
    if (SUCCEEDED(hr) && ppDD && *ppDD) {
        Log("Fake_DirectDrawCreateEx: got IDirectDraw7 0x%p", *ppDD);
        PatchDDrawVtable(*ppDD);
    }
    return hr;
}

typedef UINT_PTR FL_SOCKET;
typedef int (__stdcall *recv_t)(FL_SOCKET, char*, int, int);
typedef int (__stdcall *send_t)(FL_SOCKET, const char*, int, int);
static volatile bool g_fastLogin = false;
static volatile LONG g_fastLoginDone = 0;
static recv_t g_realRecv = nullptr;
static send_t g_realSend = nullptr;
static CRITICAL_SECTION g_flCs;
static struct { FL_SOCKET s; int off; } g_flSock[32];
static int  g_flSockN = 0;
static char g_flResp[400];
static int  g_flRespLen = 0;

static void BuildFastResp()
{
    static const char* body =
        "<pml><body><timer href=\"gameto:1\" enable=\"1\" delay=\"0\"></body></pml>";
    g_flRespLen = sprintf_s(g_flResp, sizeof(g_flResp),
        "HTTP/1.1 200 OK\r\nContent-Type: text/x-playonline-pml;charset=UTF-8\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
        (int)strlen(body), body);
}

static int FlIndex(FL_SOCKET s)
{
    for (int i = 0; i < g_flSockN; ++i) if (g_flSock[i].s == s) return i;
    return -1;
}

static int __stdcall Fake_send(FL_SOCKET s, const char* buf, int len, int flags)
{
    if (!g_realSend) { HMODULE w = GetModuleHandleA("ws2_32.dll");
                       if (w) g_realSend = (send_t)GetProcAddress(w, "send"); }
    int r = g_realSend ? g_realSend(s, buf, len, flags) : -1;
    if (g_fastLogin && buf && len >= 19) {
        int scan = len < 1024 ? len : 1024;
        for (int i = 0; i + 19 <= scan; ++i) {
            if (memcmp(buf + i, "/pml/main/index.pml", 19) == 0) {
                EnterCriticalSection(&g_flCs);
                if (FlIndex(s) < 0 && g_flSockN < 32) {
                    g_flSock[g_flSockN].s = s; g_flSock[g_flSockN].off = 0; ++g_flSockN;
                }
                LeaveCriticalSection(&g_flCs);
                Log("fastlogin: tagged socket for index.pml fetch (in-proc gameto:1)");
                break;
            }
        }
    }
    return r;
}

static int __stdcall Fake_recv(FL_SOCKET s, char* buf, int len, int flags)
{
    if (g_fastLogin && buf && len > 0) {
        EnterCriticalSection(&g_flCs);
        int i = FlIndex(s);
        if (i >= 0) {
            int off = g_flSock[i].off, remain = g_flRespLen - off, n;
            if (remain <= 0) { g_flSock[i] = g_flSock[--g_flSockN]; n = 0; }
            else { n = remain < len ? remain : len; memcpy(buf, g_flResp + off, n); g_flSock[i].off = off + n; }
            LeaveCriticalSection(&g_flCs);
            if (n == 0) {
                Log("fastlogin: gameto:1 delivered, EOF");
                if (g_inGameFired) {
                    Log("fastlogin: IN_GAME already fired — suppressing DONE write");
                }
                else if (!InterlockedExchange(&g_fastLoginDone, 1))
                    WriteStatus("DONE", "fastlogin complete");
            }
            return n;
        }
        LeaveCriticalSection(&g_flCs);
    }
    if (!g_realRecv) { HMODULE w = GetModuleHandleA("ws2_32.dll");
                       if (w) g_realRecv = (recv_t)GetProcAddress(w, "recv"); }
    return g_realRecv ? g_realRecv(s, buf, len, flags) : -1;
}

struct OrdHook { const char* dll; WORD ord; void* trampoline; };
static const OrdHook kOrdHooks[] = {
    { "ws2_32.dll", 16, (void*)&Fake_recv },
    { "ws2_32.dll", 19, (void*)&Fake_send },
};

static LSTATUS WINAPI Hook_RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
static LSTATUS WINAPI Hook_RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
static LSTATUS WINAPI Hook_RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static LSTATUS WINAPI Hook_RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static LSTATUS WINAPI Hook_RegGetValueW(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
static LSTATUS WINAPI Hook_RegGetValueA(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);
static HANDLE  WINAPI Hook_OpenFileMappingW(DWORD, BOOL, LPCWSTR);
static LPVOID  WINAPI Hook_MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
static LONG    WINAPI Hook_ChangeDisplaySettingsW(LPDEVMODEW, DWORD);
static LONG    WINAPI Hook_ChangeDisplaySettingsExW(LPCWSTR, LPDEVMODEW, HWND, DWORD, LPVOID);

static const FakeFocusHook kFakeFocusHooks[] = {
    { "user32.dll",   "GetForegroundWindow", (void*)&Fake_GetForegroundWindow },
    { "user32.dll",   "GetActiveWindow",     (void*)&Fake_GetActiveWindow     },
    { "user32.dll",   "GetFocus",            (void*)&Fake_GetFocus            },
    { "user32.dll",   "IsIconic",            (void*)&Fake_IsIconic            },
    { "user32.dll",   "IsWindowVisible",     (void*)&Fake_IsWindowVisible     },
    { "user32.dll",   "CreateWindowExA",     (void*)&Fake_CreateWindowExA     },
    { "user32.dll",   "CreateWindowExW",     (void*)&Fake_CreateWindowExW     },
    { "user32.dll",   "ShowWindow",          (void*)&Fake_ShowWindow          },
    { "user32.dll",   "SetWindowPos",        (void*)&Fake_SetWindowPos        },
    { "user32.dll",   "MoveWindow",          (void*)&Fake_MoveWindow          },
    { "ddraw.dll",    "DirectDrawCreate",    (void*)&Fake_DirectDrawCreate    },
    { "ddraw.dll",    "DirectDrawCreateEx",  (void*)&Fake_DirectDrawCreateEx  },
    { "advapi32.dll", "RegOpenKeyExW",            (void*)&Hook_RegOpenKeyExW            },
    { "advapi32.dll", "RegOpenKeyExA",            (void*)&Hook_RegOpenKeyExA            },
    { "advapi32.dll", "RegQueryValueExW",         (void*)&Hook_RegQueryValueExW         },
    { "advapi32.dll", "RegQueryValueExA",         (void*)&Hook_RegQueryValueExA         },
    { "advapi32.dll", "RegGetValueW",             (void*)&Hook_RegGetValueW             },
    { "advapi32.dll", "RegGetValueA",             (void*)&Hook_RegGetValueA             },
    { "kernel32.dll", "OpenFileMappingW",         (void*)&Hook_OpenFileMappingW         },
    { "kernel32.dll", "MapViewOfFile",            (void*)&Hook_MapViewOfFile            },
    { "user32.dll",   "ChangeDisplaySettingsW",   (void*)&Hook_ChangeDisplaySettingsW   },
    { "user32.dll",   "ChangeDisplaySettingsExW", (void*)&Hook_ChangeDisplaySettingsExW },
};

struct IatRestore { uintptr_t* slot; uintptr_t orig; };
static IatRestore g_iatRestores[512] = {};
static volatile LONG g_iatRestoreN = 0;

static int PatchOneIatEntry(HMODULE mod, const char* dllName,
                            const char* funcName, void* newFn)
{
    __try {
        auto* base = (uint8_t*)mod;
        auto* dos  = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        auto* nt   = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        auto& dir = nt->OptionalHeader
                      .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.VirtualAddress || !dir.Size) return 0;

        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
        int patched = 0;
        for (; desc->Name; ++desc) {
            const char* dll = (const char*)(base + desc->Name);
            if (_stricmp(dll, dllName) != 0) continue;
            auto* names = desc->OriginalFirstThunk
                ? (IMAGE_THUNK_DATA*)(base + desc->OriginalFirstThunk)
                : (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
            auto* iat   = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
            for (int i = 0; names[i].u1.AddressOfData; ++i) {
                if (names[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                auto* ibn = (IMAGE_IMPORT_BY_NAME*)
                            (base + names[i].u1.AddressOfData);
                if (strcmp((const char*)ibn->Name, funcName) != 0) continue;
                uintptr_t* slot = (uintptr_t*)&iat[i].u1.Function;
                if (*slot == (uintptr_t)newFn) continue;
                DWORD oldProt;
                if (VirtualProtect(slot, sizeof(void*),
                                   PAGE_READWRITE, &oldProt))
                {
                    LONG idx = InterlockedIncrement(&g_iatRestoreN) - 1;
                    if (idx < 512) {
                        g_iatRestores[idx].slot = slot;
                        g_iatRestores[idx].orig = *slot;
                    }
                    *slot = (uintptr_t)newFn;
                    DWORD tmp;
                    VirtualProtect(slot, sizeof(void*), oldProt, &tmp);
                    ++patched;
                }
            }
        }
        return patched;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static int PatchOneIatEntryByOrdinal(HMODULE mod, const char* dllName,
                                     WORD ord, void* newFn)
{
    __try {
        auto* base = (uint8_t*)mod;
        auto* dos  = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        auto* nt   = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        auto& dir = nt->OptionalHeader
                      .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.VirtualAddress || !dir.Size) return 0;

        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
        int patched = 0;
        for (; desc->Name; ++desc) {
            const char* dll = (const char*)(base + desc->Name);
            if (_stricmp(dll, dllName) != 0) continue;
            auto* names = desc->OriginalFirstThunk
                ? (IMAGE_THUNK_DATA*)(base + desc->OriginalFirstThunk)
                : (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
            auto* iat   = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
            for (int i = 0; names[i].u1.AddressOfData; ++i) {
                if (!(names[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)) continue;
                if (IMAGE_ORDINAL(names[i].u1.Ordinal) != ord) continue;
                uintptr_t* slot = (uintptr_t*)&iat[i].u1.Function;
                if (*slot == (uintptr_t)newFn) continue;
                DWORD oldProt;
                if (VirtualProtect(slot, sizeof(void*),
                                   PAGE_READWRITE, &oldProt))
                {
                    LONG idx = InterlockedIncrement(&g_iatRestoreN) - 1;
                    if (idx < 512) {
                        g_iatRestores[idx].slot = slot;
                        g_iatRestores[idx].orig = *slot;
                    }
                    *slot = (uintptr_t)newFn;
                    DWORD tmp;
                    VirtualProtect(slot, sizeof(void*), oldProt, &tmp);
                    ++patched;
                }
            }
        }
        return patched;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static int PatchAllFakeFocusInModule(HMODULE mod)
{
    int n = 0;
    for (auto& h : kFakeFocusHooks)
        n += PatchOneIatEntry(mod, h.dll, h.name, h.trampoline);
    if (g_fastLogin)
        for (auto& h : kOrdHooks)
            n += PatchOneIatEntryByOrdinal(mod, h.dll, h.ord, h.trampoline);
    return n;
}

static int InstallFakeFocusAllModules(HMODULE self)
{
    HMODULE mods[256];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods,
                            sizeof(mods), &needed))
        return 0;
    int count = (int)(needed / sizeof(HMODULE));
    int total = 0;
    for (int i = 0; i < count; ++i) {
        if (mods[i] == self) continue;
        char base[64] = {0};
        GetModuleBaseNameA(GetCurrentProcess(), mods[i], base, sizeof(base));
        if (_stricmp(base, "FFXiMain.dll") == 0) continue;
        total += PatchAllFakeFocusInModule(mods[i]);
    }
    return total;
}

static HMODULE GetSelfModule()
{
    HMODULE self = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&GetSelfModule), &self);
    return self;
}

static HHOOK g_cbtHooks[200] = {0};
static int   g_cbtHookN     = 0;

static volatile LONG g_cbtFires = 0;
static DWORD g_hookedTids[128] = {0};
static int   g_hookedTidsN     = 0;

static bool TidAlreadyHooked(DWORD tid)
{
    for (int i = 0; i < g_hookedTidsN; ++i)
        if (g_hookedTids[i] == tid) return true;
    return false;
}

static LRESULT CALLBACK CbtHookProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HCBT_CREATEWND) {
        InterlockedIncrement(&g_cbtFires);
        auto* cs = (CBT_CREATEWNDA*)lParam;
        if (g_hideEnabled && cs && cs->lpcs) {
            DWORD style = cs->lpcs->style;
            int  w = cs->lpcs->cx, h = cs->lpcs->cy;
            bool isChild = (style & WS_CHILD) != 0;
            bool hasParent = cs->lpcs->hwndParent != nullptr;
            if (!isChild && !hasParent) {
                RememberPolRect(cs->lpcs->x, cs->lpcs->y, w, h);
                cs->lpcs->x = -32000;
                cs->lpcs->y = -32000;
                Log("CBT-CREATE: top-level hwnd-pre=0x%p style=0x%08lX "
                    "size=%dx%d tid=%lu -> rewrote xy to off-screen",
                    (HWND)wParam, (unsigned long)style, w, h,
                    GetCurrentThreadId());
            }
        }
    }
    else if (code == HCBT_MOVESIZE && g_hideEnabled) {
        HWND h = (HWND)wParam;
        RECT* nr = (RECT*)lParam;
        if (nr && (nr->left > -30000 || nr->top > -30000)) {
            LONG style = GetWindowLongA(h, GWL_STYLE);
            if (!(style & WS_CHILD) && !GetWindow(h, GW_OWNER)) {
                LONG w = nr->right - nr->left, ht = nr->bottom - nr->top;
                RememberPolRect(nr->left, nr->top, w, ht);
                Log("CBT-MOVESIZE: hwnd=0x%p was moving to (%ld,%ld) %ldx%ld "
                    "-> rewrote off-screen", h, nr->left, nr->top, w, ht);
                nr->right  = -32000 + w;
                nr->bottom = -32000 + ht;
                nr->left   = -32000;
                nr->top    = -32000;
            }
        }
    }
    else if (code == HCBT_ACTIVATE && g_hideEnabled) {
        HWND h = (HWND)wParam;
        char cls[64] = {0}; GetClassNameA(h, cls, sizeof(cls));
        Log("CBT-ACTIVATE: hwnd=0x%p class=[%s] tid=%lu", h, cls,
            GetCurrentThreadId());
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static void InstallCbtHooks(HMODULE self)
{
    if (!g_hideEnabled) return;
    DWORD me = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{ sizeof(te) };
    int installed = 0;
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != me) continue;
        if (g_cbtHookN >= 200) break;
        HHOOK h = SetWindowsHookExA(WH_CBT, CbtHookProc, self, te.th32ThreadID);
        if (h) {
            g_cbtHooks[g_cbtHookN++] = h;
            bool first = !TidAlreadyHooked(te.th32ThreadID);
            if (first && g_hookedTidsN < 128)
                g_hookedTids[g_hookedTidsN++] = te.th32ThreadID;
            ++installed;
            if (first) Log("CBT-INSTALL: tid=%lu hooked (1st time)",
                           te.th32ThreadID);
        }
    }
    CloseHandle(snap);
    if (installed)
        Log("CBT-INSTALL: pass done, +%d hooks (total %d, %d unique tids)",
            installed, g_cbtHookN, g_hookedTidsN);
}

static DWORD WINAPI CbtReinstallThread(LPVOID lp)
{
    HMODULE self = (HMODULE)lp;
    for (int i = 0; i < 300 && g_hideEnabled; ++i) {
        Sleep(50);
        InstallCbtHooks(self);
    }
    Log("CBT-INSTALL: final hook count=%d, unique tids=%d, fires=%ld",
        g_cbtHookN, g_hookedTidsN, g_cbtFires);
    return 0;
}

static volatile LONG g_winEvFires = 0;

static void CALLBACK WinEvCreateProc(HWINEVENTHOOK, DWORD ev, HWND h,
                                     LONG idObject, LONG, DWORD eventTid, DWORD)
{
    if (!h || idObject != OBJID_WINDOW) return;
    InterlockedIncrement(&g_winEvFires);
    if (!g_hideEnabled && !g_winEvLateActive) return;
    LONG style = GetWindowLongA(h, GWL_STYLE);
    if (style & WS_CHILD) return;
    if (GetWindow(h, GW_OWNER)) return;
    char cls[64] = {0}; GetClassNameA(h, cls, sizeof(cls));
    if (!g_hideEnabled && g_winEvLateActive) {
        if (strcmp(cls, "#32770") != 0 &&
            _strnicmp(cls, "PlayOnline", 10) != 0) return;
    }
    char ttl[64] = {0}; GetWindowTextA(h, ttl, sizeof(ttl));
    RECT r{}; GetWindowRect(h, &r);
    SetWindowPos(h, HWND_BOTTOM, -32000, -32000, 0, 0,
                 SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOZORDER);
    Log("WINEV: ev=0x%04X hwnd=0x%p tid=%lu class=[%s] title=[%s] "
        "style=0x%08lX rect=%ldx%ld+%ld+%ld -> stashed", ev, h, eventTid,
        cls, ttl, (unsigned long)style,
        r.right - r.left, r.bottom - r.top, r.left, r.top);
}

struct AttachEnumCtx { DWORD pid; int n; };
static BOOL CALLBACK AttachEnumCb(HWND h, LPARAM lp)
{
    auto* c = (AttachEnumCtx*)lp;
    DWORD wpid = 0; GetWindowThreadProcessId(h, &wpid);
    if (wpid != c->pid) return TRUE;
    char cls[64] = {0}; GetClassNameA(h, cls, sizeof(cls));
    char ttl[64] = {0}; GetWindowTextA(h, ttl, sizeof(ttl));
    LONG style = GetWindowLongA(h, GWL_STYLE);
    RECT r{}; GetWindowRect(h, &r);
    Log("ATTACH-ENUM: hwnd=0x%p class=[%s] title=[%s] "
        "style=0x%08lX vis=%d rect=%ldx%ld+%ld+%ld",
        h, cls, ttl, (unsigned long)style, IsWindowVisible(h),
        r.right - r.left, r.bottom - r.top, r.left, r.top);
    ++c->n;
    return TRUE;
}

static DWORD WINAPI AttachEnumThread(LPVOID)
{
    AttachEnumCtx ctx{ GetCurrentProcessId(), 0 };
    EnumWindows(AttachEnumCb, (LPARAM)&ctx);
    Log("ATTACH-ENUM: %d top-level windows in pid at +0ms", ctx.n);
    return 0;
}

static volatile HWINEVENTHOOK g_winEvHook = nullptr;

static DWORD WINAPI WinEvPumpThread(LPVOID)
{
    HMODULE self = GetSelfModule();
    g_winEvHook = SetWinEventHook(
        EVENT_OBJECT_CREATE, EVENT_OBJECT_LOCATIONCHANGE, self,
        WinEvCreateProc, GetCurrentProcessId(), 0,
        WINEVENT_INCONTEXT);
    if (!g_winEvHook) {
        Log("WINEV: SetWinEventHook(INCONTEXT) FAILED err=%lu", GetLastError());
        return 0;
    }
    Log("WINEV: INCONTEXT hook installed (pid scope=%lu)", GetCurrentProcessId());
    while (g_winEvHook) Sleep(1000);
    return 0;
}

static DWORD WINAPI WinEventDelayedTeardown(LPVOID)
{
    g_winEvLateActive = true;
    Sleep(60000);
    g_winEvLateActive = false;
    if (g_winEvHook) {
        UnhookWinEvent(g_winEvHook);
        g_winEvHook = nullptr;
        Log("WINEV: hook unhooked (60s post-DONE delayed teardown)");
    }
    return 0;
}

static void TeardownHooks()
{
    int cbtN = 0;
    for (int i = 0; i < g_cbtHookN; ++i) {
        if (g_cbtHooks[i]) {
            UnhookWindowsHookEx(g_cbtHooks[i]);
            g_cbtHooks[i] = nullptr;
            ++cbtN;
        }
    }
    g_cbtHookN = 0;
    g_hookedTidsN = 0;

    CloseHandle(CreateThread(nullptr, 0, WinEventDelayedTeardown,
                             nullptr, 0, nullptr));

    int ddN = 0;
    if (g_ddrawPatchedVt && g_realSetCoopLvl) {
        __try {
            DWORD oldProt;
            if (VirtualProtect(&g_ddrawPatchedVt[20], sizeof(uintptr_t),
                               PAGE_READWRITE, &oldProt)) {
                g_ddrawPatchedVt[20] = (uintptr_t)g_realSetCoopLvl;
                DWORD tmp;
                VirtualProtect(&g_ddrawPatchedVt[20], sizeof(uintptr_t),
                               oldProt, &tmp);
                ddN = 1;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        g_ddrawPatchedVt = nullptr;
    }

    Log("TeardownHooks: unhooked %d CBT + WinEvent, restored %d DDraw vtbl "
        "(focus IAT kept active for POL-viewer anti-throttle)", cbtN, ddN);
}

struct GameWndCtx { DWORD pid; HWND hwnd; };
static BOOL CALLBACK EnumGameWnd(HWND h, LPARAM lp)
{
    auto* c = (GameWndCtx*)lp;
    DWORD wpid = 0; GetWindowThreadProcessId(h, &wpid);
    if (wpid != c->pid) return TRUE;
    char cls[64] = {0}; GetClassNameA(h, cls, sizeof(cls));
    if (strcmp(cls, "FFXiClass") == 0) { c->hwnd = h; return FALSE; }
    return TRUE;
}
static HWND FindGameWindow()
{
    GameWndCtx c{ GetCurrentProcessId(), nullptr };
    EnumWindows(EnumGameWnd, (LPARAM)&c);
    return c.hwnd;
}

static const GUID kIID_IDirectInput8A =
    { 0xBF798030, 0x483A, 0x4DA2, { 0xAA,0x99,0x5D,0x64,0xED,0x36,0x97,0x00 } };
static const GUID kIID_IDirectInput8W =
    { 0xBF798031, 0x483A, 0x4DA2, { 0xAA,0x99,0x5D,0x64,0xED,0x36,0x97,0x00 } };
static const GUID kGUID_SysKeyboard =
    { 0x6F1D2B61, 0xD5A0, 0x11CF, { 0xBF,0xC7,0x44,0x45,0x53,0x54,0x00,0x00 } };

typedef HRESULT (WINAPI *DI8Create_t)(HINSTANCE, DWORD, const GUID&, void**, void*);
typedef HRESULT (STDMETHODCALLTYPE *DI_CreateDevice_t)(void*, const GUID&, void**, void*);
typedef HRESULT (STDMETHODCALLTYPE *DI_GetDeviceState_t)(void*, DWORD, void*);
typedef ULONG   (STDMETHODCALLTYPE *DI_Release_t)(void*);

typedef LSTATUS (WINAPI *RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *RegOpenKeyExA_t)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *RegQueryValueExA_t)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *RegGetValueW_t)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
typedef LSTATUS (WINAPI *RegGetValueA_t)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);
typedef HANDLE  (WINAPI *OpenFileMappingW_t)(DWORD, BOOL, LPCWSTR);
typedef LPVOID  (WINAPI *MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef LONG    (WINAPI *ChangeDisplaySettingsW_t)(LPDEVMODEW, DWORD);
typedef LONG    (WINAPI *ChangeDisplaySettingsExW_t)(LPCWSTR, LPDEVMODEW, HWND, DWORD, LPVOID);

static volatile RegOpenKeyExW_t           g_chainRegOpenW       = nullptr;
static volatile RegOpenKeyExA_t           g_chainRegOpenA       = nullptr;
static volatile RegQueryValueExW_t        g_chainRegQueryW      = nullptr;
static volatile RegQueryValueExA_t        g_chainRegQueryA      = nullptr;
static volatile RegGetValueW_t            g_chainRegGetValueW   = nullptr;
static volatile RegGetValueA_t            g_chainRegGetValueA   = nullptr;
static volatile OpenFileMappingW_t        g_chainOpenFileMapW   = nullptr;
static volatile MapViewOfFile_t           g_chainMapViewOfFile  = nullptr;
static volatile ChangeDisplaySettingsW_t  g_chainChangeDispW    = nullptr;
static volatile ChangeDisplaySettingsExW_t g_chainChangeDispExW = nullptr;

static CRITICAL_SECTION g_winMapCs;
static volatile LONG g_winMapCsInit = 0;
static HANDLE g_winMapHandles[16] = {0};
static int g_winMapN = 0;

static void EnsureWinMapCs() {
    if (InterlockedExchange(&g_winMapCsInit, 1) == 0)
        InitializeCriticalSection(&g_winMapCs);
}

static void TrackWinMap(HANDLE h) {
    if (!h) return;
    EnterCriticalSection(&g_winMapCs);
    bool found = false;
    for (int i = 0; i < g_winMapN && !found; ++i) if (g_winMapHandles[i] == h) found = true;
    if (!found && g_winMapN < 16) g_winMapHandles[g_winMapN++] = h;
    LeaveCriticalSection(&g_winMapCs);
}

static bool IsTrackedWinMap(HANDLE h) {
    if (!h) return false;
    EnterCriticalSection(&g_winMapCs);
    bool found = false;
    for (int i = 0; i < g_winMapN && !found; ++i) if (g_winMapHandles[i] == h) found = true;
    LeaveCriticalSection(&g_winMapCs);
    return found;
}

static CRITICAL_SECTION g_ffxiKeyCs;
static volatile LONG g_ffxiKeyCsInit = 0;
static HKEY g_ffxiKeys[128] = {0};
static int  g_ffxiKeyN = 0;
static volatile LONG g_configReadFired = 0;

static void EnsureFFXiKeyCs() {
    if (InterlockedExchange(&g_ffxiKeyCsInit, 1) == 0)
        InitializeCriticalSection(&g_ffxiKeyCs);
}

static bool IsFFXiSubA(const char* s) {
    return s && (strstr(s, "PlayOnline") || strstr(s, "FinalFantasy")
              || strstr(s, "SquareEnix") || strstr(s, "Square"));
}
static bool IsFFXiSubW(const wchar_t* s) {
    return s && (wcsstr(s, L"PlayOnline") || wcsstr(s, L"FinalFantasy")
              || wcsstr(s, L"SquareEnix") || wcsstr(s, L"Square"));
}

static void TrackFFXiKey(HKEY h) {
    if (!h) return;
    EnterCriticalSection(&g_ffxiKeyCs);
    for (int i = 0; i < g_ffxiKeyN; ++i) if (g_ffxiKeys[i] == h) { LeaveCriticalSection(&g_ffxiKeyCs); return; }
    if (g_ffxiKeyN < 128) g_ffxiKeys[g_ffxiKeyN++] = h;
    LeaveCriticalSection(&g_ffxiKeyCs);
}

static bool IsTrackedFFXiKey(HKEY h) {
    if (!h || (uintptr_t)h < 0x1000 || h == HKEY_LOCAL_MACHINE || h == HKEY_CURRENT_USER
        || h == HKEY_CLASSES_ROOT || h == HKEY_USERS) return false;
    EnterCriticalSection(&g_ffxiKeyCs);
    bool found = false;
    for (int i = 0; i < g_ffxiKeyN && !found; ++i) if (g_ffxiKeys[i] == h) found = true;
    LeaveCriticalSection(&g_ffxiKeyCs);
    return found;
}

// Old IAT-level diagnostic hook: just LOG when an FFXi-pathed read is seen.
// Does NOT write CONFIG_READ status — that's reserved for the kernel-level
// ntdll detour which detects the actual FinalFantasyXI key reads via
// NtCreateKey-tracked handles. Firing CONFIG_READ from this path was wrong:
// POL viewer reads `PlayOnlineUS\Interface\1000` (its own build string) very
// early in boot, which would resolve the launch barrier long before the
// dangerous FFXi-side bg-res read happens.
static void FireConfigReadOnce(const char* origin, const char* valueName) {
    if (InterlockedExchange(&g_configReadFired, 1) == 0) {
        Log("FFXi-PATHED-READ (diagnostic only, NOT firing CONFIG_READ): origin=%s value='%s'",
            origin, valueName ? valueName : "?");
    }
}

static void FormatRegValue(char* out, size_t outSz, DWORD type, const BYTE* data, DWORD sz, LSTATUS r) {
    out[0] = 0;
    if (r != ERROR_SUCCESS || !data || sz == 0) return;
    if ((type == REG_DWORD || type == REG_DWORD_BIG_ENDIAN) && sz >= 4) {
        DWORD v = *(const DWORD*)data;
        sprintf_s(out, outSz, "dword=%u (0x%X)", v, v);
    } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
        DWORD n = sz < (DWORD)(outSz - 1) ? sz : (DWORD)(outSz - 1);
        memcpy(out, data, n);
        out[n] = 0;
    } else {
        DWORD n = sz < 16 ? sz : 16;
        size_t p = 0;
        for (DWORD i = 0; i < n && p + 4 < outSz; ++i) {
            sprintf_s(out + p, outSz - p, "%02X ", data[i]);
            p += 3;
        }
        if (sz > 16 && p + 4 < outSz) strcat_s(out, outSz, "...");
    }
}

static LSTATUS WINAPI Hook_RegOpenKeyExW(HKEY hKey, LPCWSTR subKey, DWORD opt, REGSAM sam, PHKEY out) {
    RegOpenKeyExW_t real = g_chainRegOpenW;
    LSTATUS r = real ? real(hKey, subKey, opt, sam, out) : ERROR_INVALID_FUNCTION;
    if (r == ERROR_SUCCESS && out && *out) {
        bool track = (subKey && IsFFXiSubW(subKey)) || IsTrackedFFXiKey(hKey);
        if (track) {
            TrackFFXiKey(*out);
            char buf[256] = "<null>";
            if (subKey) WideCharToMultiByte(CP_UTF8, 0, subKey, -1, buf, sizeof(buf)-1, NULL, NULL);
            Log("REG-OPEN-W: '%s' parent=0x%p new=0x%p caller=0x%p sam=0x%X",
                buf, (void*)hKey, (void*)*out, _ReturnAddress(), (unsigned)sam);
        }
    }
    return r;
}

static LSTATUS WINAPI Hook_RegOpenKeyExA(HKEY hKey, LPCSTR subKey, DWORD opt, REGSAM sam, PHKEY out) {
    RegOpenKeyExA_t real = g_chainRegOpenA;
    LSTATUS r = real ? real(hKey, subKey, opt, sam, out) : ERROR_INVALID_FUNCTION;
    if (r == ERROR_SUCCESS && out && *out) {
        bool track = (subKey && IsFFXiSubA(subKey)) || IsTrackedFFXiKey(hKey);
        if (track) {
            TrackFFXiKey(*out);
            Log("REG-OPEN-A: '%s' parent=0x%p new=0x%p caller=0x%p sam=0x%X",
                subKey ? subKey : "<null>", (void*)hKey, (void*)*out, _ReturnAddress(), (unsigned)sam);
        }
    }
    return r;
}

static LSTATUS WINAPI Hook_RegQueryValueExW(HKEY h, LPCWSTR name, LPDWORD res, LPDWORD type, LPBYTE data, LPDWORD cb) {
    RegQueryValueExW_t real = g_chainRegQueryW;
    LSTATUS r = real ? real(h, name, res, type, data, cb) : ERROR_INVALID_FUNCTION;
    if (IsTrackedFFXiKey(h)) {
        char nm[128] = "<null>";
        if (name) WideCharToMultiByte(CP_UTF8, 0, name, -1, nm, sizeof(nm)-1, NULL, NULL);
        DWORD ty = type ? *type : 0;
        DWORD sz = cb ? *cb : 0;
        char val[160];
        FormatRegValue(val, sizeof(val), ty, data, sz, r);
        Log("REG-QUERY-W: key=0x%p name='%s' status=%ld type=%u size=%u val=[%s] caller=0x%p",
            (void*)h, nm, r, ty, sz, val, _ReturnAddress());
        if (r == ERROR_SUCCESS) FireConfigReadOnce("RegQueryValueExW", nm);
    }
    return r;
}

static LSTATUS WINAPI Hook_RegQueryValueExA(HKEY h, LPCSTR name, LPDWORD res, LPDWORD type, LPBYTE data, LPDWORD cb) {
    RegQueryValueExA_t real = g_chainRegQueryA;
    LSTATUS r = real ? real(h, name, res, type, data, cb) : ERROR_INVALID_FUNCTION;
    if (IsTrackedFFXiKey(h)) {
        DWORD ty = type ? *type : 0;
        DWORD sz = cb ? *cb : 0;
        char val[160];
        FormatRegValue(val, sizeof(val), ty, data, sz, r);
        Log("REG-QUERY-A: key=0x%p name='%s' status=%ld type=%u size=%u val=[%s] caller=0x%p",
            (void*)h, name ? name : "<null>", r, ty, sz, val, _ReturnAddress());
        if (r == ERROR_SUCCESS) FireConfigReadOnce("RegQueryValueExA", name);
    }
    return r;
}

static LSTATUS WINAPI Hook_RegGetValueW(HKEY hkey, LPCWSTR subKey, LPCWSTR value,
                                         DWORD flags, LPDWORD type, PVOID data, LPDWORD cb) {
    RegGetValueW_t real = g_chainRegGetValueW;
    LSTATUS r = real ? real(hkey, subKey, value, flags, type, data, cb) : ERROR_INVALID_FUNCTION;
    bool isFFXi = (subKey && IsFFXiSubW(subKey)) || IsTrackedFFXiKey(hkey);
    if (isFFXi) {
        char sk[256] = "<null>", vn[128] = "<null>";
        if (subKey) WideCharToMultiByte(CP_UTF8, 0, subKey, -1, sk, sizeof(sk)-1, NULL, NULL);
        if (value)  WideCharToMultiByte(CP_UTF8, 0, value,  -1, vn, sizeof(vn)-1, NULL, NULL);
        DWORD ty = type ? *type : 0;
        DWORD sz = cb ? *cb : 0;
        char val[160];
        FormatRegValue(val, sizeof(val), ty, (BYTE*)data, sz, r);
        Log("REG-GET-W: subKey='%s' name='%s' status=%ld type=%u size=%u val=[%s] caller=0x%p",
            sk, vn, r, ty, sz, val, _ReturnAddress());
        if (r == ERROR_SUCCESS) FireConfigReadOnce("RegGetValueW", vn);
    }
    return r;
}

static LSTATUS WINAPI Hook_RegGetValueA(HKEY hkey, LPCSTR subKey, LPCSTR value,
                                         DWORD flags, LPDWORD type, PVOID data, LPDWORD cb) {
    RegGetValueA_t real = g_chainRegGetValueA;
    LSTATUS r = real ? real(hkey, subKey, value, flags, type, data, cb) : ERROR_INVALID_FUNCTION;
    bool isFFXi = (subKey && IsFFXiSubA(subKey)) || IsTrackedFFXiKey(hkey);
    if (isFFXi) {
        DWORD ty = type ? *type : 0;
        DWORD sz = cb ? *cb : 0;
        char val[160];
        FormatRegValue(val, sizeof(val), ty, (BYTE*)data, sz, r);
        Log("REG-GET-A: subKey='%s' name='%s' status=%ld type=%u size=%u val=[%s] caller=0x%p",
            subKey ? subKey : "<null>", value ? value : "<null>",
            r, ty, sz, val, _ReturnAddress());
        if (r == ERROR_SUCCESS) FireConfigReadOnce("RegGetValueA", value);
    }
    return r;
}

static HANDLE WINAPI Hook_OpenFileMappingW(DWORD access, BOOL inherit, LPCWSTR name) {
    OpenFileMappingW_t real = g_chainOpenFileMapW;
    HANDLE h = real ? real(access, inherit, name) : nullptr;
    if (name && wcsstr(name, L"Windower")) {
        char buf[256] = "<null>";
        WideCharToMultiByte(CP_UTF8, 0, name, -1, buf, sizeof(buf)-1, NULL, NULL);
        Log("OFM-W: name='%s' access=0x%X result=0x%p lastErr=%lu caller=0x%p",
            buf, (unsigned)access, h, h ? 0 : GetLastError(), _ReturnAddress());
        if (h) TrackWinMap(h);
    }
    return h;
}

static LPVOID WINAPI Hook_MapViewOfFile(HANDLE h, DWORD access, DWORD offH, DWORD offL, SIZE_T n) {
    MapViewOfFile_t real = g_chainMapViewOfFile;
    LPVOID p = real ? real(h, access, offH, offL, n) : nullptr;
    if (IsTrackedWinMap(h) && p) {
        SIZE_T dumpLen = (n > 0 && n < 256) ? n : 256;
        __try {
            char hexBuf[800] = {0};
            char asciiBuf[300] = {0};
            int p1 = 0, p2 = 0;
            const BYTE* bytes = (const BYTE*)p;
            for (SIZE_T i = 0; i < dumpLen; ++i) {
                if (p1 + 4 < (int)sizeof(hexBuf))
                    p1 += sprintf_s(hexBuf + p1, sizeof(hexBuf) - p1, "%02X ", bytes[i]);
                if (p2 + 2 < (int)sizeof(asciiBuf))
                    asciiBuf[p2++] = (bytes[i] >= 0x20 && bytes[i] < 0x7F) ? bytes[i] : '.';
            }
            asciiBuf[p2] = 0;
            Log("MVF: handle=0x%p map=0x%p reqSize=%zu", h, p, n);
            Log("MVF: first%zu hex=[%s]", dumpLen, hexBuf);
            Log("MVF: first%zu ascii=[%s]", dumpLen, asciiBuf);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("MVF: handle=0x%p map=0x%p (read fault, no dump)", h, p);
        }
    }
    return p;
}

static LONG WINAPI Hook_ChangeDisplaySettingsW(LPDEVMODEW devmode, DWORD flags) {
    ChangeDisplaySettingsW_t real = g_chainChangeDispW;
    if (devmode) {
        Log("CDS-W: w=%lu h=%lu bpp=%lu freq=%lu fields=0x%X flags=0x%X caller=0x%p",
            devmode->dmPelsWidth, devmode->dmPelsHeight,
            devmode->dmBitsPerPel, devmode->dmDisplayFrequency,
            (unsigned)devmode->dmFields, (unsigned)flags, _ReturnAddress());
    } else {
        Log("CDS-W: NULL devmode (reset) flags=0x%X caller=0x%p",
            (unsigned)flags, _ReturnAddress());
    }
    return real ? real(devmode, flags) : DISP_CHANGE_FAILED;
}

static LONG WINAPI Hook_ChangeDisplaySettingsExW(LPCWSTR device, LPDEVMODEW devmode,
                                                  HWND hwnd, DWORD flags, LPVOID param) {
    ChangeDisplaySettingsExW_t real = g_chainChangeDispExW;
    char devBuf[64] = "<null>";
    if (device) WideCharToMultiByte(CP_UTF8, 0, device, -1, devBuf, sizeof(devBuf)-1, NULL, NULL);
    if (devmode) {
        Log("CDSEx-W: device='%s' w=%lu h=%lu bpp=%lu freq=%lu fields=0x%X flags=0x%X caller=0x%p",
            devBuf, devmode->dmPelsWidth, devmode->dmPelsHeight,
            devmode->dmBitsPerPel, devmode->dmDisplayFrequency,
            (unsigned)devmode->dmFields, (unsigned)flags, _ReturnAddress());
    } else {
        Log("CDSEx-W: device='%s' NULL devmode (reset) flags=0x%X caller=0x%p",
            devBuf, (unsigned)flags, _ReturnAddress());
    }
    return real ? real(device, devmode, hwnd, flags, param) : DISP_CHANGE_FAILED;
}

static void InitRegistryDiagnostic() {
    EnsureFFXiKeyCs();
    EnsureWinMapCs();
    HMODULE adv = GetModuleHandleA("advapi32.dll");
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE u32 = GetModuleHandleA("user32.dll");
    if (!adv) adv = LoadLibraryA("advapi32.dll");
    if (adv) {
        g_chainRegOpenW     = (RegOpenKeyExW_t)   GetProcAddress(adv, "RegOpenKeyExW");
        g_chainRegOpenA     = (RegOpenKeyExA_t)   GetProcAddress(adv, "RegOpenKeyExA");
        g_chainRegQueryW    = (RegQueryValueExW_t)GetProcAddress(adv, "RegQueryValueExW");
        g_chainRegQueryA    = (RegQueryValueExA_t)GetProcAddress(adv, "RegQueryValueExA");
        g_chainRegGetValueW = (RegGetValueW_t)    GetProcAddress(adv, "RegGetValueW");
        g_chainRegGetValueA = (RegGetValueA_t)    GetProcAddress(adv, "RegGetValueA");
    }
    if (k32) {
        g_chainOpenFileMapW  = (OpenFileMappingW_t)GetProcAddress(k32, "OpenFileMappingW");
        g_chainMapViewOfFile = (MapViewOfFile_t)   GetProcAddress(k32, "MapViewOfFile");
    }
    if (u32) {
        g_chainChangeDispW   = (ChangeDisplaySettingsW_t)  GetProcAddress(u32, "ChangeDisplaySettingsW");
        g_chainChangeDispExW = (ChangeDisplaySettingsExW_t)GetProcAddress(u32, "ChangeDisplaySettingsExW");
    }
    HMODULE windowerCore = GetModuleHandleA("windower.dll");
    if (!windowerCore) windowerCore = GetModuleHandleA("core.dll");
    Log("REG-DIAG: advapi32=0x%p chainW=0x%p chainA=0x%p windower-core=0x%p",
        (void*)adv, (void*)g_chainRegQueryW, (void*)g_chainRegQueryA, (void*)windowerCore);
    Log("REG-DIAG-EXT: regGetW=0x%p regGetA=0x%p ofm=0x%p mvf=0x%p cds=0x%p cdsEx=0x%p",
        (void*)g_chainRegGetValueW, (void*)g_chainRegGetValueA,
        (void*)g_chainOpenFileMapW, (void*)g_chainMapViewOfFile,
        (void*)g_chainChangeDispW, (void*)g_chainChangeDispExW);
}

// ============================================================================
// Kernel-level (ntdll) inline-detour diagnostic.
//
// Why: Windower's launcher writes per-profile FFXi resolution values into
// HKLM\SOFTWARE\WOW6432Node\PlayOnlineUS\SquareEnix\FinalFantasyXI\0001-0004
// before spawning pol.exe. pol.exe(A) reads those keys ~60s later during FFXi
// initialization. If launcher B runs in between, A reads B's clobbered values
// and renders at the wrong size.
//
// IAT hooks at advapi32/kernelbase do NOT catch FFXi's read on modern Windows
// (procmon proved the call reaches the kernel; our IAT hooks never fired).
// So we hook ntdll!NtQueryValueKey via inline detour — that's below every
// user-mode layer and catches every kernel-bound registry read.
//
// On first FFXi-pathed value read we emit a CONFIG_READ status milestone so
// Forest can use it as a serial-launch barrier.
// ============================================================================

typedef LONG    NT_STATUS_T;
typedef LONG    NTSTATUS_T;
#define NT_SUCCESS_OK(s) ((s) >= 0)

typedef struct _UNI_STR { USHORT Length; USHORT MaxLen; PWSTR Buf; } UNI_STR;
typedef struct _OBJ_ATTR {
    ULONG Length; HANDLE Root; UNI_STR* Name;
    ULONG Attr; PVOID SecDesc; PVOID SecQos;
} OBJ_ATTR;

typedef NTSTATUS_T (NTAPI *NtOpenKey_t)(PHANDLE, ACCESS_MASK, OBJ_ATTR*);
typedef NTSTATUS_T (NTAPI *NtOpenKeyEx_t)(PHANDLE, ACCESS_MASK, OBJ_ATTR*, ULONG);
typedef NTSTATUS_T (NTAPI *NtCreateKey_t)(PHANDLE, ACCESS_MASK, OBJ_ATTR*, ULONG, UNI_STR*, ULONG, PULONG);
typedef NTSTATUS_T (NTAPI *NtQueryValueKey_t)(HANDLE, UNI_STR*, int, PVOID, ULONG, PULONG);
typedef NTSTATUS_T (NTAPI *NtQueryKey_t)(HANDLE, int, PVOID, ULONG, PULONG);

static NtOpenKey_t       g_origNtOpenKey       = nullptr;
static NtOpenKeyEx_t     g_origNtOpenKeyEx     = nullptr;
static NtCreateKey_t     g_origNtCreateKey     = nullptr;
static NtQueryValueKey_t g_origNtQueryValueKey = nullptr;
static NtQueryKey_t      g_origNtQueryKey      = nullptr;  // not detoured, just called

static CRITICAL_SECTION g_ffxiHCs;
static volatile LONG g_ffxiHCsInit = 0;
static HANDLE g_ffxiHKeys[64] = {0};
static int g_ffxiHKeyN = 0;
static volatile LONG g_configReadKernelFired = 0;

static void EnsureFFXiHCs() {
    if (InterlockedExchange(&g_ffxiHCsInit, 1) == 0)
        InitializeCriticalSection(&g_ffxiHCs);
}

static bool WStrContainsFinalFantasyXI(const wchar_t* p, int wlen) {
    if (!p || wlen < 14) return false;
    for (int i = 0; i <= wlen - 14; ++i) {
        if (p[i] == L'F' && p[i+1] == L'i' && p[i+2] == L'n' && p[i+3] == L'a' &&
            p[i+4] == L'l' && p[i+5] == L'F' && p[i+6] == L'a' && p[i+7] == L'n' &&
            p[i+8] == L't' && p[i+9] == L'a' && p[i+10] == L's' && p[i+11] == L'y' &&
            p[i+12] == L'X' && p[i+13] == L'I') return true;
    }
    return false;
}

static void TrackFFXiHKey(HANDLE h) {
    if (!h) return;
    EnsureFFXiHCs();
    EnterCriticalSection(&g_ffxiHCs);
    for (int i = 0; i < g_ffxiHKeyN; ++i)
        if (g_ffxiHKeys[i] == h) { LeaveCriticalSection(&g_ffxiHCs); return; }
    if (g_ffxiHKeyN < 64) g_ffxiHKeys[g_ffxiHKeyN++] = h;
    LeaveCriticalSection(&g_ffxiHCs);
}

static bool IsTrackedFFXiHKey(HANDLE h) {
    if (!h) return false;
    EnterCriticalSection(&g_ffxiHCs);
    bool found = false;
    for (int i = 0; i < g_ffxiHKeyN && !found; ++i)
        if (g_ffxiHKeys[i] == h) found = true;
    LeaveCriticalSection(&g_ffxiHCs);
    return found;
}

static void UntrackFFXiHKey(HANDLE h) {
    if (!h) return;
    EnsureFFXiHCs();
    EnterCriticalSection(&g_ffxiHCs);
    for (int i = 0; i < g_ffxiHKeyN; ++i) {
        if (g_ffxiHKeys[i] == h) {
            g_ffxiHKeys[i] = g_ffxiHKeys[--g_ffxiHKeyN];
            break;
        }
    }
    LeaveCriticalSection(&g_ffxiHCs);
}

// After an Nt key open succeeds, query its full path and check if it lives
// under any FinalFantasyXI subtree. If yes, mark the handle as tracked.
static void MaybeTrackFFXiHKey(HANDLE h) {
    if (!h || !g_origNtQueryKey) return;
    __try {
        BYTE buf[1024];
        ULONG resultLen = 0;
        // KeyNameInformation = 3
        NTSTATUS_T qr = g_origNtQueryKey(h, 3, buf, sizeof(buf), &resultLen);
        if (NT_SUCCESS_OK(qr) && resultLen > sizeof(ULONG)) {
            ULONG nameLen = *(ULONG*)buf;
            const wchar_t* name = (const wchar_t*)(buf + sizeof(ULONG));
            int wlen = (int)(nameLen / 2);
            if (WStrContainsFinalFantasyXI(name, wlen)) {
                TrackFFXiHKey(h);
                char ascii[512] = {0};
                int copyN = wlen < 510 ? wlen : 510;
                WideCharToMultiByte(CP_UTF8, 0, name, copyN, ascii, sizeof(ascii)-1, NULL, NULL);
                Log("KRN-OPEN-FFXI: handle=0x%p path='%s'", h, ascii);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ============================================================================
// BG-RES OVERRIDE (zero-overhead alternative to the launch-barrier wait).
//
// When `bgres_<pid>.txt` exists in the same folder as Trees.dll, Trees.dll
// loads a map of FFXi-registry-value-name -> override-DWORD from it. Then
// inside Detour_NtQueryValueKey, when pol.exe queries one of these values
// on a FinalFantasyXI-tracked handle, we transparently overwrite the
// returned DWORD with our profile-specific value. Result: pol.exe sees the
// correct bg-res for its profile regardless of what the actual registry
// contains (so concurrent Windower launches can clobber the registry freely
// without consequence).
//
// Sidecar file format (plain text, one key=value per line):
//   0001=2560
//   0002=1400
//   0003=2560
//   0004=1400
//   0037=1969
//   0038=1076
// ============================================================================

#define BGRES_KEY_COUNT 64
static volatile bool g_bgresLoaded = false;
static int g_bgresN = 0;
static int g_bgresKeyIdx[BGRES_KEY_COUNT] = {0};   // FFXi key index (parsed from "0001" etc.)
static DWORD g_bgresValues[BGRES_KEY_COUNT] = {0};

// Parse a UNICODE_STRING value name as a 4-digit FFXi key index ("0001" -> 1).
// Returns -1 if not a 4-digit numeric.
static int ParseFFXiKeyIndex(UNI_STR* vn) {
    if (!vn || !vn->Buf) return -1;
    int wlen = vn->Length / 2;
    if (wlen < 4) return -1;
    int val = 0;
    for (int i = 0; i < 4; ++i) {
        wchar_t c = vn->Buf[i];
        if (c < L'0' || c > L'9') return -1;
        val = val * 10 + (c - L'0');
    }
    if (wlen > 4 && vn->Buf[4] != 0) return -1;
    return val;
}

static DWORD GetBgResOverride(int keyIdx, bool* found) {
    *found = false;
    for (int i = 0; i < g_bgresN; ++i) {
        if (g_bgresKeyIdx[i] == keyIdx) {
            *found = true;
            return g_bgresValues[i];
        }
    }
    return 0;
}

static bool TryLoadBgResSidecarOnce(const char* p, const char* fb) {
    FILE* f = nullptr;
    if (fopen_s(&f, p, "r") != 0 || !f) {
        if (fopen_s(&f, fb, "r") != 0 || !f) return false;
    }
    char line[128];
    while (fgets(line, sizeof(line), f) && g_bgresN < BGRES_KEY_COUNT) {
        char keyStr[16] = {0};
        unsigned val = 0;
        if (sscanf_s(line, "%15[^=]=%u", keyStr, (unsigned)sizeof(keyStr), &val) == 2) {
            int keyIdx = atoi(keyStr);
            if (keyIdx >= 0 && keyIdx < 10000) {
                g_bgresKeyIdx[g_bgresN] = keyIdx;
                g_bgresValues[g_bgresN] = val;
                g_bgresN++;
                Log("BGRES-OVERRIDE: loaded key %04d = %u", keyIdx, val);
            }
        }
    }
    fclose(f);
    return true;
}

// Async sidecar loader. Forest writes bgres_<pid>.txt after pol.exe spawns
// but before Trees.dll's DllMain completes — there's a tiny race, plus a
// potentially slow Forest write. Poll for up to 5 seconds.
static DWORD WINAPI BgResSidecarLoaderThread(LPVOID) {
    char p[MAX_PATH], fb[MAX_PATH];
    PidPaths(p, fb, MAX_PATH, "bgres", "txt");
    for (int i = 0; i < 50 && !g_bgresLoaded; ++i) {
        if (TryLoadBgResSidecarOnce(p, fb)) {
            g_bgresLoaded = (g_bgresN > 0);
            Log("BGRES-OVERRIDE: %d overrides active for this pol.exe (took %d ms)",
                g_bgresN, i * 100);
            return 0;
        }
        Sleep(100);
    }
    Log("BGRES-OVERRIDE: no sidecar appeared within 5s (looked for %s and %s)", p, fb);
    return 0;
}

// ============================================================================
// IN_GAME milestone. Polls FFXi's "party global" pointer (already used by
// AutoEnterThread's IsInGameNow): it stays null/junk during POL viewer + char
// select, then becomes a valid pointer when the character is fully zoned in
// with party data populated. That's the terminal "fully in game" state Forest
// uses to gate auto-quit.
//
// Runs as its own thread so it works regardless of whether AutoLoginCharacter
// is on. Doesn't write CONFIG_READ — that's a different signal (FFXi reading
// bg-res from registry), handled elsewhere.
// ============================================================================

// Forward decls — real definitions live further down in the file alongside
// the AutoEnter machinery.
extern volatile uintptr_t g_partyG;
static uintptr_t ResolveGlobalLE(HMODULE mod, const char* hexPat, const char* mask, int off);
static bool IsInGameNow();

static DWORD WINAPI InGameDetectorThread(LPVOID) {
    // Wait for FFXiMain.dll to load + sig-scan g_partyG (the same global
    // AutoEnterThread uses; whichever thread gets there first sets it).
    HMODULE ff = nullptr;
    for (int i = 0; i < 600 && !ff; ++i) {
        ff = GetModuleHandleA("FFXiMain.dll");
        if (!ff) Sleep(500);
    }
    if (!ff) {
        Log("IN_GAME: FFXiMain.dll never loaded; poller giving up");
        return 0;
    }
    if (!g_partyG) {
        g_partyG = ResolveGlobalLE(ff,
            "0FBEC38D0C5256578BF58D0448", "xxxxxxxxxxxxx", 23);
    }
    if (!g_partyG) {
        Log("IN_GAME: party global sig-scan failed; poller can't watch");
        return 0;
    }
    Log("IN_GAME: poller armed (partyG=0x%08X)", (unsigned)g_partyG);

    // 3 consecutive positive polls (~1.5s) before firing, to avoid lobby/title flickers.
    const int kStableThreshold = 3;
    int positiveStreak = 0;
    while (!g_inGameFired) {
        if (IsInGameNow()) {
            if (++positiveStreak >= kStableThreshold &&
                InterlockedExchange(&g_inGameFired, 1) == 0)
            {
                WriteStatus("IN_GAME", "character fully zoned in");
                Log("IN_GAME fired: character is in-game (party global stable for %d polls)", positiveStreak);
                break;
            }
        } else {
            if (positiveStreak > 0)
                Log("IN_GAME: streak reset after %d positive poll(s)", positiveStreak);
            positiveStreak = 0;
        }
        Sleep(500);
    }

    // Post-IN_GAME watchdog. 15s threshold survives normal zone loads;
    // stops polling after 5 minutes of stable in-game time.
    const int kDropStreakThreshold = 15;
    const ULONGLONG kMaxWatchMillis = 5 * 60 * 1000;
    ULONGLONG inGameSince = GetTickCount64();
    int dropStreak = 0;
    while (true) {
        Sleep(1000);
        if (GetTickCount64() - inGameSince > kMaxWatchMillis) {
            Log("post-IN_GAME watchdog: stopping after %llus stable in-game time",
                (GetTickCount64() - inGameSince) / 1000);
            return 0;
        }
        if (IsInGameNow()) {
            dropStreak = 0;
        } else {
            if (++dropStreak >= kDropStreakThreshold) {
                WriteStatus("DISCONNECTED", "lost connection to world");
                Log("DISCONNECTED fired: party global cleared for %d consecutive polls (%ds)",
                    dropStreak, dropStreak);
                return 0;
            }
        }
    }
}

static NTSTATUS_T NTAPI Detour_NtOpenKey(PHANDLE handle, ACCESS_MASK access, OBJ_ATTR* attr) {
    NtOpenKey_t fn = g_origNtOpenKey;
    if (!fn) return -1;
    NTSTATUS_T r = fn(handle, access, attr);
    if (NT_SUCCESS_OK(r) && handle && *handle) MaybeTrackFFXiHKey(*handle);
    return r;
}

static NTSTATUS_T NTAPI Detour_NtOpenKeyEx(PHANDLE handle, ACCESS_MASK access,
                                            OBJ_ATTR* attr, ULONG opt) {
    NtOpenKeyEx_t fn = g_origNtOpenKeyEx;
    if (!fn) return -1;
    NTSTATUS_T r = fn(handle, access, attr, opt);
    if (NT_SUCCESS_OK(r) && handle && *handle) MaybeTrackFFXiHKey(*handle);
    return r;
}

// NtCreateKey covers RegCreateKeyEx with REG_OPENED_EXISTING_KEY disposition,
// which is the call pol.exe actually uses to open the FinalFantasyXI registry
// key (verified via procmon trace). MUST be hooked or we never track the HKEY.
static NTSTATUS_T NTAPI Detour_NtCreateKey(PHANDLE handle, ACCESS_MASK access,
                                            OBJ_ATTR* attr, ULONG titleIdx,
                                            UNI_STR* cls, ULONG createOpts,
                                            PULONG dispos) {
    NtCreateKey_t fn = g_origNtCreateKey;
    if (!fn) return -1;
    NTSTATUS_T r = fn(handle, access, attr, titleIdx, cls, createOpts, dispos);
    if (NT_SUCCESS_OK(r) && handle && *handle) MaybeTrackFFXiHKey(*handle);
    return r;
}

static NTSTATUS_T NTAPI Detour_NtQueryValueKey(HANDLE h, UNI_STR* vn, int cls,
                                                PVOID info, ULONG len, PULONG result) {
    NtQueryValueKey_t fn = g_origNtQueryValueKey;
    if (!fn) return -1;
    NTSTATUS_T r = fn(h, vn, cls, info, len, result);
    if (IsTrackedFFXiHKey(h)) {
        // BG-RES OVERRIDE: substitute the returned DWORD with our profile's
        // value before returning to the caller. Only fires when:
        //   - the sidecar file loaded an override for this FFXi key index
        //   - the call succeeded and returned a KeyValuePartialInformation
        //     buffer with REG_DWORD type and DataLength >= 4
        // For everything else (other classes, non-DWORD types) we just pass
        // through unchanged.
        if (g_bgresLoaded && cls == 2 && NT_SUCCESS_OK(r) &&
            info && result && *result >= 16)
        {
            int keyIdx = ParseFFXiKeyIndex(vn);
            if (keyIdx >= 0) {
                bool haveOverride = false;
                DWORD ovr = GetBgResOverride(keyIdx, &haveOverride);
                if (haveOverride) {
                    __try {
                        BYTE* p = (BYTE*)info;
                        DWORD type = *(DWORD*)(p + 4);
                        DWORD dataLen = *(DWORD*)(p + 8);
                        if (type == REG_DWORD && dataLen >= 4) {
                            DWORD oldVal = *(DWORD*)(p + 12);
                            *(DWORD*)(p + 12) = ovr;
                            Log("BGRES-APPLY: key %04d real=%u -> override=%u",
                                keyIdx, oldVal, ovr);
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
        }
        char nm[64] = "<null>";
        if (vn && vn->Buf && vn->Length) {
            int wlen = vn->Length / 2;
            if (wlen > 62) wlen = 62;
            WideCharToMultiByte(CP_UTF8, 0, vn->Buf, wlen, nm, sizeof(nm)-1, NULL, NULL);
            nm[wlen < 63 ? wlen : 63] = 0;
        }
        // Try to read the returned DWORD value for visibility
        DWORD dwVal = 0;
        if (NT_SUCCESS_OK(r) && info && result && *result >= 16) {
            // KEY_VALUE_PARTIAL_INFORMATION layout:
            //   ULONG TitleIndex  (offset 0)
            //   ULONG Type        (offset 4)
            //   ULONG DataLength  (offset 8)
            //   UCHAR Data[1]     (offset 12)
            // class 2 = KeyValuePartialInformation
            if (cls == 2) {
                __try { dwVal = *(DWORD*)((BYTE*)info + 12); }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
        Log("KRN-QRY: handle=0x%p value='%s' status=0x%08X cls=%d dword=%u",
            h, nm, (unsigned)r, cls, dwVal);
        if (NT_SUCCESS_OK(r) &&
            InterlockedExchange(&g_configReadKernelFired, 1) == 0)
        {
            char msg[128];
            sprintf_s(msg, "FFXi kernel-read '%s' val=%u", nm, dwVal);
            WriteStatus("CONFIG_READ", msg);
            Log("CONFIG_READ kernel-fired: first read of '%s' (dword=%u) on tracked handle 0x%p",
                nm, dwVal, h);
        }
    }
    return r;
}

// (NtClose hook deliberately removed: too frequent, too risky for inline
// detour; the FFXi handle set just accumulates closed handles, which is
// bounded at 64 entries and not a correctness issue.)

// Inline detour state — one entry per detoured function.
struct InlineDetour {
    void* target;
    void* tramp;     // executable trampoline: original prologue + JMP back
    BYTE  saved[16];
    int   saved_len;
};

static InlineDetour g_inlineDetours[8];
static volatile LONG g_inlineDetourN = 0;

// Tiny prologue measurer — handles the instruction shapes we see at the top
// of ntdll syscall stubs. Returns bytes consumed to cover >= 5 bytes worth
// of complete instructions, or 0 on shapes we don't recognize.
static int MeasureNtdllPrologue(const BYTE* p) {
    int len = 0;
    int safety = 0;
    while (len < 5 && safety++ < 8) {
        BYTE b = p[len];
        // mov reg32, imm32  (0xB8..0xBF) — 5 bytes
        if (b >= 0xB8 && b <= 0xBF) { len += 5; continue; }
        // push reg  (0x50..0x57) — 1 byte
        if (b >= 0x50 && b <= 0x57) { len += 1; continue; }
        // mov edi, edi  (8B FF) — 2 bytes, classic hotpatch
        if (b == 0x8B && p[len+1] == 0xFF) { len += 2; continue; }
        // sub esp, imm8  (83 EC XX) — 3 bytes
        if (b == 0x83 && (p[len+1] == 0xEC || p[len+1] == 0xC4)) { len += 3; continue; }
        // xor reg, reg  (33 XX) — 2 bytes
        if (b == 0x33) { len += 2; continue; }
        // nop  (90) — 1 byte
        if (b == 0x90) { len += 1; continue; }
        // Unknown opcode — bail
        return 0;
    }
    return len >= 5 ? len : 0;
}

// Install an inline detour. CRITICAL: writes *chainOut (the trampoline
// pointer that the detour calls to invoke the original) BEFORE patching
// the target, so any thread that hits the JMP and enters the detour finds
// a non-null chain pointer to call. Returns true on success.
static bool InstallInlineDetour(void* target, void* detour, void** chainOut) {
    if (!target || !detour || !chainOut) return false;
    LONG idx = InterlockedIncrement(&g_inlineDetourN) - 1;
    if (idx >= 8) return false;
    InlineDetour* d = &g_inlineDetours[idx];

    BYTE* tgt = (BYTE*)target;
    int len = MeasureNtdllPrologue(tgt);
    if (len == 0 || len > 16) {
        Log("InlineDetour FAIL: prologue measure failed at 0x%p (first bytes %02X %02X %02X %02X %02X)",
            target, tgt[0], tgt[1], tgt[2], tgt[3], tgt[4]);
        InterlockedDecrement(&g_inlineDetourN);
        return false;
    }

    // Allocate trampoline: prologue bytes + 5-byte JMP back to target+len
    BYTE* tramp = (BYTE*)VirtualAlloc(nullptr, len + 5, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!tramp) {
        Log("InlineDetour FAIL: VirtualAlloc tramp failed for 0x%p", target);
        InterlockedDecrement(&g_inlineDetourN);
        return false;
    }

    memcpy(tramp, tgt, len);
    tramp[len] = 0xE9; // JMP rel32
    int32_t relBack = (int32_t)((uintptr_t)(tgt + len) - (uintptr_t)(tramp + len + 5));
    memcpy(tramp + len + 1, &relBack, 4);
    FlushInstructionCache(GetCurrentProcess(), tramp, len + 5);

    memcpy(d->saved, tgt, len);
    d->saved_len = len;
    d->target = target;
    d->tramp = tramp;

    // RACE FIX: publish the chain pointer BEFORE patching the target so the
    // very first concurrent caller of the patched function finds a usable
    // chain. On x86 a properly-aligned pointer write is atomic.
    *chainOut = tramp;
    MemoryBarrier();

    // Patch target prologue: JMP detour, padded with NOPs
    DWORD oldProt = 0;
    if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("InlineDetour FAIL: VirtualProtect target failed for 0x%p", target);
        *chainOut = nullptr;
        VirtualFree(tramp, 0, MEM_RELEASE);
        InterlockedDecrement(&g_inlineDetourN);
        return false;
    }
    tgt[0] = 0xE9;
    int32_t relFwd = (int32_t)((uintptr_t)detour - (uintptr_t)(tgt + 5));
    memcpy(tgt + 1, &relFwd, 4);
    for (int i = 5; i < len; ++i) tgt[i] = 0x90;
    DWORD tmp = 0;
    VirtualProtect(target, len, oldProt, &tmp);
    FlushInstructionCache(GetCurrentProcess(), target, len);

    Log("InlineDetour OK: target=0x%p detour=0x%p tramp=0x%p (saved %d bytes)",
        target, detour, tramp, len);
    return true;
}

static void InitKernelLevelDiagnostic() {
    EnsureFFXiHCs();
    // Spawn async loader so DllMain doesn't block waiting for Forest's write
    CloseHandle(CreateThread(nullptr, 0, BgResSidecarLoaderThread, nullptr, 0, nullptr));
    // Spawn the IN_GAME poller — always on, works regardless of AutoLogin
    CloseHandle(CreateThread(nullptr, 0, InGameDetectorThread, nullptr, 0, nullptr));
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { Log("KRN-DIAG: ntdll not loaded?!"); return; }

    // Resolve real ntdll function pointers (we need NtQueryKey unhooked
    // so we can use it inside our hooks)
    g_origNtQueryKey = (NtQueryKey_t)GetProcAddress(ntdll, "NtQueryKey");

    void* fnOpenKey       = GetProcAddress(ntdll, "NtOpenKey");
    void* fnOpenKeyEx     = GetProcAddress(ntdll, "NtOpenKeyEx");
    void* fnCreateKey     = GetProcAddress(ntdll, "NtCreateKey");
    void* fnQueryValueKey = GetProcAddress(ntdll, "NtQueryValueKey");

    if (fnOpenKey)
        InstallInlineDetour(fnOpenKey, (void*)&Detour_NtOpenKey, (void**)&g_origNtOpenKey);
    if (fnOpenKeyEx)
        InstallInlineDetour(fnOpenKeyEx, (void*)&Detour_NtOpenKeyEx, (void**)&g_origNtOpenKeyEx);
    if (fnCreateKey)
        InstallInlineDetour(fnCreateKey, (void*)&Detour_NtCreateKey, (void**)&g_origNtCreateKey);
    if (fnQueryValueKey)
        InstallInlineDetour(fnQueryValueKey, (void*)&Detour_NtQueryValueKey, (void**)&g_origNtQueryValueKey);

    Log("KRN-DIAG: ntdll=0x%p openKey-tramp=0x%p openKeyEx-tramp=0x%p createKey-tramp=0x%p queryValueKey-tramp=0x%p queryKey-real=0x%p",
        (void*)ntdll, (void*)g_origNtOpenKey, (void*)g_origNtOpenKeyEx,
        (void*)g_origNtCreateKey, (void*)g_origNtQueryValueKey, (void*)g_origNtQueryKey);
}

static DI_GetDeviceState_t g_realGetDevState = nullptr;
static volatile bool g_injectActive = false;
static volatile BYTE g_injectKey = 0x1C;
static volatile LONG g_injectOneShot = 0;

struct DiPatch { uintptr_t* vt; uintptr_t orig; };
static DiPatch g_diPatches[2] = {};
static int g_diPatchN = 0;

struct MenuGlobals { uintptr_t menu, lic, lob, sel, yes, sidx, mainsys; };

static HRESULT STDMETHODCALLTYPE Hook_GetDeviceState(void* self, DWORD cb, void* data)
{
    DI_GetDeviceState_t real = g_realGetDevState;
    HRESULT hr = real ? real(self, cb, data) : E_FAIL;
    if (SUCCEEDED(hr) && data && cb >= 256) {
        if (g_injectActive)
            ((BYTE*)data)[g_injectKey] = (BYTE)0x80;
        else if (InterlockedExchange(&g_injectOneShot, 0))
            ((BYTE*)data)[g_injectKey] = (BYTE)0x80;
    }
    return hr;
}

static void PatchKeyboardGetState(const GUID& iid)
{
    HMODULE di = GetModuleHandleA("dinput8.dll");
    if (!di) return;
    auto create = (DI8Create_t)GetProcAddress(di, "DirectInput8Create");
    if (!create) return;
    void* pDI = nullptr;
    if (FAILED(create(GetModuleHandleA(nullptr), 0x0800, iid, &pDI, nullptr)) || !pDI)
        return;
    void** diVtbl = *(void***)pDI;
    auto createDev = (DI_CreateDevice_t)diVtbl[3];
    void* pDev = nullptr;
    if (SUCCEEDED(createDev(pDI, kGUID_SysKeyboard, &pDev, nullptr)) && pDev) {
        __try {
            uintptr_t* vt = *(uintptr_t**)pDev;
            uintptr_t orig = vt[9];
            if (!g_realGetDevState)
                g_realGetDevState = (DI_GetDeviceState_t)orig;
            if (orig != (uintptr_t)&Hook_GetDeviceState && g_diPatchN < 2) {
                DWORD op;
                if (VirtualProtect(&vt[9], sizeof(uintptr_t), PAGE_READWRITE, &op)) {
                    vt[9] = (uintptr_t)&Hook_GetDeviceState;
                    DWORD t; VirtualProtect(&vt[9], sizeof(uintptr_t), op, &t);
                    g_diPatches[g_diPatchN].vt = vt;
                    g_diPatches[g_diPatchN].orig = orig;
                    g_diPatchN++;
                    Log("auto-enter: keyboard GetDeviceState patched (vtbl=0x%p)", (void*)vt);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        __try {
            auto rel = (DI_Release_t)(*(void***)pDev)[2];
            rel(pDev);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    __try {
        auto relDI = (DI_Release_t)(*(void***)pDI)[2];
        relDI(pDI);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void RestoreKeyboardGetState()
{
    int restored = 0, failed = 0;
    for (int i = 0; i < g_diPatchN; ++i) {
        bool ok = false;
        __try {
            DWORD op;
            if (VirtualProtect(&g_diPatches[i].vt[9], sizeof(uintptr_t),
                               PAGE_READWRITE, &op)) {
                g_diPatches[i].vt[9] = g_diPatches[i].orig;
                DWORD t;
                VirtualProtect(&g_diPatches[i].vt[9], sizeof(uintptr_t), op, &t);
                ok = true;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (ok) {
            ++restored;
            Log("auto-enter: keyboard GetDeviceState RESTORED (vtbl=0x%p)",
                (void*)g_diPatches[i].vt);
        } else {
            ++failed;
            Log("auto-enter: keyboard GetDeviceState RESTORE FAILED (vtbl=0x%p) "
                "- hook will remain on shared dinput8 vtable",
                (void*)g_diPatches[i].vt);
        }
    }
    Log("auto-enter: RestoreKeyboardGetState done (restored=%d failed=%d total=%d)",
        restored, failed, g_diPatchN);
    g_diPatchN = 0;
}

static volatile int g_injMethod = 0;   // 0 = DInput vtable hook, 1 = SendInput

static void SendDik(BYTE dik, bool keyup)
{
    WORD sc; BOOL ext = FALSE;
    switch (dik) {
        case 0x1C: sc = 0x1C;             break;   // Enter
        case 0xD0: sc = 0x50; ext = TRUE; break;   // Down (extended arrow)
        case 0xC8: sc = 0x48; ext = TRUE; break;   // Up   (extended arrow)
        default:   sc = dik;              break;
    }
    INPUT in = {};
    in.type = INPUT_KEYBOARD;
    in.ki.wScan = sc;
    in.ki.dwFlags = KEYEVENTF_SCANCODE
                  | (ext ? KEYEVENTF_EXTENDEDKEY : 0)
                  | (keyup ? KEYEVENTF_KEYUP : 0);
    SendInput(1, &in, sizeof(INPUT));
}

static void EnsureGameFocus()
{
    HWND h = FindGameWindow();
    if (h) { SetForegroundWindow(h); BringWindowToTop(h); }
}

static void PulseKey(BYTE dik, int holdMs)
{
    if (g_injMethod == 1) {
        EnsureGameFocus();
        SendDik(dik, false);
        Sleep(holdMs);
        SendDik(dik, true);
    } else {
        g_injectKey = dik;
        g_injectActive = true;
        Sleep(holdMs);
        g_injectActive = false;
    }
}

static void TapKey(BYTE dik)
{
    if (g_injMethod == 1) {
        EnsureGameFocus();
        SendDik(dik, false);
        Sleep(30);
        SendDik(dik, true);
    } else {
        g_injectKey = dik;
        InterlockedExchange(&g_injectOneShot, 1);
    }
}

static uint8_t* FindPatLE(HMODULE mod, const char* hexPat, const char* mask)
{
    char buf[512]; int bp = 0;
    for (int i = 0; mask[i]; ++i) {
        if (bp && bp < (int)sizeof(buf) - 2) buf[bp++] = ' ';
        if (mask[i] == 'x') { buf[bp++] = hexPat[i*2]; buf[bp++] = hexPat[i*2+1]; }
        else buf[bp++] = '?';
    }
    buf[bp] = 0;
    return ScanModule(mod, buf);
}

static uintptr_t ResolveGlobalLE(HMODULE mod, const char* hexPat, const char* mask, int off)
{
    uint8_t* m = FindPatLE(mod, hexPat, mask);
    if (!m) return 0;
    __try { return *(uintptr_t*)(m + off); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static volatile uintptr_t g_curAddr = 0;
static volatile uintptr_t g_partyG  = 0;

static int ReadCursorIdx()
{
    if (!g_curAddr) return -1;
    __try { int v = *(int*)g_curAddr; return (v >= 0 && v <= 31) ? v : -1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}

static bool IsInGameNow()
{
    if (!g_partyG) return false;
    __try { return *(uint32_t*)g_partyG > 0x10000; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool RunBootNav(int target)
{
    bool atSelect = false;
    for (int i = 0; i < 20 && !atSelect; ++i) {
        if (IsInGameNow()) { Log("auto-enter: in-game before select."); return true; }
        int c0 = ReadCursorIdx();
        TapKey(0xD0);
        Sleep(250);
        int c1 = ReadCursorIdx();
        if (c0 >= 0 && c1 >= 0 && c0 != c1) {
            atSelect = true;
            Log("auto-enter: char-select detected (cursor %d->%d via Down).", c0, c1);
            break;
        }
        TapKey(0xC8);
        Sleep(200);
        PulseKey(0x1C, 150);
        Sleep(900);
    }

    if (!atSelect) {
        Log("auto-enter: char-select not detected; Enter-to-in-game attempt.");
        for (int i = 0; i < 8 && !IsInGameNow(); ++i) { PulseKey(0x1C, 150); Sleep(1000); }
        return IsInGameNow();
    }

    for (int i = 0; i < 24; ++i) {
        int c = ReadCursorIdx();
        if (c < 0 || c == target) break;
        TapKey(c < target ? 0xD0 : 0xC8);
        Sleep(220);
    }
    Log("auto-enter: cursor=%d (target %d); selecting.", ReadCursorIdx(), target);
    PulseKey(0x1C, 150);
    Sleep(900);

    for (int i = 0; i < 40 && !IsInGameNow(); ++i) {
        PulseKey(0x1C, 150);
        Sleep(1000);
    }
    return IsInGameNow();
}

static uint32_t MenuObj(uintptr_t gAddr)
{
    if (!gAddr) return 0;
    __try { return *(uint32_t*)gAddr; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static void MenuSet(uint32_t obj, uint32_t off, int v)
{
    if (!obj) return;
    __try { *(int*)(obj + off) = v; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static bool ReadMenuName(uintptr_t menuGlobal, char* out, uint32_t* focusedOut)
{
    if (!menuGlobal) return false;
    __try {
        uint32_t root = *(uint32_t*)menuGlobal;
        if (root < 0x10000 || root > 0x7FFFFFFF) return false;
        for (int variant = 0; variant < 2; ++variant) {
            uint32_t b = (variant == 0) ? root : *(uint32_t*)root;
            if (b < 0x10000 || b > 0x7FFFFFFF) continue;
            uint32_t f = *(uint32_t*)(b + 0x04);
            if (f < 0x10000 || f > 0x7FFFFFFF) continue;
            const char* s = (const char*)(f + 0x46);
            if (s[0] == 'm' && s[1] == 'e' && s[2] == 'n' && s[3] == 'u') {
                memcpy(out, s, 16);
                out[16] = 0;
                if (focusedOut) *focusedOut = f;
                return true;
            }
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool ResolveMenuGlobals(HMODULE ff, MenuGlobals* g)
{
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), ff, &mi, sizeof(mi))) return false;
    uintptr_t base = (uintptr_t)mi.lpBaseOfDll, end = base + mi.SizeOfImage;

    const char* p1 = "895E1C895E14896E18890000000000EB0089000000000068";
    const char* m1 = "xxxxxxxxxx?????x?x?????x";
    const char* p2 = "89412C8B1500000000897C2410894230A1";
    const char* m2 = "xxxxx????xxxxxxxx";
    const char* p3 = "A1000000008B5108406689424C8B4908668B414C50E8";
    const char* m3 = "x????xxxxxxxxxxxxxxxxx";
    const char* pm = "8B480C85C974008B510885D274003B05";
    const char* mm = "xxxxxx?xxxxxx?xx";
    const char* pc = "8B0D000000008D04808B848100000000C3";
    const char* mc = "xx????xxxxxx????x";

    g->menu = ResolveGlobalLE(ff, pm, mm, 0x10);
    g->lic  = ResolveGlobalLE(ff, p1, m1, 0x0B);
    g->yes  = ResolveGlobalLE(ff, p1, m1, 0x47);
    g->lob  = ResolveGlobalLE(ff, p2, m2, 0x05);
    g->sel  = ResolveGlobalLE(ff, p2, m2, 0x11);
    g->sidx = ResolveGlobalLE(ff, p3, m3, 0x01);
    g->mainsys = (uintptr_t)FindPatLE(ff, pc, mc);

    auto inMod = [&](uintptr_t a) { return a >= base && a < end; };
    Log("auto-enter(menu): menu=0x%08X lic=0x%08X lob=0x%08X sel=0x%08X yes=0x%08X sidx=0x%08X mainsys=0x%08X",
        (unsigned)g->menu, (unsigned)g->lic, (unsigned)g->lob, (unsigned)g->sel, (unsigned)g->yes, (unsigned)g->sidx, (unsigned)g->mainsys);
    return inMod(g->menu) && inMod(g->lic) && inMod(g->lob) && inMod(g->sel) && inMod(g->yes);
}

static int MenuCharCount(uintptr_t mainsys)
{
    if (!mainsys) return -1;
    __try {
        uint32_t g1  = *(uint32_t*)(mainsys + 0x02);
        uint32_t off = *(uint32_t*)(mainsys + 0x0C);
        if (g1 < 0x10000 || !off) return -1;
        uint32_t arr = *(uint32_t*)g1 + off;
        if (arr < 0x10000) return -1;
        int c = (int)*(uint32_t*)(arr - 4);
        return (c >= 0 && c <= 16) ? c : -1;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}

static bool MenuLogin(int sel, const MenuGlobals& g)
{
    char name[17], last[17] = { 0 };
    int clampedLogged = 0;
    for (int i = 0; i < 2400; ++i) {
        if (IsInGameNow()) return true;
        if (!ReadMenuName(g.menu, name, nullptr)) { Sleep(25); continue; }
        if (strcmp(name, last)) { Log("auto-enter(menu): screen '%s'", name); strcpy_s(last, sizeof(last), name); }

        if (strstr(name, "ptc8lice")) {
            uint32_t o = MenuObj(g.lic); MenuSet(o, 0x18, 0); MenuSet(o, 0x1C, 1);
        } else if (strstr(name, "loby2win")) {
            uint32_t o = MenuObj(g.lob); MenuSet(o, 0x18, 0); MenuSet(o, 0x1C, 1);
        } else if (strstr(name, "dbnamese")) {
            int s = sel, cnt = MenuCharCount(g.mainsys);
            if (cnt > 0 && s >= cnt) {
                if (!clampedLogged) { Log("auto-enter(menu): slot idx %d >= char count %d; selecting last (idx %d).", sel, cnt, cnt - 1); clampedLogged = 1; }
                s = cnt - 1;
            }
            uint32_t o = MenuObj(g.sel);
            MenuSet(g.sidx, 0, s);
            MenuSet(o, 0x14, s); MenuSet(o, 0x18, s); MenuSet(o, 0x1C, 1);
        } else if (strstr(name, "ptc6yesn")) {
            uint32_t o = MenuObj(g.yes); MenuSet(o, 0x14, 0); MenuSet(o, 0x30, 1);
        }
        Sleep(25);
    }
    return IsInGameNow();
}

static DWORD WINAPI AutoEnterThread(LPVOID)
{
    for (int i = 0; i < 100 && !GetModuleHandleA("dinput8.dll"); ++i) Sleep(100);
    Sleep(1000);

    char smk[MAX_PATH]; DllSibling(smk, MAX_PATH, "forest_sendinput.txt");
    bool sendAllowed = (GetFileAttributesA(smk) != INVALID_FILE_ATTRIBUTES);

    HMODULE ff = nullptr;
    for (int i = 0; i < 200 && !ff; ++i) { ff = GetModuleHandleA("FFXiMain.dll"); if (!ff) Sleep(100); }
    if (ff) {
        MODULEINFO mi{}; GetModuleInformation(GetCurrentProcess(), ff, &mi, sizeof(mi));
        uint8_t* fb = (uint8_t*)mi.lpBaseOfDll;
        g_partyG  = ResolveGlobalLE(ff, "0FBEC38D0C5256578BF58D0448", "xxxxxxxxxxxxx", 23);
        g_curAddr = ResolveGlobalLE(ff, "0FBF404C48A3FFFFFFFF8D3C808D0478", "xxxxxx????xxxxxx", 6);
        uint32_t crva = g_curAddr ? (uint32_t)((uintptr_t)g_curAddr - (uintptr_t)fb) : 0;
        if (!g_curAddr || crva < 0x34F000 || crva >= 0x9C7000) {
            Log("auto-enter: cursor sig miss (rva 0x%X); fallback FFXiMain+0x63656C.", crva);
            g_curAddr = (uintptr_t)fb + 0x63656C;
        } else {
            Log("auto-enter: cursor sig -> rva 0x%X%s.", crva,
                crva == 0x63656C ? " (matches expected)" : " (differs; client patched?)");
        }
    }
    int target = (g_charSlot < 1 ? 1 : g_charSlot) - 1;
    if (target > 15) target = 15;
    Log("auto-enter: target slot %d (idx %d); cur=0x%08X party=0x%08X "
        "(dinput patch deferred until keystroke fallback is needed)",
        target + 1, target, (unsigned)g_curAddr, (unsigned)g_partyG);
    Sleep(1500);

    MenuGlobals mg{};
    bool menuOk = ff && ResolveMenuGlobals(ff, &mg);

    bool done = false;
    const char* method = "none";
    bool hookOk = false;

    if (menuOk) {
        Log("auto-enter: pure menu-memory login (autologin-style, no keystrokes), target idx %d.", target);
        done = MenuLogin(target, mg);
        if (done) method = "menu";
    }

    if (!done) {
        Log("auto-enter: %s; keystroke fallback - patching dinput8 keyboard now.",
            menuOk ? "menu memory did not reach in-game" : "menu signatures unresolved");
        PatchKeyboardGetState(kIID_IDirectInput8A);
        PatchKeyboardGetState(kIID_IDirectInput8W);
        hookOk = (g_realGetDevState != nullptr);
        if (hookOk || sendAllowed) {
            if (hookOk) { g_injMethod = 0; done = RunBootNav(target); if (done) method = "hook"; }
            if (!done && sendAllowed) { g_injMethod = 1; done = RunBootNav(target); if (done) method = "sendinput"; }
        }
    }

    if (hookOk) RestoreKeyboardGetState();
    Log("auto-enter: complete (in-game=%d, method=%s).",
        IsInGameNow() ? 1 : 0, method);
    return 0;
}

static DWORD WINAPI FakeFocusInstallThread(LPVOID)
{
    HMODULE self = GetSelfModule();
    ULONGLONG t0 = GetTickCount64();
    int prevTotal = -1;
    bool armed = false;
    DWORD lastModCount = 0;
    while (g_antiThrottle) {
        if (!armed) {
            HWND pol = PolWnd();
            if (pol) {
                g_fakeFocusHwnd = pol;
                armed = true;
                Log("fake-focus: arming (pol HWND = 0x%p)", pol);
            }
        }
        HMODULE mods[256]; DWORD needed = 0;
        DWORD modCount = lastModCount;
        if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
            modCount = needed / sizeof(HMODULE);
        if (modCount != lastModCount) {
            lastModCount = modCount;
            int total = InstallFakeFocusAllModules(self);
            if (total != prevTotal) {
                Log("fake-focus: %d user32 IAT slots redirected", total);
                prevTotal = total;
            }
        }
        HWND game = FindGameWindow();
        bool ffxiUp = (GetModuleHandleA("FFXiMain.dll") != nullptr);
        if (game || ffxiUp) {
            g_antiThrottle = false;
            Log("fake-focus: anti-throttle OFF (game up: FFXiClass=%d FFXiMain=%d); "
                "in-game uses real focus.", game ? 1 : 0, ffxiUp ? 1 : 0);
            if (g_autoEnter)
                CloseHandle(CreateThread(nullptr, 0, AutoEnterThread,
                                         (LPVOID)game, 0, nullptr));
            else
                Log("auto-enter: disabled by config; skipping boot ENTERs.");
            break;
        }
        if (GetTickCount64() - t0 > 300000) {
            g_antiThrottle = false;
            Log("fake-focus: anti-throttle OFF (timeout, no game window).");
            break;
        }
        Sleep(armed ? 1000 : 50);
    }
    return 0;
}

static uint32_t FindWideStringInHeap(const wchar_t* needle)
{
    int nlen = (int)wcslen(needle);
    if (nlen <= 0) return 0;
    size_t nbytes = nlen * 2;

    const uint8_t* HEAP_LO = (uint8_t*)0x00010000;
    const uint8_t* HEAP_HI = (uint8_t*)0x40000000;

    MEMORY_BASIC_INFORMATION mbi;
    for (uint8_t* a = (uint8_t*)HEAP_LO; a < HEAP_HI; ) {
        if (!VirtualQuery(a, &mbi, sizeof(mbi))) break;
        uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        bool readable = mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD);
        if (readable) {
            __try {
                uint8_t* end = next - nbytes;
                if (end > HEAP_HI) end = (uint8_t*)HEAP_HI;
                for (uint8_t* q = (uint8_t*)mbi.BaseAddress; q <= end; q += 2) {
                    bool match = true;
                    for (int i = 0; i < nlen; ++i) {
                        if (*(uint16_t*)(q + i * 2) != (uint16_t)needle[i]) {
                            match = false; break;
                        }
                    }
                    if (match) return (uint32_t)(uintptr_t)q;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {   }
        }
        if (next <= a) break;
        a = next;
    }
    return 0;
}

static DWORD WINAPI PostConnectWatchdog(LPVOID)
{
    Log("PostConnectWatchdog: armed (10s POL-5311 scan, 30s stuck deadline)");

    auto tryFindPOL5311 = []() -> uint32_t {
        uint32_t h = FindWideStringInHeap(L"Error code:POL-5311");
        if (!h) h = FindWideStringInHeap(L"POL-5311");
        return h;
    };

    auto fireWrongPw = [](uint32_t hit) {
        Log("PostConnectWatchdog: POL-5311 found at 0x%08X — writing "
            "FAILED|WRONG_SE_PASSWORD + terminating.", hit);
        WriteStatus("FAILED", "WRONG_SE_PASSWORD");
        Sleep(750);
        TerminateProcess(GetCurrentProcess(), 1);
    };

    auto SafeWriteDone = [](const char* reason) {
        if (g_inGameFired) {
            Log("PostConnectWatchdog: %s, but IN_GAME already fired — suppressing DONE write", reason);
            return;
        }
        if (!InterlockedExchange(&g_fastLoginDone, 1)) WriteStatus("DONE", "login complete");
    };

    Sleep(10000);
    if (g_fastLoginDone || g_inGameFired) return 0;
    if (!PolWnd()) {
        Log("PostConnectWatchdog: POL window gone at +10s (login succeeded).");
        SafeWriteDone("POL gone at +10s");
        return 0;
    }
    if (uint32_t hit = tryFindPOL5311()) { fireWrongPw(hit); return 0; }

    Log("PostConnectWatchdog: +10s no POL-5311 yet; extending wait to +30s "
        "for slow SE round-trip or late error display.");
    Sleep(20000);

    if (g_fastLoginDone || g_inGameFired) return 0;
    if (!PolWnd()) {
        Log("PostConnectWatchdog: POL window gone at +30s (slow login "
            "eventually succeeded).");
        SafeWriteDone("POL gone at +30s");
        return 0;
    }
    if (uint32_t hit = tryFindPOL5311()) { fireWrongPw(hit); return 0; }
    if (g_fastLoginDone) return 0;

    Log("PostConnectWatchdog: POL window still alive at +30s with no "
        "POL-5311 string. Likely a non-WRONG_SE_PASSWORD error (network / "
        "server / OTP / ban / etc.). Writing FAILED|POST_CONNECT_STUCK "
        "and self-terminating.");
    WriteStatus("FAILED", "POST_CONNECT_STUCK");
    Sleep(750);
    TerminateProcess(GetCurrentProcess(), 1);
    return 0;
}

static void PostKeyToPol(WORD vk)
{
    HWND h = PolWnd();
    if (!h) { Log("PostKey: POL window not found"); return; }
    UINT sc = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    LPARAM down = (LPARAM)(1u | (sc << 16));
    LPARAM up   = (LPARAM)(1u | (sc << 16) | (1u << 30) | (1u << 31));
    PostMessageW(h, WM_KEYDOWN, vk, down);
    PostMessageW(h, WM_KEYUP,   vk, up);
    Log("PostKey: VK=0x%02X posted to POL hwnd=0x%p", vk, h);
}

static bool StashWnd(bool announce)
{
    HWND h = PolWnd();
    if (!h) return false;
    RECT r;
    if (GetWindowRect(h, &r) && r.left <= -30000) return true;
    SetWindowPos(h, HWND_BOTTOM, -32000, -32000, 0, 0,
                 SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOZORDER);
    if (announce)
        Log("POL window moved OFF-SCREEN (still shown) -- "
            "interference-proof, POL keeps running.");
    return true;
}

static void RestorePolWnd()
{
    HWND h = PolWnd();
    if (!h) return;
    int x = g_polOrigSaved ? g_polOrigRect.left : 120;
    int y = g_polOrigSaved ? g_polOrigRect.top  : 120;
    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN), vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN), vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    bool onScreen = (x >= vx && y >= vy && x <= vx + vw - 120 && y <= vy + vh - 80);
    if (!onScreen) { x = vx + 120; y = vy + 120; }
    SetWindowPos(h, HWND_BOTTOM, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
    Log("RestorePolWnd: POL window to %d,%d (saved=%d onscreen=%d virt=%d,%d %dx%d)",
        x, y, (int)g_polOrigSaved, (int)onScreen, vx, vy, vw, vh);
}

static int ReadTargetSlot()
{
    char p[MAX_PATH], fb[MAX_PATH];
    PidPaths(p, fb, MAX_PATH, "slot", "txt");
    FILE* f = nullptr;
    if (fopen_s(&f, p, "r") != 0 || !f) {
        if (fopen_s(&f, fb, "r") != 0 || !f) return -1;
    }
    int v = -1; if (fscanf_s(f, "%d", &v) != 1) v = -1;
    fclose(f);
    return v;
}

static bool ReadNoHide()
{
    char p[MAX_PATH], fb[MAX_PATH];
    PidPaths(p, fb, MAX_PATH, "nohide", "txt");
    return GetFileAttributesA(p)  != INVALID_FILE_ATTRIBUTES
        || GetFileAttributesA(fb) != INVALID_FILE_ATTRIBUTES;
}

static int ReadAutoEnter(int* settleMs)
{
    char p[MAX_PATH], fb[MAX_PATH];
    PidPaths(p, fb, MAX_PATH, "autoenter", "txt");
    FILE* f = nullptr;
    if (fopen_s(&f, p, "r") != 0 || !f) {
        if (fopen_s(&f, fb, "r") != 0 || !f) return 0;
    }
    int slot = 0, ms = 5000;
    int n = fscanf_s(f, "%d %d", &slot, &ms);
    fclose(f);
    if (n < 1) return 0;
    if (n < 2 || ms <= 0) ms = 5000;
    if (settleMs) *settleMs = ms;
    return slot;
}

enum { B_MEMBERLIST = 1<<0, B_SUBCMD = 1<<10, B_SOFTKBD = 1<<19 };

static int ScanAllHeapForVtable(uint32_t vtbl, uint32_t* out, int maxN)
{
    int n = 0;
    MEMORY_BASIC_INFORMATION mbi;
    for (uint8_t* a = (uint8_t*)0x00010000;
         a < (uint8_t*)0x7FFE0000 && n < maxN; )
    {
        if (!VirtualQuery(a, &mbi, sizeof(mbi))) break;
        uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        bool readable =
            mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD);
        if (readable) {
            __try {
                auto* b = (uint8_t*)mbi.BaseAddress;
                for (uint8_t* q = b; q + 4 <= next && n < maxN; q += 4)
                    if (*(uint32_t*)q == vtbl) out[n++] = (uint32_t)(uintptr_t)q;
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
        a = next;
    }
    return n;
}

static void DoStepAction(int step, uint32_t softkeywin, bool firstTime)
{
    switch (step) {
    case 0: {
        int tgt = ReadTargetSlot();
        uint32_t base = (uint32_t)g_uiBase;
        uint32_t ml = ResolveMemberListInner(base);
        if (!ml) ml = g_memberList;

        if (ml && tgt > 0 && g_fnSelRow && g_rowVtbl) __try {
            if (*(uint32_t*)ml == g_rowVtbl) {
                typedef void (__thiscall *SelRowFn)(void*, int, char, int);
                SelRowFn selRow = (SelRowFn)g_fnSelRow;
                selRow((void*)ml, tgt - 1, 1, 1);
                Log("nav: Member List -> select-row slot %d in-proc "
                    "(inner=0x%08X vtbl=0x%08X)%s", tgt, ml, g_rowVtbl,
                    firstTime ? "" : " (retry)");
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {   }

        PostKeyToPol(VK_RETURN);
        break; }
    case 1:
        Log("nav: Log In screen -> PostKey RETURN%s", firstTime ? "" : " (retry)");
        PostKeyToPol(VK_RETURN);
        break;
    case 2:
        Log("nav: Password screen -> PostKey RETURN%s (open soft keyboard)",
            firstTime ? "" : " (retry)");
        PostKeyToPol(VK_RETURN);
        break;
    case 3:
        Log("nav: Soft keyboard (skw=0x%08X) -> in-proc pw + OK",
            softkeywin);
        DoPasswordSeq(softkeywin);
        break;
    case 4:
        if (g_haveTotp) {
            char code[7] = {0};
            if (TotpNow(code)) {
                Log("nav: OTP -> DOWN, RETURN(enable), type, ESC(confirm), DOWN, RETURN(connect)");
                PostKeyToPol(VK_DOWN);   Sleep(280);
                PostKeyToPol(VK_RETURN); Sleep(450);
                for (int i = 0; i < 6 && code[i]; ++i) { PostKeyToPol((WORD)code[i]); Sleep(200); }
                SecureZeroMemory(code, sizeof(code));
                Sleep(400);
                Log("nav: OTP -> ESC (confirm)");
                PostKeyToPol(VK_ESCAPE); Sleep(500);
                Log("nav: OTP -> DOWN (to Connect)");
                PostKeyToPol(VK_DOWN);   Sleep(450);
                Log("nav: OTP -> RETURN (connect)");
                PostKeyToPol(VK_RETURN); Sleep(120);
                PostKeyToPol(VK_RETURN);
                break;
            }
        }
        Log("nav: Connect -> PostKey DOWN, RETURN, RETURN%s",
            firstTime ? "" : " (retry)");
        PostKeyToPol(VK_DOWN);   Sleep(120);
        PostKeyToPol(VK_RETURN); Sleep(80);
        PostKeyToPol(VK_RETURN);
        break;
    }
}

static void LogFrameSlots(uint32_t base)
{
    static uint32_t seenVts[256] = { 0 };
    static int      seenN        = 0;
    static const struct { uint32_t lo, hi; } regions[] = {
        { 0x4E0000, 0x4E2000 },
        { 0x506000, 0x508000 },
    };

    __try {
        for (auto& r : regions) {
            for (uint32_t off = r.lo; off < r.hi; off += 4) {
                uint32_t fr = *(uint32_t*)(base + off);
                if (fr < 0x10000 || fr > 0x7FFE0000) continue;
                uint32_t fvt = *(uint32_t*)fr;
                if (fvt < base || fvt > base + 0x600000) continue;
                uint32_t rva = fvt - base;

                bool known = false;
                for (int i = 0; i < seenN; ++i)
                    if (seenVts[i] == rva) { known = true; break; }
                if (known) continue;
                if (seenN < 256) seenVts[seenN++] = rva;

                uint8_t visByte = *(uint8_t*)(fr + 0xF4);
                Log("FRAME-DISC: slot=app+0x%X this=0x%08X vtbl-rva=0x%X vis=%d",
                    off, fr, rva, (visByte & 1));

                for (int fidx = 0; fidx < 64; ++fidx) {
                    uint32_t v = *(uint32_t*)(fr + fidx * 4);
                    if (v == 5311) {
                        Log("  *** POL-5311 FOUND at +0x%02X (val=0x%08X) ***",
                            fidx * 4, v);
                    }
                    if (fidx < 16 && v != 0)
                        Log("  +0x%02X = 0x%08X (%d)", fidx * 4, v, (int32_t)v);
                }

                for (int row = 0; row < 16; ++row) {
                    char line[160]; int p = 0;
                    p += sprintf_s(line + p, sizeof(line) - p,
                                   "  hex +0x%02X:", row * 16);
                    for (int col = 0; col < 16; ++col) {
                        uint8_t b = *(uint8_t*)(fr + row * 16 + col);
                        p += sprintf_s(line + p, sizeof(line) - p, " %02X", b);
                    }
                    Log("%s", line);
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {   }
}

static void ScanForErrorFrames(uint32_t base)
{
    static const uint32_t kCandidateVts[] = {
        0x3CE96C, 0x3CE960, 0x3CE954,
        0x3CCBDC, 0x3CCBD4, 0x3CCBC8,
    };
    static uint32_t seenThis[64] = { 0 };
    static int      seenN       = 0;

    for (uint32_t vtRva : kCandidateVts) {
        uint32_t hits[32];
        int n = ScanAllHeapForVtable(base + vtRva, hits, 32);
        for (int i = 0; i < n; ++i) {
            uint32_t obj = hits[i];
            if (obj >= base && obj < base + 0x600000) continue;

            bool known = false;
            for (int k = 0; k < seenN; ++k)
                if (seenThis[k] == obj) { known = true; break; }
            if (known) continue;
            if (seenN < 64) seenThis[seenN++] = obj;

            __try {
                uint8_t vis = *(uint8_t*)(obj + 0xF4) & 1;
                Log("ERR-FRAME: vt-rva=0x%X this=0x%08X vis=%d",
                    vtRva, obj, vis);
                for (int fidx = 0; fidx < 32; ++fidx) {
                    uint32_t v = *(uint32_t*)(obj + fidx * 4);
                    if (v == 5311) {
                        Log("  *** POL-5311 FOUND at +0x%02X (val=0x%08X) ***",
                            fidx * 4, v);
                    }
                }
                for (int row = 0; row < 8; ++row) {
                    char line[160]; int p = 0;
                    p += sprintf_s(line + p, sizeof(line) - p,
                                   "  +0x%02X:", row * 16);
                    for (int col = 0; col < 16; ++col) {
                        uint8_t b = *(uint8_t*)(obj + row * 16 + col);
                        p += sprintf_s(line + p, sizeof(line) - p, " %02X", b);
                    }
                    Log("%s", line);
                }
                for (uint32_t off = 0x100; off <= 0x200; off += 4) {
                    uint32_t pstr = *(uint32_t*)(obj + off);
                    if (pstr < 0x00100000 || pstr > 0x7FFE0000) continue;
                    __try {
                        wchar_t nm[40] = { 0 };
                        for (int ci = 0; ci < 39; ++ci) {
                            uint16_t wc = *(uint16_t*)(pstr + ci * 2);
                            if (!wc) break;
                            nm[ci] = (wchar_t)wc;
                        }
                        if (nm[0])
                            Log("  +0x%03X -> string [%.39ls]", off, nm);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Log("ERR-FRAME: SEH dumping obj=0x%08X", obj);
            }
        }
    }
}

static DWORD WINAPI FrameDiscoveryThread(LPVOID)
{
    HMODULE ui = nullptr;
    for (int i = 0; i < 400; ++i) {
        ui = FindPolUi();
        if (ui) break;
        Sleep(150);
    }
    if (!ui) return 0;
    MODULEINFO mi{};
    GetModuleInformation(GetCurrentProcess(), ui, &mi, sizeof(mi));
    uint32_t base = (uint32_t)(uintptr_t)mi.lpBaseOfDll;

    Sleep(750);
    Log("FrameDiscovery: starting 10-min observation (independent thread).");

    for (int t = 0; t < 600 && g_hideEnabled; ++t) {
        LogFrameSlots(base);
        ScanForErrorFrames(base);
        Sleep(1000);
    }
    Log("FrameDiscovery: observation window ended (t=%dx1s).",
        g_hideEnabled ? 600 : -1);
    return 0;
}

static int ZeroScanMask(uint32_t base, uint32_t& softkeywin)
{
    softkeywin = 0;
    int mask = 0;
    __try {
        uint32_t o = *(uint32_t*)(base + 0x5069C0);
        if (o && *(uint32_t*)o == base + 0x3CC4F4 && (*(uint8_t*)(o + 0xF4) & 1))
            mask |= B_MEMBERLIST;
        o = *(uint32_t*)(base + 0x5069C8);
        if (o && *(uint32_t*)o == base + 0x3CCE2C && (*(uint8_t*)(o + 0xF4) & 1))
            mask |= B_SUBCMD;
        o = *(uint32_t*)(base + 0x4E109C);
        if (o && *(uint32_t*)o == base + 0x321CCC && (*(uint8_t*)(o + 0xF4) & 1)) {
            mask |= B_SOFTKBD;
            uint32_t sk = o + 0x2A8;
            if (*(uint32_t*)sk == base + 0x321CB8) softkeywin = sk;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    return mask;
}

static DWORD WINAPI StateObserver(LPVOID)
{
    HMODULE ui = nullptr;
    for (int i = 0; i < 400; ++i) {
        ui = FindPolUi();
        if (ui) break;
        Sleep(150);
    }
    if (!ui) return 0;
    MODULEINFO mi{}; GetModuleInformation(GetCurrentProcess(), ui, &mi, sizeof(mi));
    uint32_t base = (uint32_t)(uintptr_t)mi.lpBaseOfDll;
    Log("Navigator: %s base=0x%08X (zero-scan: per-frame globals)", (const char*)g_uiModuleName, base);

    static const int NEED[5] = { 5, 4, 14, 3, 3 };
    int  step = 0, stable = 0, prevMask = -1;
    bool acted = false, hidden = false; int retries = 0; ULONGLONG actMs = 0;
    const ULONGLONG RETRY_MS = 1500;
    bool noHide = ReadNoHide();
    if (noHide) Log("POL window will stay VISIBLE (nohide flag set).");
    for (int tick = 0; tick < 20000 && step < 5; ++tick)
    {
        ProbeMemberListInner(base);

        FlushSelRowRing(base);

#if DIAG_CAPTURE_FIRE
        FlushFireBpRing(base);
#endif

        uint32_t softkeywin = 0;
        int mask = ZeroScanMask(base, softkeywin);
        if (mask < 0) mask = 0;

#if POL_STASH_WND

        if (!noHide && mask && (!hidden || (tick % 40 == 0)))
            hidden = StashWnd(!hidden);
#else
        (void)hidden;
#endif
        if (mask != prevMask) {
            Log("Navigator: mask=0x%X step=%d skw=0x%08X", mask, step, softkeywin);
            prevMask = mask;
        }
        else if (tick % 200 == 0)
            Log("Navigator: alive tick=%d mask=0x%X step=%d", tick, mask, step);

        bool present =
            step==0 ? ((mask & B_MEMBERLIST) != 0) :
            step==1 ? ((mask & B_SUBCMD) != 0) :
            step==2 ? (!(mask & B_SUBCMD) && !(mask & B_SOFTKBD)) :
            step==3 ? ((mask & B_SOFTKBD) && softkeywin != 0) :
            step==4 ? ((mask & B_SOFTKBD) == 0) : false;
        bool gone =
            step==0 ? ((mask & B_SUBCMD)  != 0) :
            step==1 ? ((mask & B_SUBCMD)  == 0) :
            step==2 ? ((mask & B_SOFTKBD) != 0) :
            step==3 ? ((mask & B_SOFTKBD) == 0) :
            false;

        if (!acted) {
            stable = present ? stable + 1 : 0;
            if (stable >= NEED[step]) {
                DoStepAction(step, softkeywin, true);
                acted = true; retries = 0; actMs = GetTickCount64();
                stable = 0;
                Sleep(150);
            }
        } else if (gone) {
            Log("nav: step %d complete (transitioned).", step);
            ++step; acted = false; stable = 0;
            static const char* S[6] = { "MEMBERLIST","LOGIN","PASSWORD",
                                        "SOFTKBD","CONNECT","DONE" };
            WriteStatus(S[step <= 5 ? step : 5],
                        step >= 5 ? "logged in" : "screen advanced");
            Sleep(150);
        } else if (step == 4) {
            Log("nav: Connect issued; sequence done.");
            ++step;
            WriteStatus("CONNECT", "connect issued, awaiting login");
            g_hideEnabled = false;
            RestorePolWnd();
            TeardownHooks();
            Log("hide: disabled (DONE) — game window will be visible.");
        } else if (GetTickCount64() - actMs >= RETRY_MS) {
#if DIAG_CAPTURE_FIRE
            static ULONGLONG lastReminder = 0;
            ULONGLONG now = GetTickCount64();
            if (now - lastReminder > 15000) {
                Log("nav: DIAG waiting for user input on step %d "
                    "(focus POL window, press Enter)", step);
                lastReminder = now;
            }
            actMs = now;
#else
            if (++retries <= 19) {
                Log("nav: step %d no transition in %llums -> retry %d",
                    step, RETRY_MS, retries);
                WriteStatus("RETRY", "re-attempting current screen");
                DoStepAction(step, softkeywin, false);
                actMs = GetTickCount64();
            } else {
                Log("nav: step %d failed (no transition after %d retries).",
                    step, retries);
                WriteStatus("FAILED", "no transition after retries");
                break;
            }
#endif
        }
        Sleep(25);
    }
    Log("Navigator: sequence finished at step %d.", step);
    bool ok = step >= 5;
    WriteStatus(ok ? "CONNECT" : "FAILED",
                ok ? "connect issued, awaiting login" : "ended before connect");
    if (ok) { g_hideEnabled = false; RestorePolWnd(); TeardownHooks(); }

    if (ok) {
        CloseHandle(CreateThread(nullptr, 0, PostConnectWatchdog, nullptr, 0, nullptr));
    }

#if !DIAG_CAPTURE_FIRE
    if (!ok) {
        Log("Navigator: in-process advance failed; terminating pol.exe "
            "(no keystroke fallback by user policy).");
        Sleep(750);
        TerminateProcess(GetCurrentProcess(), 1);
    }
#else
    Log("Navigator: DIAG mode finished (ok=%d). NOT terminating pol.exe; "
        "close POL manually when done capturing.", ok ? 1 : 0);
#endif
    return 0;
}

static DWORD WINAPI Worker(LPVOID)
{
    Log("Trees.dll injected (stage 4a+: chain hook + HW-bp ABI capture).");
    WriteStatus("INJECTED", "helper attached");

    HMODULE ui = nullptr;
    for (int i = 0; i < 400; ++i) {
        ui = FindPolUi();
        if (ui) break;
        Sleep(150);
    }
    if (!ui) { Log("ERROR: POL UI module (app.dll / appEU.dll) never loaded."); return 0; }

    MODULEINFO mi{};
    GetModuleInformation(GetCurrentProcess(), ui, &mi, sizeof(mi));
    auto base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);

    uint8_t* hit = ScanModule(ui, SIG_SOFTKEY_HANDLER);
    if (!hit) { Log("FAIL: soft-key handler signature not found."); return 0; }
    Log("soft-key handler @ 0x%08X (%s+0x%X)",
        (unsigned)(uintptr_t)hit, (const char*)g_uiModuleName, (unsigned)((uintptr_t)hit - base));

    static const uint8_t okpat[] = { 0x8B, 0xCE, 0x6A, 0x01, 0xE8 };
    uint8_t* ok = nullptr;
    for (uint8_t* p = hit; p < hit + 0x400; ++p)
        if (!memcmp(p, okpat, sizeof(okpat))) { ok = p; break; }
    if (!ok) { Log("FAIL: OK-dispatch pattern not found."); return 0; }

    uint8_t* callBfc = ok + 4;
    int32_t relBfc; memcpy(&relBfc, callBfc + 1, 4);
    g_fnBfc = (uintptr_t)(callBfc + 5) + relBfc;

    uint8_t* callApply = ok - 5;
    if (*callApply == 0xE8) {
        int32_t relA; memcpy(&relA, callApply + 1, 4);
        g_fnApply = (uintptr_t)(callApply + 5) + relA;
    }

    Log("OK funcs: FUN_04647645=0x%08X (+0x%X)  FUN_04692bfc=0x%08X (+0x%X)",
        (unsigned)g_fnApply, (unsigned)(g_fnApply - base),
        (unsigned)g_fnBfc,   (unsigned)(g_fnBfc - base));
    g_uiBase = base;

    g_fnSelRow = (uintptr_t)ScanModule(ui, SIG_SELECT_ROW);
    if (g_fnSelRow)
        Log("select-row @ 0x%08X (%s+0x%X)", (unsigned)g_fnSelRow,
            (const char*)g_uiModuleName, (unsigned)(g_fnSelRow - base));
    else {
        g_fnSelRow = base + 0x75102;
        Log("WARN: select-row signature not found; fallback %s+0x75102.",
            (const char*)g_uiModuleName);
    }

    g_veh = AddVectoredExceptionHandler(1, Veh);
    g_bp[2] = g_fnSelRow;
    SetHwBp(2, g_bp[2]);
    Log("member-list select-row capture armed (HW-bp 0x%08X = %s+0x%X).",
        (unsigned)g_fnSelRow, (const char*)g_uiModuleName,
        (unsigned)(g_fnSelRow - base));

#if DIAG_CAPTURE_FIRE
    g_bp[0] = base + 0x6B62;
    SetHwBp(0, g_bp[0]);
    Log("DIAG_CAPTURE_FIRE: fire-by-name capture armed (HW-bp "
        "app.dll+0x6B62). Navigator auto-advance is suppressed; "
        "press Enter manually on each login screen.");
#endif

    bool armed = LoadCred();
    LoadTotp();
    Log("Worker(lean): %s%s. Navigator drives the rest hook-free.",
        armed ? "credential ARMED" : "no cred.bin (Navigator will stall at pw)",
        g_haveTotp ? " +TOTP" : "");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hMod);
        RotateLogIfHuge();
        {
            char p[MAX_PATH], fb[MAX_PATH];
            PidPaths(p, fb, MAX_PATH, "nohide", "txt");
            if (GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES ||
                GetFileAttributesA(fb) != INVALID_FILE_ATTRIBUTES)
                g_hideEnabled = false;
        }
        {
            int ms = 5000;
            int s = ReadAutoEnter(&ms);
            if (s > 0) { g_autoEnter = true; g_charSlot = s; g_settleMs = ms; }
        }
        {
            char fl[MAX_PATH]; DllSibling(fl, MAX_PATH, "forest_fastlogin.txt");
            if (GetFileAttributesA(fl) != INVALID_FILE_ATTRIBUTES) {
                InitializeCriticalSection(&g_flCs);
                BuildFastResp();
                g_fastLogin = true;
            }
        }
        InitRegistryDiagnostic();
        InitKernelLevelDiagnostic();
        InstallFakeFocusAllModules(hMod);
        InstallCbtHooks(hMod);
        CloseHandle(CreateThread(nullptr, 0, AttachEnumThread, nullptr, 0, nullptr));
        CloseHandle(CreateThread(nullptr, 0, CbtReinstallThread, (LPVOID)hMod, 0, nullptr));
        CloseHandle(CreateThread(nullptr, 0, WinEvPumpThread, nullptr, 0, nullptr));
        CloseHandle(CreateThread(nullptr, 0, EarlyStashThread, nullptr, 0, nullptr));
        CloseHandle(CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr));
        CloseHandle(CreateThread(nullptr, 0, StateObserver, nullptr, 0, nullptr));
        CloseHandle(CreateThread(nullptr, 0, FrameDiscoveryThread, nullptr, 0, nullptr));
        CloseHandle(CreateThread(nullptr, 0, FakeFocusInstallThread, nullptr, 0, nullptr));
    }
    return TRUE;
}
