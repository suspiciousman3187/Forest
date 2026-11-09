// PolProbe.dll: read-only diagnostic for Forest's login navigator.
//
// Injected into pol.exe (waitinject.exe PolProbe.dll "" "" nohide), it logs
// which POL UI objects exist while the login screens are stepped through by
// hand, so screen detection can be rebuilt after a POL patch moves things.
// It never writes POL memory, never sends input and never touches the window.
//
// Output: polprobe_<pid>.log next to this DLL.

#include <windows.h>
#include <psapi.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "../PolClasses.h"
#include "../PolRtti.h"
#include "../SafeMem.h"

#pragma comment(lib, "psapi.lib")

namespace {

constexpr int      kTickMs         = 500;
constexpr int      kRunMinutes     = 20;
constexpr int      kHeapEveryTicks = 4;
constexpr uint32_t kSnapBytes      = 0x400;
constexpr int      kSnapDwords     = kSnapBytes / 4;
constexpr int      kNumClasses     = (int)(sizeof(polclass::kLoginFlow) / sizeof(polclass::kLoginFlow[0]));

char      g_logPath[MAX_PATH];
uintptr_t g_base = 0;
uint32_t  g_size = 0;
uint32_t  g_dataLo = 0, g_dataHi = 0;
uint32_t  g_classVt[kNumClasses];   // absolute vtable address per kLoginFlow entry, 0 if absent

void Log(const char* fmt, ...)
{
    FILE* f = nullptr;
    if (fopen_s(&f, g_logPath, "a") != 0 || !f) return;
    SYSTEMTIME t; GetLocalTime(&t);
    fprintf(f, "[%02d:%02d:%02d.%03d] ", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f);
    fclose(f);
}

void RefreshReadable() { safemem::Refresh(); }
bool SafeRead32(uintptr_t addr, uint32_t* out) { return safemem::Read32(addr, out); }
bool SafeCopy(uintptr_t addr, void* dst, size_t n) { return safemem::Copy(addr, dst, n); }

bool InModule(uintptr_t a) { return a >= g_base && a < g_base + g_size; }
bool Plausible(uint32_t p) { return p >= 0x10000 && p < 0x7FFE0000; }

// RTTI name of the class whose primary vtable is `vt`, via vt[-1] -> COL -> TypeDescriptor.
bool VtableClassName(uint32_t vt, char* out, size_t cap)
{
    uint32_t col, sig, off, td;
    if (!InModule(vt) || !SafeRead32(vt - 4, &col) || !InModule(col)) return false;
    if (!SafeRead32(col, &sig) || sig != 0) return false;
    if (!SafeRead32(col + 4, &off) || off != 0) return false;
    if (!SafeRead32(col + 12, &td) || !InModule(td)) return false;
    if (!SafeCopy(td + 8, out, cap - 1)) return false;
    out[cap - 1] = 0;
    return out[0] == '.' && out[1] == '?' && out[2] == 'A';
}

int ClassIndexOfVtable(uint32_t vt)
{
    for (int i = 0; i < kNumClasses; ++i)
        if (g_classVt[i] && g_classVt[i] == vt) return i;
    return -1;
}

// ---- 1. Global slots in the UI module's .data that hold POL objects -------

struct SlotRec { uint32_t rva, obj, vt; bool embedded; };
std::vector<SlotRec> g_prevSlots;
std::vector<uint16_t> g_slotChanges;   // per .data dword: how often it changed
constexpr uint16_t kSlotMuteAfter = 20;

void ScanGlobals(bool first)
{
    std::vector<SlotRec> cur;
    for (uint32_t r = g_dataLo; r + 4 <= g_dataHi; r += 4) {
        uint32_t d;
        if (!SafeRead32(g_base + r, &d) || d == 0) continue;
        char nm[96];
        if (InModule(d)) {
            // An object embedded in .data: its first dword is a vtable. RTTI
            // TypeDescriptors also look like this (type_info objects); skip them.
            if (VtableClassName(d, nm, sizeof(nm)) && strcmp(nm, ".?AVtype_info@@") != 0)
                cur.push_back({ r, (uint32_t)(g_base + r), d, true });
        } else if (Plausible(d)) {
            uint32_t vt;
            if (SafeRead32(d, &vt) && VtableClassName(vt, nm, sizeof(nm)))
                cur.push_back({ r, d, vt, false });
        }
    }

    if (g_slotChanges.empty()) g_slotChanges.assign((g_dataHi - g_dataLo) / 4 + 1, 0);
    size_t i = 0, j = 0;
    char nm[96], was[96];
    auto changed = [&](uint32_t rva) -> bool {
        uint16_t& c = g_slotChanges[(rva - g_dataLo) / 4];
        if (c == kSlotMuteAfter) return false;
        if (++c == kSlotMuteAfter) { Log("SLOT +0x%06X muted (changes too often)", rva); return false; }
        return true;
    };
    while (i < g_prevSlots.size() || j < cur.size()) {
        const SlotRec* p = i < g_prevSlots.size() ? &g_prevSlots[i] : nullptr;
        const SlotRec* c = j < cur.size() ? &cur[j] : nullptr;
        if (c && (!p || c->rva < p->rva)) {
            if (first || changed(c->rva)) {
                VtableClassName(c->vt, nm, sizeof(nm));
                Log("SLOT +0x%06X %s obj=0x%08X %s%s", c->rva, c->embedded ? "EMBED" : "PTR  ",
                    c->obj, nm, first ? "" : "   <-- NEW");
            }
            ++j;
        } else if (p && (!c || p->rva < c->rva)) {
            if (changed(p->rva)) {
                VtableClassName(p->vt, was, sizeof(was));
                Log("SLOT +0x%06X cleared (was obj=0x%08X %s)", p->rva, p->obj, was);
            }
            ++i;
        } else {
            if ((p->obj != c->obj || p->vt != c->vt) && changed(c->rva)) {
                VtableClassName(p->vt, was, sizeof(was));
                VtableClassName(c->vt, nm, sizeof(nm));
                Log("SLOT +0x%06X changed obj=0x%08X %s  (was obj=0x%08X %s)",
                    c->rva, c->obj, nm, p->obj, was);
            }
            ++i; ++j;
        }
    }
    g_prevSlots.swap(cur);
}

// ---- 2. Login-flow objects anywhere in the heap, with byte-level diffs ----

struct Tracked {
    uint32_t obj, vt;
    int      cls;
    uint32_t snap[kSnapDwords];
    uint8_t  churn[kSnapDwords];
    bool     muted[kSnapDwords];
};
std::vector<Tracked> g_tracked;

void Dump(const Tracked& t)
{
    for (uint32_t row = 0; row < kSnapBytes; row += 16) {
        const uint8_t* b = reinterpret_cast<const uint8_t*>(t.snap) + row;
        Log("    +0x%03X: %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X",
            row, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    }
}

void Track(uint32_t obj, uint32_t vt, int cls, const char* how)
{
    for (auto& t : g_tracked) if (t.obj == obj) return;
    Tracked t{};
    t.obj = obj; t.vt = vt; t.cls = cls;
    if (!SafeCopy(obj, t.snap, kSnapBytes)) return;
    Log("OBJ  NEW %-17s obj=0x%08X vt=+0x%06X (found via %s)",
        polclass::kLoginFlow[cls].key, obj, vt - (uint32_t)g_base, how);
    Dump(t);
    g_tracked.push_back(t);
}

int ScanRegionForVtables(uintptr_t lo, size_t n, uint32_t* hits, int cap)
{
    int found = 0;
    __try {
        auto* p = reinterpret_cast<const uint32_t*>(lo);
        for (size_t k = 0; k < n / 4 && found < cap; ++k) {
            uint32_t v = p[k];
            if (!InModule(v)) continue;
            if (ClassIndexOfVtable(v) >= 0) hits[found++] = (uint32_t)(lo + k * 4);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return found;
}

void ScanHeap()
{
    MEMORY_BASIC_INFORMATION mbi;
    for (uintptr_t a = 0x10000; a < 0x7FFE0000; a = (uintptr_t)mbi.BaseAddress + mbi.RegionSize) {
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(a), &mbi, sizeof(mbi))) break;
        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE) continue;
        if (!(mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_GUARD)) continue;
        uint32_t hits[64];
        int n = ScanRegionForVtables((uintptr_t)mbi.BaseAddress, mbi.RegionSize, hits, 64);
        for (int k = 0; k < n; ++k) {
            // Re-read: the object may have changed since the region scan.
            uint32_t vt;
            if (!SafeRead32(hits[k], &vt)) continue;
            int cls = ClassIndexOfVtable(vt);
            if (cls >= 0) Track(hits[k], vt, cls, "heap");
        }
    }
}

void TrackGlobalsOfInterest()
{
    for (const auto& s : g_prevSlots) {
        int cls = ClassIndexOfVtable(s.vt);
        if (cls >= 0) Track(s.obj, s.vt, cls, "global slot");
    }
}

void DiffTracked()
{
    for (size_t i = 0; i < g_tracked.size();) {
        Tracked& t = g_tracked[i];
        uint32_t now[kSnapDwords];
        if (!SafeCopy(t.obj, now, kSnapBytes) || now[0] != t.vt) {
            Log("OBJ  GONE %-17s obj=0x%08X", polclass::kLoginFlow[t.cls].key, t.obj);
            g_tracked.erase(g_tracked.begin() + i);
            continue;
        }
        int lines = 0;
        for (int k = 0; k < kSnapDwords; ++k) {
            if (now[k] == t.snap[k]) { t.churn[k] = 0; continue; }
            if (!t.muted[k] && ++t.churn[k] > 6) {
                t.muted[k] = true;
                Log("  ~ %-17s +0x%03X muted (changes every tick)", polclass::kLoginFlow[t.cls].key, k * 4);
            }
            if (!t.muted[k] && lines++ < 24)
                Log("  ~ %-17s obj=0x%08X +0x%03X: %08X -> %08X",
                    polclass::kLoginFlow[t.cls].key, t.obj, k * 4, t.snap[k], now[k]);
            t.snap[k] = now[k];
        }
        ++i;
    }
}

// ---- 3. Pointer chains between login-flow objects -------------------------

struct Pair { uint32_t a, b; };
std::vector<Pair> g_linked;

bool LooksLikeObject(uint32_t p)
{
    uint32_t vt;
    return Plausible(p) && SafeRead32(p, &vt) && InModule(vt);
}

bool FindChain(uint32_t from, uint32_t to, int* offs, int* depth)
{
    uint32_t p, q, r;
    for (uint32_t a = 0; a < 0x400; a += 4)
        if (SafeRead32(from + a, &p) && p == to) { offs[0] = a; *depth = 1; return true; }
    for (uint32_t a = 0; a < 0x400; a += 4) {
        if (!SafeRead32(from + a, &p) || !LooksLikeObject(p)) continue;
        for (uint32_t b = 0; b < 0x300; b += 4)
            if (SafeRead32(p + b, &q) && q == to) { offs[0] = a; offs[1] = b; *depth = 2; return true; }
    }
    for (uint32_t a = 0; a < 0x400; a += 4) {
        if (!SafeRead32(from + a, &p) || !LooksLikeObject(p)) continue;
        for (uint32_t b = 0; b < 0x300; b += 4) {
            if (!SafeRead32(p + b, &q) || !LooksLikeObject(q)) continue;
            for (uint32_t c = 0; c < 0x200; c += 4)
                if (SafeRead32(q + c, &r) && r == to) {
                    offs[0] = a; offs[1] = b; offs[2] = c; *depth = 3; return true;
                }
        }
    }
    return false;
}

void LinkTracked()
{
    for (const auto& A : g_tracked)
        for (const auto& B : g_tracked) {
            if (A.obj == B.obj) continue;
            bool done = false;
            for (const auto& l : g_linked) if (l.a == A.obj && l.b == B.obj) { done = true; break; }
            if (done) continue;
            g_linked.push_back({ A.obj, B.obj });
            int offs[3] = { 0 }, depth = 0;
            if (!FindChain(A.obj, B.obj, offs, &depth)) continue;
            char chain[64];
            if (depth == 1) sprintf_s(chain, "+0x%X", offs[0]);
            else if (depth == 2) sprintf_s(chain, "+0x%X -> +0x%X", offs[0], offs[1]);
            else sprintf_s(chain, "+0x%X -> +0x%X -> +0x%X", offs[0], offs[1], offs[2]);
            Log("LINK %s(0x%08X) %s -> %s(0x%08X)",
                polclass::kLoginFlow[A.cls].key, A.obj, chain,
                polclass::kLoginFlow[B.cls].key, B.obj);
        }
}

// ---- Setup -----------------------------------------------------------------

HMODULE WaitForUiModule(const char** nameOut)
{
    static const char* kNames[] = { "app.dll", "appEU.dll", "appJP.dll" };
    for (int tries = 0; tries < 600; ++tries) {
        for (auto n : kNames)
            if (HMODULE h = GetModuleHandleA(n)) { *nameOut = n; return h; }
        Sleep(100);
    }
    return nullptr;
}

DWORD WINAPI ProbeThread(LPVOID)
{
    Log("=== PolProbe start, pid=%lu (read-only: no writes, no input) ===", GetCurrentProcessId());
    const char* uiName = "?";
    HMODULE ui = WaitForUiModule(&uiName);
    if (!ui) { Log("ERROR: POL UI module never loaded."); return 0; }

    MODULEINFO mi{};
    GetModuleInformation(GetCurrentProcess(), ui, &mi, sizeof(mi));
    g_base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
    g_size = mi.SizeOfImage;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
        g_base + reinterpret_cast<const IMAGE_DOS_HEADER*>(g_base)->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        if (memcmp(sec[i].Name, ".data", 6) == 0) {
            g_dataLo = sec[i].VirtualAddress;
            g_dataHi = g_dataLo + sec[i].Misc.VirtualSize;
        }
    Log("UI module %s base=0x%08X size=0x%X timestamp=0x%08X .data=+0x%X..+0x%X",
        uiName, (unsigned)g_base, g_size, nt->FileHeader.TimeDateStamp, g_dataLo, g_dataHi);

    RefreshReadable();
    polrtti::Image view{ reinterpret_cast<const uint8_t*>(g_base), g_size, g_base };
    for (int i = 0; i < kNumClasses; ++i) {
        uint32_t rva = polrtti::FindVtable(view, polclass::kLoginFlow[i].rtti);
        g_classVt[i] = rva ? (uint32_t)(g_base + rva) : 0;
        Log("CLASS %-17s %-50s vt=+0x%06X", polclass::kLoginFlow[i].key,
            polclass::kLoginFlow[i].rtti, rva);
    }

    const int ticks = kRunMinutes * 60 * 1000 / kTickMs;
    for (int tick = 0; tick < ticks; ++tick) {
        RefreshReadable();
        ScanGlobals(tick == 0);
        TrackGlobalsOfInterest();
        if (tick % kHeapEveryTicks == 0) ScanHeap();
        DiffTracked();
        LinkTracked();
        Sleep(kTickMs);
    }
    Log("=== PolProbe finished (%d min) ===", kRunMinutes);
    return 0;
}

} // namespace

BOOL APIENTRY DllMain(HMODULE self, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(self);
        GetModuleFileNameA(self, g_logPath, MAX_PATH);
        if (char* slash = strrchr(g_logPath, '\\'))
            sprintf_s(slash + 1, MAX_PATH - (slash + 1 - g_logPath), "polprobe_%lu.log",
                      GetCurrentProcessId());
        CloseHandle(CreateThread(nullptr, 0, ProbeThread, nullptr, 0, nullptr));
    }
    return TRUE;
}
