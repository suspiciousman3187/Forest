#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "winmm.lib")

typedef LONG (NTAPI *NtQIP_t)(HANDLE, int, PVOID, ULONG, PULONG);
struct PBI32 {
    LONG ExitStatus; PVOID PebBaseAddress; ULONG_PTR AffinityMask;
    LONG BasePriority; ULONG_PTR UniqueProcessId; ULONG_PTR InheritedFrom;
};

static bool ProcEnvHasMarker(DWORD pid, const char* marker)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) return false;
    bool found = false;
    static NtQIP_t qip = (NtQIP_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (qip)
    {
        PBI32 pbi{}; SIZE_T br = 0;
        if (qip(h, 0 , &pbi, sizeof(pbi), nullptr) == 0
            && pbi.PebBaseAddress)
        {
            DWORD pp = 0, env = 0;

            if (ReadProcessMemory(h, (BYTE*)pbi.PebBaseAddress + 0x10, &pp, 4, &br) && pp &&
                ReadProcessMemory(h, (BYTE*)(uintptr_t)pp + 0x48, &env, 4, &br) && env)
            {
                std::vector<wchar_t> buf(32768);
                if (ReadProcessMemory(h, (void*)(uintptr_t)env, buf.data(),
                                      buf.size() * sizeof(wchar_t), &br) && br)
                {
                    std::wstring want = L"FOREST_TAG=";
                    for (const char* c = marker; *c; ++c) want += (wchar_t)*c;
                    std::wstring hay(buf.data(), br / sizeof(wchar_t));
                    found = hay.find(want) != std::wstring::npos;
                }
            }
        }
    }
    CloseHandle(h);
    return found;
}

static volatile DWORD g_stashPid    = 0;
static volatile LONG  g_stashRun    = 1;
static ULONGLONG      g_stashT0     = 0;
static HWND           g_stashSeen[64] = {0};
static volatile LONG  g_stashSeenN  = 0;
static CRITICAL_SECTION g_stashCs;

static void DumpHwnd(const char* tag, HWND h)
{
    char t[64] = {0};
    GetWindowTextA(h, t, sizeof(t));
    char cls[64] = {0};
    GetClassNameA(h, cls, sizeof(cls));
    LONG s  = GetWindowLongA(h, GWL_STYLE);
    LONG sx = GetWindowLongA(h, GWL_EXSTYLE);
    RECT r{}; GetWindowRect(h, &r);
    HWND own = GetWindow(h, GW_OWNER);
    printf("[stash] %s @%llums hwnd=0x%p title=[%s] class=[%s] "
           "style=0x%08lX exstyle=0x%08lX rect=%ldx%ld+%ld+%ld owner=0x%p\n",
           tag, GetTickCount64() - g_stashT0, h, t, cls,
           (unsigned long)s, (unsigned long)sx,
           r.right - r.left, r.bottom - r.top, r.left, r.top, own);
    fflush(stdout);
}

static bool LooksLikePolMainWindow(HWND h)
{
    char cls[64] = {0};
    GetClassNameA(h, cls, sizeof(cls));
    if (_stricmp(cls, "SystemUserAdapterWindowClass") == 0) return false;
    if (_stricmp(cls, "IME") == 0) return false;
    if (_stricmp(cls, "MSCTFIME UI") == 0) return false;
    if (_stricmp(cls, "Default IME") == 0) return false;
    RECT r{}; GetWindowRect(h, &r);
    LONG w = r.right - r.left, htall = r.bottom - r.top;
    if (w < 200 || htall < 100) return false;
    return true;
}

static bool AlreadyStashed(HWND h)
{
    EnterCriticalSection(&g_stashCs);
    for (int i = 0; i < g_stashSeenN; ++i)
        if (g_stashSeen[i] == h) { LeaveCriticalSection(&g_stashCs); return true; }
    if (g_stashSeenN < 64) g_stashSeen[g_stashSeenN++] = h;
    LeaveCriticalSection(&g_stashCs);
    return false;
}

static void StashHwnd(HWND h, const char* via)
{
    if (!h) return;
    if (AlreadyStashed(h)) return;
    DumpHwnd("STASH", h);
    SetWindowPos(h, HWND_BOTTOM, -32000, -32000, 0, 0,
                 SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOZORDER);
    printf("[stash] moved via %s\n", via);
    fflush(stdout);
}

static void CALLBACK WinEventProc(HWINEVENTHOOK, DWORD ev, HWND hwnd,
                                  LONG idObject, LONG, DWORD, DWORD)
{
    if (!g_stashRun || !hwnd || idObject != OBJID_WINDOW) return;
    DWORD wpid = 0;
    GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid != g_stashPid) return;
    if (!LooksLikePolMainWindow(hwnd)) {
        char tag[32];
        sprintf_s(tag, "ignore ev=0x%04X", ev);
        DumpHwnd(tag, hwnd);
        return;
    }
    char via[32];
    sprintf_s(via, "winevent(0x%04X)", ev);
    StashHwnd(hwnd, via);
}

static BOOL CALLBACK StashAllCb(HWND h, LPARAM lp)
{
    DWORD pid = (DWORD)lp;
    DWORD wpid = 0;
    GetWindowThreadProcessId(h, &wpid);
    if (wpid != pid) return TRUE;
    if (LooksLikePolMainWindow(h)) StashHwnd(h, "poll");
    return TRUE;
}

static DWORD WINAPI StashEarlyThread(LPVOID lp)
{
    g_stashPid = (DWORD)(uintptr_t)lp;
    g_stashT0  = GetTickCount64();
    InitializeCriticalSection(&g_stashCs);
    timeBeginPeriod(1);

    HWINEVENTHOOK hk = SetWinEventHook(
        EVENT_MIN, EVENT_MAX, NULL,
        WinEventProc, g_stashPid, 0,
        WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    if (!hk)
        printf("[stash] SetWinEventHook failed (%lu)\n", GetLastError());

    while (g_stashRun && GetTickCount64() - g_stashT0 < 30000)
    {
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        EnumWindows(StashAllCb, (LPARAM)g_stashPid);
        Sleep(1);
    }

    if (hk) UnhookWinEvent(hk);
    timeEndPeriod(1);
    DeleteCriticalSection(&g_stashCs);
    return 0;
}

static std::set<DWORD> SnapshotPol()
{
    std::set<DWORD> pids;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32 pe{ sizeof(pe) };
    for (BOOL ok = Process32First(s, &pe); ok; ok = Process32Next(s, &pe))
        if (_stricmp(pe.szExeFile, "pol.exe") == 0) pids.insert(pe.th32ProcessID);
    CloseHandle(s);
    return pids;
}

static bool ModuleLoaded(DWORD pid, const char* mod)
{
    HANDLE s = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (s == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 me{ sizeof(me) };
    bool found = false;
    for (BOOL ok = Module32First(s, &me); ok; ok = Module32Next(s, &me))
        if (_stricmp(me.szModule, mod) == 0) { found = true; break; }
    CloseHandle(s);
    return found;
}

static bool Inject(DWORD pid, const char* dllFull)
{
    HANDLE p = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!p) { printf("OpenProcess failed (%lu) - run elevated?\n", GetLastError()); return false; }

    SIZE_T n = strlen(dllFull) + 1;
    void* rem = VirtualAllocEx(p, nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem || !WriteProcessMemory(p, rem, dllFull, n, nullptr))
    { printf("alloc/write failed (%lu)\n", GetLastError()); CloseHandle(p); return false; }

    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE th = CreateRemoteThread(p, nullptr, 0, loadLib, rem, 0, nullptr);
    if (!th) { printf("CreateRemoteThread failed (%lu)\n", GetLastError()); CloseHandle(p); return false; }

    WaitForSingleObject(th, 5000);
    DWORD ec = 0; GetExitCodeThread(th, &ec);
    VirtualFreeEx(p, rem, 0, MEM_RELEASE);
    CloseHandle(th); CloseHandle(p);
    printf("injected into pid %lu (LoadLibraryA -> 0x%08X). See trees.log.\n", pid, ec);
    return ec != 0;
}

static void WritePerPid(const char* dllDir, DWORD pid,
                        const char* slot, const char* credSrc, bool noHide,
                        const char* totpSrc)
{
    char p[MAX_PATH];
    if (slot && *slot) {
        sprintf_s(p, "%s\\slot_%lu.txt", dllDir, pid);
        FILE* f = nullptr;
        if (fopen_s(&f, p, "w") == 0 && f) { fputs(slot, f); fclose(f);
            printf("wrote %s\n", p); }
    }
    if (credSrc && *credSrc) {
        char dst[MAX_PATH];
        sprintf_s(dst, "%s\\cred_%lu.bin", dllDir, pid);
        if (CopyFileA(credSrc, dst, FALSE)) printf("wrote %s\n", dst);
        else printf("cred copy failed (%lu): %s -> %s\n",
                    GetLastError(), credSrc, dst);
    }
    if (totpSrc && *totpSrc) {
        char dst[MAX_PATH];
        sprintf_s(dst, "%s\\totp_%lu.bin", dllDir, pid);
        if (CopyFileA(totpSrc, dst, FALSE)) printf("wrote %s\n", dst);
        else printf("totp copy failed (%lu): %s -> %s\n",
                    GetLastError(), totpSrc, dst);
    }
    if (noHide) {
        sprintf_s(p, "%s\\nohide_%lu.txt", dllDir, pid);
        FILE* f = nullptr;
        if (fopen_s(&f, p, "w") == 0 && f) { fputs("1", f); fclose(f);
            printf("wrote %s (POL window will stay visible)\n", p); }
    }
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("usage: waitinject <Trees.dll> [slot] [credSrc] "
               "[hide|nohide] [marker] [nologin] [totpSrc]\n");
        return 1;
    }
    char dll[MAX_PATH];
    if (!GetFullPathNameA(argv[1], MAX_PATH, dll, nullptr)) { printf("bad dll path\n"); return 1; }
    const char* slot    = argc > 2 ? argv[2] : nullptr;
    const char* credSrc = argc > 3 ? argv[3] : nullptr;
    bool noHide = argc > 4 && _stricmp(argv[4], "nohide") == 0;

    const char* marker = (argc > 5 && argv[5][0]) ? argv[5] : nullptr;

    bool noLogin = argc > 6 && _stricmp(argv[6], "nologin") == 0;

    const char* totpSrc = (argc > 7 && argv[7][0]) ? argv[7] : nullptr;
    char dllDir[MAX_PATH]; strcpy_s(dllDir, dll);
    if (char* s = strrchr(dllDir, '\\')) *s = 0;

    auto baseline = SnapshotPol();
    printf("Baseline: %zu existing pol.exe (live characters - WILL NOT be touched).\n",
           baseline.size());
    printf("READY (waiting for a NEW pol.exe%s)\n",
           marker ? ", marker-matched" : "");
    fflush(stdout);

    DWORD target = 0;
    for (int i = 0; i < 1200 && !target; ++i)
    {
        for (DWORD pid : SnapshotPol())
        {
            if (baseline.count(pid)) continue;
            if (marker)
            {

                if (ProcEnvHasMarker(pid, marker)) { target = pid; break; }
            }
            else { target = pid; break; }
        }
        if (!target) Sleep(50);
    }
    if (!target) { printf("TIMEOUT waiting for a new pol.exe.\n"); return 1; }
    printf("CAPTURED_PID=%lu\n", target);
    fflush(stdout);

    if (!noHide)
        CloseHandle(CreateThread(nullptr, 0, StashEarlyThread,
                                 (LPVOID)(uintptr_t)target, 0, nullptr));

    if (noLogin)
    {

        printf("NO-AUTO: pid captured; skipping inject (manual login).\n");
        printf("INJECT_OK\n");
        fflush(stdout);
        return 0;
    }

    WritePerPid(dllDir, target, slot, credSrc, noHide, totpSrc);
    Sleep(50);
    bool ok = Inject(target, dll);
    printf(ok ? "INJECT_OK\n" : "INJECT_FAIL\n");
    fflush(stdout);
    InterlockedExchange(&g_stashRun, 0);
    Sleep(50);
    return ok ? 0 : 1;
}
