#pragma once
// Reading memory inside pol.exe without side effects.
//
// SEH alone is not enough: touching a thread's stack guard page raises an
// exception we would catch, but it also silently consumes the guard, and that
// thread can crash later when its stack grows. So reads are first checked
// against a snapshot of committed, readable, non-guard regions.
//
// Not thread-safe: refresh and read from one thread.

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>

namespace safemem {

struct Range { uintptr_t lo, hi; };

inline std::vector<Range>& Ranges() { static std::vector<Range> r; return r; }

// Re-snapshot readable memory. Call once per scan pass.
inline void Refresh()
{
    constexpr DWORD kReadable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    auto& r = Ranges();
    r.clear();
    MEMORY_BASIC_INFORMATION mbi;
    for (uintptr_t a = 0x10000; a < 0x7FFE0000; a = (uintptr_t)mbi.BaseAddress + mbi.RegionSize) {
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(a), &mbi, sizeof(mbi))) break;
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & kReadable) || (mbi.Protect & PAGE_GUARD)) continue;
        uintptr_t lo = (uintptr_t)mbi.BaseAddress, hi = lo + mbi.RegionSize;
        if (!r.empty() && r.back().hi == lo) r.back().hi = hi;
        else r.push_back({ lo, hi });
    }
}

inline bool Readable(uintptr_t a, size_t n)
{
    const auto& r = Ranges();
    size_t lo = 0, hi = r.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (r[mid].hi <= a) lo = mid + 1; else hi = mid;
    }
    return lo < r.size() && r[lo].lo <= a && a + n <= r[lo].hi;
}

inline bool RawRead32(uintptr_t addr, uint32_t* out)
{
    __try { *out = *reinterpret_cast<volatile uint32_t*>(addr); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

inline bool RawCopy(uintptr_t addr, void* dst, size_t n)
{
    __try { memcpy(dst, reinterpret_cast<const void*>(addr), n); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Guard-safe reads (memory freed since the last Refresh is still caught by SEH).
inline bool Read32(uintptr_t addr, uint32_t* out) { return Readable(addr, 4) && RawRead32(addr, out); }
inline bool Copy(uintptr_t addr, void* dst, size_t n) { return Readable(addr, n) && RawCopy(addr, dst, n); }

} // namespace safemem
