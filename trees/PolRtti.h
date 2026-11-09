#pragma once
// Finds C++ class vtables inside a PE module from the MSVC x86 RTTI it ships
// with, so POL's UI classes can be located by name instead of by addresses
// that move every time Square Enix rebuilds appEU.dll / app.dll.
//
// MSVC x86 RTTI chain, walked back from the class name:
//   TypeDescriptor        { vftable*, spare, char name[] }   name e.g. ".?AVCFoo@pol@@"
//   CompleteObjectLocator { 0, subobjOffset, cdOffset, TypeDescriptor*, ClassHierarchy* }
//   vtable                [-1] = CompleteObjectLocator*, [0..] = virtual functions

#include <windows.h>
#include <cstdint>
#include <cstring>

namespace polrtti {

// A PE image laid out the way the Windows loader maps it (sections at RVAs).
// ptrBase is the address absolute pointers inside the image are based on:
// the load address for a live module, or the header's ImageBase for a file
// mapped by hand (relocations not applied).
struct Image {
    const uint8_t* map;
    uint32_t       size;
    uintptr_t      ptrBase;
};

namespace detail {

struct Section { uint32_t lo, hi; bool exec; };
constexpr int kMaxSections = 32;

inline int ReadSections(const Image& img, Section* out)
{
    if (img.size < sizeof(IMAGE_DOS_HEADER)) return 0;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(img.map);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if ((uint32_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > img.size) return 0;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(img.map + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    int n = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections && n < kMaxSections; ++i) {
        uint32_t lo = sec[i].VirtualAddress;
        uint32_t hi = lo + sec[i].Misc.VirtualSize;
        if (lo >= img.size) continue;
        if (hi > img.size) hi = img.size;
        out[n++] = { lo, hi, (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 };
    }
    return n;
}

inline uint32_t Read32(const Image& img, uint32_t rva)
{
    uint32_t v; memcpy(&v, img.map + rva, 4); return v;
}

inline bool PointsIntoCode(const Image& img, const Section* secs, int n, uint32_t ptr)
{
    if (ptr < img.ptrBase) return false;
    uintptr_t rva = ptr - img.ptrBase;
    for (int i = 0; i < n; ++i)
        if (secs[i].exec && rva >= secs[i].lo && rva < secs[i].hi) return true;
    return false;
}

// Calls fn(rva) for every 4-byte-aligned dword in a data section equal to value.
template <class Fn>
inline bool ForEachDataDword(const Image& img, const Section* secs, int n,
                             uint32_t value, Fn fn)
{
    for (int i = 0; i < n; ++i) {
        if (secs[i].exec) continue;
        uint32_t lo = (secs[i].lo + 3) & ~3u;
        for (uint32_t r = lo; r + 4 <= secs[i].hi; r += 4)
            if (Read32(img, r) == value && fn(r)) return true;
    }
    return false;
}

// Calls fn(tdRva) for each TypeDescriptor whose name is exactly `mangled`.
template <class Fn>
inline bool ForEachTypeDescriptor(const Image& img, const Section* secs, int n,
                                  const char* mangled, Fn fn)
{
    size_t len = strlen(mangled) + 1;
    for (int i = 0; i < n; ++i) {
        if (secs[i].exec) continue;
        for (uint32_t p = secs[i].lo + 8; p + len <= secs[i].hi; ++p)
            if (memcmp(img.map + p, mangled, len) == 0 && fn(p - 8)) return true;
    }
    return false;
}

inline bool InImage(const Image& img, uint32_t ptr, uint32_t bytes)
{
    return ptr >= img.ptrBase && ptr - img.ptrBase + bytes <= img.size;
}

// Vtable of one class's subobject: finds the CompleteObjectLocator for
// (TypeDescriptor, subobject offset), then the vtable that points at it.
// Calls fn(colRva, vtRva) for the first match.
template <class Fn>
inline bool FindColVtable(const Image& img, const Section* secs, int n,
                          uint32_t tdRva, uint32_t subobjOffset, Fn fn)
{
    uint32_t tdPtr = (uint32_t)(img.ptrBase + tdRva);
    return ForEachDataDword(img, secs, n, tdPtr, [&](uint32_t r) {
        if (r < 12) return false;
        uint32_t colRva = r - 12;
        if (Read32(img, colRva) != 0) return false;                // x86 COL signature
        if (Read32(img, colRva + 4) != subobjOffset) return false;
        uint32_t colPtr = (uint32_t)(img.ptrBase + colRva);
        return ForEachDataDword(img, secs, n, colPtr, [&](uint32_t v) {
            if (v + 8 > img.size) return false;
            if (!PointsIntoCode(img, secs, n, Read32(img, v + 4))) return false;
            return fn(colRva, v + 4);
        });
    });
}

} // namespace detail

// RVA of the primary vtable (the complete object's, subobject offset 0) of the
// class whose RTTI name is exactly `mangled` (e.g. ".?AVCRegularMember@pol@@"),
// or 0 when the class is not present. An object's first dword points here.
inline uint32_t FindVtable(const Image& img, const char* mangled)
{
    using namespace detail;
    Section secs[kMaxSections];
    int n = ReadSections(img, secs);
    uint32_t vtRva = 0;
    ForEachTypeDescriptor(img, secs, n, mangled, [&](uint32_t td) {
        return FindColVtable(img, secs, n, td, 0, [&](uint32_t, uint32_t vt) {
            vtRva = vt; return true;
        });
    });
    return vtRva;
}

// For a class with multiple inheritance, the vtable used by its `baseMangled`
// base subobject (e.g. the CActionListener part of a window), or 0. The
// subobject's byte offset inside the object is written to *offsetOut; a
// pointer to the object plus that offset is what POL passes as `this` to the
// base's virtual functions. Both come from RTTI, so they track layout changes.
inline uint32_t FindSubobjectVtable(const Image& img, const char* classMangled,
                                    const char* baseMangled, uint32_t* offsetOut)
{
    using namespace detail;
    Section secs[kMaxSections];
    int n = ReadSections(img, secs);
    size_t baseLen = strlen(baseMangled) + 1;
    uint32_t vtRva = 0;

    ForEachTypeDescriptor(img, secs, n, classMangled, [&](uint32_t td) {
        uint32_t mdisp = 0; bool found = false;
        FindColVtable(img, secs, n, td, 0, [&](uint32_t col, uint32_t) {
            // COL -> ClassHierarchyDescriptor { sig, attrs, numBases, BaseClassArray* }
            uint32_t chd = Read32(img, col + 16);
            if (!InImage(img, chd, 16)) return false;
            chd -= (uint32_t)img.ptrBase;
            uint32_t count = Read32(img, chd + 8);
            uint32_t arr = Read32(img, chd + 12);
            if (count > 256 || !InImage(img, arr, count * 4)) return false;
            arr -= (uint32_t)img.ptrBase;
            for (uint32_t i = 1; i < count && !found; ++i) {
                // BaseClassDescriptor { TypeDescriptor*, numContained, mdisp, pdisp, vdisp, attrs }
                uint32_t bcd = Read32(img, arr + 4 * i);
                if (!InImage(img, bcd, 12)) continue;
                bcd -= (uint32_t)img.ptrBase;
                uint32_t btd = Read32(img, bcd);
                if (!InImage(img, btd, 8 + (uint32_t)baseLen)) continue;
                btd -= (uint32_t)img.ptrBase;
                if (memcmp(img.map + btd + 8, baseMangled, baseLen) != 0) continue;
                mdisp = Read32(img, bcd + 8);
                found = true;
            }
            return true;
        });
        if (!found || mdisp == 0) return false;
        return FindColVtable(img, secs, n, td, mdisp, [&](uint32_t, uint32_t vt) {
            vtRva = vt;
            if (offsetOut) *offsetOut = mdisp;
            return true;
        });
    });
    return vtRva;
}

} // namespace polrtti
