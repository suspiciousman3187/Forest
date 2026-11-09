// Tests for PolRtti.h: finding a class's vtable in a PE image by RTTI name.
//
//   rtti_test.exe                 synthetic-image tests only
//   rtti_test.exe <appEU.dll>     also checks a real POL UI module

#include "../PolRtti.h"
#include "../PolClasses.h"
#include "../PolLogin.h"

#include <cstdio>
#include <vector>

static int g_failures = 0;

#define CHECK_EQ(actual, expected, what)                                      \
    do {                                                                      \
        unsigned long long a_ = (unsigned long long)(actual);                 \
        unsigned long long e_ = (unsigned long long)(expected);               \
        if (a_ != e_) {                                                       \
            printf("FAIL %s: got 0x%llX, expected 0x%llX\n", what, a_, e_);   \
            ++g_failures;                                                     \
        } else {                                                              \
            printf("ok   %s\n", what);                                        \
        }                                                                     \
    } while (0)

// A minimal 32-bit PE image laid out at its RVAs: one executable section
// (.text at 0x1000) and one read-only data section (.rdata at 0x2000).
// Absolute pointers inside it are based on ImageBase, as on disk.
class FakeImage {
public:
    static constexpr uint32_t kBase = 0x10000000;
    static constexpr uint32_t kSize = 0x4000;

    FakeImage() : buf_(kSize, 0)
    {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf_.data());
        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = 0x80;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(buf_.data() + 0x80);
        nt->Signature = IMAGE_NT_SIGNATURE;
        nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
        nt->FileHeader.NumberOfSections = 2;
        nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
        nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        nt->OptionalHeader.ImageBase = kBase;
        nt->OptionalHeader.SizeOfImage = kSize;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        memcpy(sec[0].Name, ".text", 5);
        sec[0].VirtualAddress = 0x1000;
        sec[0].Misc.VirtualSize = 0x1000;
        sec[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        memcpy(sec[1].Name, ".rdata", 6);
        sec[1].VirtualAddress = 0x2000;
        sec[1].Misc.VirtualSize = 0x2000;
        sec[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    }

    // Lays out MSVC x86 RTTI for one vtable of a class: the TypeDescriptor
    // (vftable ptr, spare, name), a CompleteObjectLocator (signature 0,
    // subobject offset, cd offset, TypeDescriptor ptr, hierarchy ptr), and
    // the vtable itself preceded by its COL pointer, with `slots` code ptrs.
    void AddVtable(uint32_t tdRva, const char* name, uint32_t colRva,
                   uint32_t subobjOffset, uint32_t vtRva, int slots)
    {
        Put32(tdRva, 0);
        Put32(tdRva + 4, 0);
        memcpy(&buf_[tdRva + 8], name, strlen(name) + 1);
        Put32(colRva, 0);
        Put32(colRva + 4, subobjOffset);
        Put32(colRva + 8, 0);
        Put32(colRva + 12, kBase + tdRva);
        Put32(colRva + 16, 0);
        Put32(vtRva - 4, kBase + colRva);
        for (int i = 0; i < slots; ++i)
            Put32(vtRva + 4 * i, kBase + 0x1000 + 0x10 * i);
    }

    polrtti::Image View() const { return { buf_.data(), kSize, kBase }; }

private:
    void Put32(uint32_t rva, uint32_t v) { memcpy(&buf_[rva], &v, 4); }
    std::vector<uint8_t> buf_;
};

static void FindsVtableOfAClassByItsRttiName()
{
    FakeImage img;
    img.AddVtable(0x2100, ".?AVCRegularMember@pol@@", 0x2200, 0, 0x2304, 3);
    CHECK_EQ(polrtti::FindVtable(img.View(), ".?AVCRegularMember@pol@@"),
             0x2304, "finds vtable of a class by its RTTI name");
}

static void PicksThePrimaryVtableWhenAClassHasSeveral()
{
    // Multiple inheritance: one vtable per base subobject, all sharing the
    // TypeDescriptor. The secondary (offset 8) is laid out first on purpose.
    FakeImage img;
    img.AddVtable(0x2100, ".?AVCSoftkeyPasswordWnd@pol@@", 0x2200, 8, 0x2304, 2);
    img.AddVtable(0x2100, ".?AVCSoftkeyPasswordWnd@pol@@", 0x2220, 0, 0x2404, 4);
    CHECK_EQ(polrtti::FindVtable(img.View(), ".?AVCSoftkeyPasswordWnd@pol@@"),
             0x2404, "picks the primary (offset 0) vtable when a class has several");
}

// Maps a DLL file the way the loader would (sections at their RVAs), without
// running it or applying relocations, so pointers stay ImageBase-relative.
static bool MapImageFile(const char* path, std::vector<uint8_t>& img, uint32_t& imageBase,
                         uint32_t& timestamp)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return false;
    std::vector<uint8_t> raw;
    uint8_t chunk[65536]; size_t got;
    while ((got = fread(chunk, 1, sizeof(chunk), f)) > 0) raw.insert(raw.end(), chunk, chunk + got);
    fclose(f);
    if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(raw.data());
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(raw.data() + dos->e_lfanew);
    imageBase = nt->OptionalHeader.ImageBase;
    timestamp = nt->FileHeader.TimeDateStamp;
    img.assign(nt->OptionalHeader.SizeOfImage, 0);
    memcpy(img.data(), raw.data(), nt->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        uint32_t n = sec[i].SizeOfRawData;
        if (sec[i].Misc.VirtualSize && sec[i].Misc.VirtualSize < n) n = sec[i].Misc.VirtualSize;
        if (sec[i].PointerToRawData + n > raw.size()) n = (uint32_t)raw.size() - sec[i].PointerToRawData;
        if (sec[i].VirtualAddress + n > img.size()) continue;
        memcpy(img.data() + sec[i].VirtualAddress, raw.data() + sec[i].PointerToRawData, n);
    }
    return true;
}

// Every class the navigator relies on must exist in the installed POL UI
// module. Run after a POL patch to see whether Forest still has its anchors.
static void EveryLoginFlowClassResolvesInRealModule(const char* path)
{
    std::vector<uint8_t> img; uint32_t base = 0, ts = 0;
    if (!MapImageFile(path, img, base, ts)) {
        printf("FAIL could not map %s\n", path); ++g_failures; return;
    }
    printf("\n%s (PE timestamp 0x%08X)\n", path, ts);
    polrtti::Image view{ img.data(), (uint32_t)img.size(), base };
    for (const auto& c : polclass::kLoginFlow) {
        uint32_t vt = polrtti::FindVtable(view, c.rtti);
        printf("     %-17s %-50s vt=+0x%06X\n", c.key, c.rtti, vt);
        if (!vt) { printf("FAIL %s missing from module\n", c.key); ++g_failures; }
    }

    // Cross-check against an independent scanner (polscan.py) for the POL
    // build released 2026-11: same answers from two implementations.
    if (ts == 0x6ABA1594) {
        CHECK_EQ(polrtti::FindVtable(view, ".?AVCRegularMember@pol@@"), 0x3DD5B0,
                 "CRegularMember matches independent scan");
        CHECK_EQ(polrtti::FindVtable(view, ".?AVCRegularMember_LoginCommandMenu2@pol@@"), 0x3DAE48,
                 "CRegularMember_LoginCommandMenu2 matches independent scan");
        CHECK_EQ(polrtti::FindVtable(view, ".?AVCSoftkeyPasswordWnd@pol@@"), 0x4235BC,
                 "CSoftkeyPasswordWnd matches independent scan");
        CHECK_EQ(polrtti::FindVtable(view, ".?AVCPasswordField@pol@@"), 0x3D3294,
                 "CPasswordField matches independent scan");

        // Values read off the disassembly by hand (Capstone), not from this code.
        uint32_t off = 0;
        CHECK_EQ(polrtti::FindSubobjectVtable(view, ".?AVCPasswordSoftKeyWindow@pol@@",
                                              ".?AVCActionListener@pol@@", &off),
                 0x4AF494, "soft keyboard's CActionListener sub-vtable");
        CHECK_EQ(off, 0x280, "soft keyboard's CActionListener sits at +0x280");

        // Everything the login navigator needs, resolved in one call.
        pollogin::Layout L{};
        bool ok = pollogin::Resolve(view, L);
        CHECK_EQ(ok, true, "resolver finds every login piece");
        if (!ok) printf("     missing: %s\n", L.missing ? L.missing : "?");
        CHECK_EQ(L.vtMemberList, 0x469EAC, "member list frame vtable");
        CHECK_EQ(L.vtSubCommand, 0x46A7F0, "Log In menu frame vtable");
        CHECK_EQ(L.vtSoftKeyboard, 0x4AF248, "soft keyboard window vtable");
        CHECK_EQ(L.vtRowTable, 0x3D135C, "member rows table (CPolTable) vtable");
        CHECK_EQ(L.vtScrollTable, 0x3D0F68, "scroll table holding the rows (CScrollTable) vtable");
        CHECK_EQ(L.softkeyListenerOff, 0x280, "soft keyboard listener offset");
        CHECK_EQ(L.vtSoftkeyListener, 0x4AF494, "soft keyboard listener vtable");
        CHECK_EQ(L.softkeyHandler, 0x29C1D1, "soft keyboard button handler");
        CHECK_EQ(L.fnApply, 0x29C04A, "OK step 1: apply");
        CHECK_EQ(L.fnNotify, 0x8992A, "OK step 2: notify(1)");
        CHECK_EQ(L.fieldChain[0], 0x18C, "password box path hop 1");
        CHECK_EQ(L.fieldChain[1], 0x208, "password box path hop 2");
        CHECK_EQ(L.fieldChain[2], 0x19C, "password box path hop 3");
        CHECK_EQ(L.feedVtOff, 0x14, "character feed vtable slot offset");
        CHECK_EQ(L.fnSelectRow, 0x9F4A9, "member list select-row");
    }
}

int main(int argc, char** argv)
{
    FindsVtableOfAClassByItsRttiName();
    PicksThePrimaryVtableWhenAClassHasSeveral();
    if (argc > 1) EveryLoginFlowClassResolvesInRealModule(argv[1]);

    printf(g_failures ? "\n%d FAILED\n" : "\nALL PASSED\n", g_failures);
    return g_failures ? 1 : 0;
}
