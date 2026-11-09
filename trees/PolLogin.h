#pragma once
// Finds everything Forest's login navigator needs inside POL's UI module
// (appEU.dll / app.dll / appJP.dll): the login screen classes by RTTI name,
// and POL's own select-row, password-feed and OK functions from the shape of
// the code that uses them. Nothing here is a fixed address, so a POL rebuild
// that moves things around is picked up automatically.

#include "PolClasses.h"
#include "PolRtti.h"

namespace pollogin {

struct Layout {
    // Screen frames (primary vtable RVAs). An object of each class sits in a
    // global pointer while its screen is open.
    uint32_t vtMemberList;      // CLoginMemberListFrame
    uint32_t vtSubCommand;      // CLoginSubCommandFrame (Log In / Edit / Delete)
    uint32_t vtSoftKeyboard;    // CPasswordSoftKeyWindow
    uint32_t vtRowTable;        // CPolTable: the member rows inside the member list
    uint32_t vtScrollTable;     // CScrollTable: the member list's own container of those rows

    // Soft keyboard, driven the way its own OK button does it.
    uint32_t softkeyListenerOff;  // window + this = its CActionListener part ("skw")
    uint32_t vtSoftkeyListener;   // vtable of that part (first dword at skw)
    uint32_t softkeyHandler;      // that part's button handler (actionPerformed)
    uint32_t fnApply;             // OK button, step 1: apply(window)
    uint32_t fnNotify;            // OK button, step 2: notify(window, 1)
    uint32_t fieldChain[3];       // password box object = [[[skw+a]+b]+c]
    uint32_t feedVtOff;           // password box vtable offset of insert(index, wchar*)

    // Member list.
    uint32_t fnSelectRow;         // CPolTable::selectRow(row, char, int), non-virtual
    int      selectRowMatches;    // how many functions matched (1 expected)

    const char* missing;          // first piece not found when Resolve fails
};

namespace detail {

using polrtti::detail::Section;
using polrtti::detail::Read32;

inline bool IsCode(const Section* secs, int n, uint32_t rva)
{
    for (int i = 0; i < n; ++i)
        if (secs[i].exec && rva >= secs[i].lo && rva < secs[i].hi) return true;
    return false;
}

// Target RVA of the `call rel32` (E8) at `rva`.
inline uint32_t CallTarget(const polrtti::Image& img, uint32_t rva)
{
    int32_t rel; memcpy(&rel, img.map + rva + 1, 4);
    return rva + 5 + (uint32_t)rel;
}

// Virtual-call target through a vtable entry (absolute pointer -> RVA), or 0.
inline uint32_t VtableEntry(const polrtti::Image& img, uint32_t vtRva, int slot)
{
    uint32_t p = Read32(img, vtRva + 4 * slot);
    return p >= img.ptrBase && p - img.ptrBase < img.size ? (uint32_t)(p - img.ptrBase) : 0;
}

// The OK button inside the soft keyboard handler: `call apply` immediately
// followed by `mov ecx, esi; push 1; call notify`.
inline bool FindOkDispatch(const polrtti::Image& img, const Section* secs, int n,
                           uint32_t handler, uint32_t* apply, uint32_t* notify)
{
    static const uint8_t kOk[] = { 0x8B, 0xCE, 0x6A, 0x01, 0xE8 };
    for (uint32_t p = handler; p < handler + 0x400 && p + 9 <= img.size; ++p) {
        if (memcmp(img.map + p, kOk, sizeof(kOk)) != 0) continue;
        if (img.map[p - 5] != 0xE8) continue;
        uint32_t a = CallTarget(img, p - 5), b = CallTarget(img, p + 4);
        if (!IsCode(secs, n, a) || !IsCode(secs, n, b)) continue;
        *apply = a; *notify = b;
        return true;
    }
    return false;
}

// The character-key path inside the soft keyboard handler walks three
// pointers from `this` to the password box, then calls two of its virtual
// functions; the last one inserts the character. Finds the three
// `mov reg, [reg + disp32]` hops (each based on the previous hop's result)
// and the vtable offset of that last `call [reg + disp8]`.
inline bool FindFieldChain(const polrtti::Image& img, uint32_t handler,
                           uint32_t chain[3], uint32_t* feedOff)
{
    struct Load { uint32_t pos; int dest, base; uint32_t disp; };
    Load loads[64]; int nl = 0;
    for (uint32_t p = handler; p < handler + 0x200 && p + 6 <= img.size && nl < 64; ++p) {
        uint8_t m = img.map[p + 1];
        if (img.map[p] != 0x8B || (m & 0xC0) != 0x80) continue;   // mov r32, [r32 + disp32]
        int rm = m & 7;
        if (rm == 4 || rm == 5) continue;                         // no SIB / no ebp frame slots
        uint32_t d = Read32(img, p + 2);
        if (d >= 0x1000) continue;
        loads[nl++] = { p, (m >> 3) & 7, rm, d };
    }
    for (int i = 0; i < nl; ++i)
        for (int j = i + 1; j < nl && loads[j].pos - loads[i].pos <= 16; ++j) {
            if (loads[j].base != loads[i].dest) continue;
            for (int k = j + 1; k < nl && loads[k].pos - loads[j].pos <= 16; ++k) {
                if (loads[k].base != loads[j].dest) continue;
                uint32_t calls[2]; int nc = 0;
                for (uint32_t p = loads[k].pos + 6; p < loads[k].pos + 0x30 && p + 3 <= img.size; ++p)
                    if (img.map[p] == 0xFF && (img.map[p + 1] & 0xF8) == 0x50 &&
                        (img.map[p + 1] & 7) != 4 && nc < 2)
                        calls[nc++] = img.map[p + 2];             // call [reg + disp8]
                if (nc == 0) continue;
                chain[0] = loads[i].disp; chain[1] = loads[j].disp; chain[2] = loads[k].disp;
                *feedOff = calls[nc - 1];
                return true;
            }
        }
    return false;
}

// CPolTable::selectRow(int row, char, int): an EH-prolog function
// (`push N; mov eax, handler; call prolog`) that soon tests `cmp al, 1` and
// `cmp byte [ebp+0Ch], 1` and returns with `ret 0Ch`. Same shape as the
// select-row Forest has always used; register order no longer matters.
inline uint32_t FindSelectRow(const polrtti::Image& img, const Section* secs, int n, int* matches)
{
    uint32_t first = 0; *matches = 0;
    for (int s = 0; s < n; ++s) {
        if (!secs[s].exec) continue;
        for (uint32_t p = secs[s].lo + 2; p + 0x80 <= secs[s].hi; ++p) {
            if (img.map[p] != 0xB8 || img.map[p - 2] != 0x6A || img.map[p + 5] != 0xE8) continue;
            const uint8_t* body = img.map + p + 10;
            bool cmpAl = false, cmpFlag = false, ret3 = false;
            for (int k = 0; k + 4 <= 36; ++k) {
                if (body[k] == 0x3C && body[k + 1] == 0x01) cmpAl = true;
                if (body[k] == 0x80 && body[k + 1] == 0x7D && body[k + 2] == 0x0C && body[k + 3] == 0x01) cmpFlag = true;
            }
            for (int k = 0; k + 3 <= 0x70; ++k)
                if (body[k] == 0xC2 && body[k + 1] == 0x0C && body[k + 2] == 0x00) { ret3 = true; break; }
            if (cmpAl && cmpFlag && ret3) {
                if (!first) first = p - 2;
                ++*matches;
            }
        }
    }
    return first;
}

} // namespace detail

// Resolves every piece; on failure sets out.missing to the first missing one.
inline bool Resolve(const polrtti::Image& img, Layout& out)
{
    using namespace detail;
    out = Layout{};
    Section secs[polrtti::detail::kMaxSections];
    int n = polrtti::detail::ReadSections(img, secs);

    auto need = [&](uint32_t v, const char* what) {
        if (!v && !out.missing) out.missing = what;
        return v != 0;
    };

    need(out.vtMemberList   = polrtti::FindVtable(img, polclass::kMemberList),    "member list class");
    need(out.vtSubCommand   = polrtti::FindVtable(img, polclass::kSubCommand),    "Log In menu class");
    need(out.vtSoftKeyboard = polrtti::FindVtable(img, polclass::kSoftKeyboard),  "soft keyboard class");
    need(out.vtRowTable     = polrtti::FindVtable(img, polclass::kRowTable),      "member rows table class");
    need(out.vtScrollTable  = polrtti::FindVtable(img, polclass::kScrollTable),   "member rows scroll table class");

    out.vtSoftkeyListener = polrtti::FindSubobjectVtable(img, polclass::kSoftKeyboard,
                                                         polclass::kActionListener,
                                                         &out.softkeyListenerOff);
    if (need(out.vtSoftkeyListener, "soft keyboard button handler")) {
        out.softkeyHandler = VtableEntry(img, out.vtSoftkeyListener, 1);
        if (need(out.softkeyHandler, "soft keyboard button handler")) {
            if (!FindOkDispatch(img, secs, n, out.softkeyHandler, &out.fnApply, &out.fnNotify))
                need(0, "soft keyboard OK functions");
            if (!FindFieldChain(img, out.softkeyHandler, out.fieldChain, &out.feedVtOff))
                need(0, "password box path");
        }
    }

    out.fnSelectRow = FindSelectRow(img, secs, n, &out.selectRowMatches);
    need(out.fnSelectRow, "member list select-row");

    return out.missing == nullptr;
}

} // namespace pollogin
