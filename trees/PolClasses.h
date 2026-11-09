#pragma once
// POL UI classes the login navigator relies on, by MSVC RTTI name. Looking
// classes up by name (PolRtti.h) keeps Forest working when Square Enix
// rebuilds the UI module and every address in it moves.
//
// Observed with PolProbe on the 2026-11 appEU.dll: each login frame is held in
// a global pointer that is set while its screen is open and cleared when it
// closes, so "pointer present" is the screen-visible signal.

namespace polclass {

// Screen frames of the PlayOnline login flow.
constexpr const char* kMemberList     = ".?AVCLoginMemberListFrame@pol@@";
constexpr const char* kMainCommand    = ".?AVCLoginMainCommandFrame@pol@@";
constexpr const char* kSubCommand     = ".?AVCLoginSubCommandFrame@pol@@";   // Log In / Edit / Delete
constexpr const char* kConnection     = ".?AVCLoginConnectionFrame@pol@@";
constexpr const char* kPasswordScreen = ".?AVCLoginConnectionEthernetSqexFrame@pol@@";
constexpr const char* kSoftKeyboard   = ".?AVCPasswordSoftKeyWindow@pol@@";
constexpr const char* kPasswordField  = ".?AVCPasswordField@pol@@";
constexpr const char* kLoginSequence  = ".?AVCLoginSequence@pol@@";

// Building blocks inside those screens.
constexpr const char* kRowTable       = ".?AVCPolTable@pol@@";               // member rows
constexpr const char* kScrollTable    = ".?AVCScrollTable@pol@@";            // holds the rows table
constexpr const char* kActionListener = ".?AVCActionListener@pol@@";         // button handler base

struct Entry { const char* key; const char* rtti; };

// Every class above, for tools that check or watch them all (tests, PolProbe).
constexpr Entry kLoginFlow[] = {
    { "member_list",      kMemberList },
    { "main_command",     kMainCommand },
    { "sub_command",      kSubCommand },
    { "connection",       kConnection },
    { "password_screen",  kPasswordScreen },
    { "softkey_password", kSoftKeyboard },
    { "password_field",   kPasswordField },
    { "login_sequence",   kLoginSequence },
    { "row_table",        kRowTable },
    { "scroll_table",     kScrollTable },
};

} // namespace polclass
