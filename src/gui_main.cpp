// pwvault-gui: Windows GUI version of pwvault, styled after the "Nocturne"
// design system (dark ground, single accent, outlined buttons, 8px radii).
//
// Same encrypted vault format lineage as the console version, extended:
// v2 (console-only legacy): name, username, password, notes
// v3 (current): name, username, password, website, notes, category, favorite
// A v2 file is auto-migrated to v3 on first successful unlock in this app.
//
// Windows only. Uses plain Win32 + GDI+ (both ship with Windows; no extra
// installers). Build: g++ ... -lbcrypt -lgdiplus

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objidl.h>
#include <gdiplus.h>
#include <commctrl.h>
#include <shlobj.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "gdiplus.lib")

#include "aes.hpp"
#include "kdf.hpp"
#include "sha256.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <string>
#include <vector>

// ============================================================================
// Vault core
// ============================================================================

namespace {

constexpr uint32_t PBKDF2_ITERATIONS = 200000;
constexpr size_t SALT_SIZE = 16;
constexpr size_t IV_SIZE = 16;
constexpr size_t TAG_SIZE = 32;
const char MAGIC_V2[8] = "PWVLT2\n"; // legacy: name/username/password/notes
const char MAGIC_V3[8] = "PWVLT3\n"; // current: adds website/category/favorite

struct Entry {
    std::string name;
    std::string username;
    std::string password;
    std::string website;
    std::string notes;
    std::string category; // "", "Personal", "Work", "Finance", "Other"
    bool favorite = false;
};

std::string default_vault_path() {
    const char* home = std::getenv("USERPROFILE");
    std::string dir = home ? std::string(home) + "\\.pwvault" : ".pwvault";
    CreateDirectoryA(dir.c_str(), NULL);
    return dir + "\\vault.dat";
}

std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> buf(n);
    NTSTATUS status = BCryptGenRandom(
        NULL, buf.data(), (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        MessageBoxA(NULL, "Fatal: could not generate secure random data.", "pwvault", MB_ICONERROR);
        std::exit(1);
    }
    return buf;
}

void put_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back((v >> 24) & 0xff);
    out.push_back((v >> 16) & 0xff);
    out.push_back((v >> 8) & 0xff);
    out.push_back(v & 0xff);
}

uint32_t get_u32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

void put_str(std::vector<uint8_t>& out, const std::string& s) {
    put_u32(out, (uint32_t)s.size());
    out.insert(out.end(), s.begin(), s.end());
}

bool get_str(const std::vector<uint8_t>& in, size_t& pos, std::string& out) {
    if (pos + 4 > in.size()) return false;
    uint32_t len = get_u32(&in[pos]);
    pos += 4;
    if (pos + len > in.size()) return false;
    out.assign(in.begin() + pos, in.begin() + pos + len);
    pos += len;
    return true;
}

bool constant_time_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); i++) diff |= (a[i] ^ b[i]);
    return diff == 0;
}

std::vector<uint8_t> serialize_entries_v3(const std::vector<Entry>& entries) {
    std::vector<uint8_t> out;
    put_u32(out, (uint32_t)entries.size());
    for (const auto& e : entries) {
        put_str(out, e.name);
        put_str(out, e.username);
        put_str(out, e.password);
        put_str(out, e.website);
        put_str(out, e.notes);
        put_str(out, e.category);
        put_u32(out, e.favorite ? 1u : 0u);
    }
    return out;
}

bool deserialize_entries_v3(const std::vector<uint8_t>& in, std::vector<Entry>& out) {
    if (in.size() < 4) return false;
    size_t pos = 0;
    uint32_t count = get_u32(&in[pos]); pos += 4;
    out.clear();
    out.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        Entry e;
        if (!get_str(in, pos, e.name)) return false;
        if (!get_str(in, pos, e.username)) return false;
        if (!get_str(in, pos, e.password)) return false;
        if (!get_str(in, pos, e.website)) return false;
        if (!get_str(in, pos, e.notes)) return false;
        if (!get_str(in, pos, e.category)) return false;
        if (pos + 4 > in.size()) return false;
        e.favorite = get_u32(&in[pos]) != 0; pos += 4;
        out.push_back(std::move(e));
    }
    return true;
}

bool deserialize_entries_v2(const std::vector<uint8_t>& in, std::vector<Entry>& out) {
    if (in.size() < 4) return false;
    size_t pos = 0;
    uint32_t count = get_u32(&in[pos]); pos += 4;
    out.clear();
    out.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        Entry e;
        if (!get_str(in, pos, e.name)) return false;
        if (!get_str(in, pos, e.username)) return false;
        if (!get_str(in, pos, e.password)) return false;
        if (!get_str(in, pos, e.notes)) return false;
        // website/category/favorite default-constructed (empty/false)
        out.push_back(std::move(e));
    }
    return true;
}

struct Vault {
    std::string path;
    std::vector<Entry> entries;
};

bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

// Returns true on success. `migrated` is set true if the file was read in
// the legacy v2 format (caller should re-save to upgrade it on disk).
bool load_vault(Vault& v, const std::string& master_password, std::string& err, bool& migrated) {
    migrated = false;
    std::ifstream in(v.path, std::ios::binary);
    if (!in) { err = "Vault file not found."; return false; }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    if (data.size() < 7 + 4 + SALT_SIZE + IV_SIZE + TAG_SIZE) {
        err = "Vault file is corrupt or truncated."; return false;
    }
    bool isV2 = std::memcmp(data.data(), MAGIC_V2, 7) == 0;
    bool isV3 = std::memcmp(data.data(), MAGIC_V3, 7) == 0;
    if (!isV2 && !isV3) { err = "Vault file has an unrecognized format."; return false; }

    size_t pos = 7;
    uint32_t iterations = get_u32(&data[pos]); pos += 4;
    std::vector<uint8_t> salt(data.begin() + pos, data.begin() + pos + SALT_SIZE); pos += SALT_SIZE;
    std::vector<uint8_t> iv(data.begin() + pos, data.begin() + pos + IV_SIZE); pos += IV_SIZE;
    size_t cipher_start = pos;
    size_t cipher_len = data.size() - TAG_SIZE - cipher_start;
    std::vector<uint8_t> ciphertext(data.begin() + cipher_start, data.begin() + cipher_start + cipher_len);
    std::vector<uint8_t> tag(data.end() - TAG_SIZE, data.end());

    auto derived = crypto::pbkdf2_hmac_sha256(master_password, salt, iterations, 64);
    std::vector<uint8_t> enc_key(derived.begin(), derived.begin() + 32);
    std::vector<uint8_t> mac_key(derived.begin() + 32, derived.begin() + 64);

    std::vector<uint8_t> mac_input(data.begin(), data.begin() + cipher_start + cipher_len);
    auto computed_tag = crypto::hmac_sha256(mac_key, mac_input.data(), mac_input.size());
    if (!constant_time_equal(computed_tag, tag)) {
        err = "Incorrect master password.";
        return false;
    }

    uint8_t key_arr[32], iv_arr[16];
    std::memcpy(key_arr, enc_key.data(), 32);
    std::memcpy(iv_arr, iv.data(), 16);
    auto plaintext = crypto::aes256_ctr(key_arr, iv_arr, ciphertext);

    bool ok = isV3 ? deserialize_entries_v3(plaintext, v.entries)
                    : deserialize_entries_v2(plaintext, v.entries);
    if (!ok) { err = "Failed to parse decrypted vault contents."; return false; }
    migrated = isV2;
    return true;
}

// Rotates up to MAX_BACKUPS previous versions of a vault file, kept in a
// "backups" subfolder next to it, so a single delete or corruption never
// destroys every copy. Call this with the *old* file still in place, right
// before it gets overwritten.
void RotateBackups(const std::string& vaultPath) {
    size_t slashPos = vaultPath.find_last_of("\\/");
    std::string dir = (slashPos == std::string::npos) ? "." : vaultPath.substr(0, slashPos);
    std::string backupDir = dir + "\\backups";
    CreateDirectoryA(backupDir.c_str(), NULL);

    constexpr int MAX_BACKUPS = 5;
    std::ifstream check(vaultPath, std::ios::binary);
    if (!check.good()) return; // nothing to back up yet (first-ever save)
    check.close();

    DeleteFileA((backupDir + "\\vault.dat.bak" + std::to_string(MAX_BACKUPS)).c_str());
    for (int i = MAX_BACKUPS - 1; i >= 1; i--) {
        std::string src = backupDir + "\\vault.dat.bak" + std::to_string(i);
        std::string dst = backupDir + "\\vault.dat.bak" + std::to_string(i + 1);
        MoveFileExA(src.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    CopyFileA(vaultPath.c_str(), (backupDir + "\\vault.dat.bak1").c_str(), FALSE);
}

bool save_vault(const Vault& v, const std::string& master_password, std::string& err) {
    auto salt = random_bytes(SALT_SIZE);
    auto iv = random_bytes(IV_SIZE);
    auto derived = crypto::pbkdf2_hmac_sha256(master_password, salt, PBKDF2_ITERATIONS, 64);
    std::vector<uint8_t> enc_key(derived.begin(), derived.begin() + 32);
    std::vector<uint8_t> mac_key(derived.begin() + 32, derived.begin() + 64);

    auto plaintext = serialize_entries_v3(v.entries);
    uint8_t key_arr[32], iv_arr[16];
    std::memcpy(key_arr, enc_key.data(), 32);
    std::memcpy(iv_arr, iv.data(), 16);
    auto ciphertext = crypto::aes256_ctr(key_arr, iv_arr, plaintext);

    std::vector<uint8_t> out;
    out.insert(out.end(), MAGIC_V3, MAGIC_V3 + 7);
    put_u32(out, PBKDF2_ITERATIONS);
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());

    auto tag = crypto::hmac_sha256(mac_key, out.data(), out.size());
    out.insert(out.end(), tag.begin(), tag.end());

    RotateBackups(v.path);

    std::string tmp_path = v.path + ".tmp";
    std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
    if (!ofs) { err = "Failed to write vault file."; return false; }
    ofs.write(reinterpret_cast<const char*>(out.data()), out.size());
    ofs.close();

    MoveFileExA(tmp_path.c_str(), v.path.c_str(), MOVEFILE_REPLACE_EXISTING);
    return true;
}

std::string generate_password(size_t len, bool use_upper, bool use_lower, bool use_digits, bool use_symbols) {
    std::string charset;
    if (use_upper) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (use_lower) charset += "abcdefghijklmnopqrstuvwxyz";
    if (use_digits) charset += "0123456789";
    if (use_symbols) charset += "!@#$%^&*()-_=+[]{}<>?/.,~";
    if (charset.empty()) charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    auto raw = random_bytes(len * 4);
    std::string out;
    out.reserve(len);
    size_t idx = 0;
    while (out.size() < len) {
        uint8_t b = raw[idx++ % raw.size()];
        if (idx > len * 20) break;
        out += charset[b % charset.size()];
    }
    return out;
}

// Returns 0 (empty), 1 (weak), 2 (fair), or 3 (strong).
int ComputePasswordStrength(const std::string& pw) {
    if (pw.empty()) return 0;
    bool hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
    for (unsigned char c : pw) {
        if (c >= 'a' && c <= 'z') hasLower = true;
        else if (c >= 'A' && c <= 'Z') hasUpper = true;
        else if (c >= '0' && c <= '9') hasDigit = true;
        else hasSymbol = true;
    }
    double charsetSize = 0;
    if (hasLower) charsetSize += 26;
    if (hasUpper) charsetSize += 26;
    if (hasDigit) charsetSize += 10;
    if (hasSymbol) charsetSize += 32;
    double entropy = (double)pw.size() * std::log2(std::max(charsetSize, 1.0));
    if (pw.size() < 8) return 1;
    if (entropy < 40) return 1;
    if (entropy < 65) return 2;
    return 3;
}

// ============================================================================
// GUI
// ============================================================================

constexpr int ID_LOGIN_PW1        = 1001;
constexpr int ID_LOGIN_PW2        = 1002;
constexpr int ID_LOGIN_BTN        = 1003;
constexpr int ID_LOGIN_EYE        = 1004;

constexpr int ID_NAV_VAULT        = 1101;
constexpr int ID_NAV_SETTINGS     = 1102;
constexpr int ID_NAV_LOCK         = 1103;

constexpr int ID_SEARCH           = 1110;
constexpr int ID_ADD_BTN          = 1111;
constexpr int ID_LIST             = 1112;
constexpr int ID_CHIP_ALL         = 1113;
constexpr int ID_CHIP_FAV         = 1114;
constexpr int ID_CHIP_CAT_SLOT    = 1115;
constexpr int ID_CHIP_SCROLL_LEFT  = 1116;
constexpr int ID_CHIP_SCROLL_RIGHT = 1117;

constexpr int ID_VIEW_EDIT_BTN    = 1120;
constexpr int ID_VIEW_DELETE_BTN  = 1121;
constexpr int ID_VIEW_FAV_BTN     = 1122;
constexpr int ID_VIEW_COPY_USER   = 1123;
constexpr int ID_VIEW_COPY_PASS   = 1124;
constexpr int ID_VIEW_COPY_SITE   = 1125;
constexpr int ID_VIEW_SHOW_PASS   = 1126;

constexpr int ID_FORM_NAME        = 1130;
constexpr int ID_FORM_USER        = 1131;
constexpr int ID_FORM_PASS        = 1132;
constexpr int ID_FORM_GEN         = 1133;
constexpr int ID_FORM_SHOWCHK     = 1134;
constexpr int ID_FORM_SITE        = 1135;
constexpr int ID_FORM_CATEGORY    = 1136;
constexpr int ID_FORM_FAVCHK      = 1137;
constexpr int ID_FORM_NOTES       = 1138;
constexpr int ID_FORM_OK          = 1139;
constexpr int ID_FORM_CANCEL      = 1140;

constexpr int ID_SET_AUTOLOCK_INSTANT = 1150;
constexpr int ID_SET_AUTOLOCK_CUSTOM  = 1151;
constexpr int ID_SET_AUTOLOCK_NEVER   = 1153;
constexpr int ID_SET_AUTOLOCK_MINUTES = 1157;
constexpr int ID_SET_CHANGEPW_BTN     = 1154;
constexpr int ID_SET_CHOOSE_FOLDER    = 1155;
constexpr int ID_SET_REMOVE_BACKUP    = 1156;

constexpr int ID_CP_PW1    = 1160;
constexpr int ID_CP_PW2    = 1161;
constexpr int ID_CP_OK     = 1162;
constexpr int ID_CP_CANCEL = 1163;

constexpr UINT_PTR TIMER_CLEAR_STATUS    = 1;
constexpr UINT_PTR TIMER_CLEAR_CLIPBOARD = 2;
constexpr UINT_PTR TIMER_AUTOLOCK        = 3;
constexpr UINT_PTR TIMER_STRENGTH        = 4;

enum class AppState { LOGIN, UNLOCKED };
enum class NavView { VAULT, SETTINGS, CHANGEPW };
enum class DetailMode { EMPTY, VIEW, ADD, EDIT };
enum class AutoLockMode { INSTANT, CUSTOM, NEVER };

Vault g_vault;
std::string g_masterPassword;
bool g_vaultFileExisted = false;
std::string g_secondaryBackupDir; // empty = not configured

AppState g_appState = AppState::LOGIN;
NavView g_navView = NavView::VAULT;
DetailMode g_detailMode = DetailMode::EMPTY;
AutoLockMode g_autoLock = AutoLockMode::CUSTOM;
int g_autoLockMinutes = 5; // used when g_autoLock == CUSTOM
ULONGLONG g_autoLockDeadlineTick = 0; // GetTickCount64() value at which we should lock

std::string g_searchText;
std::string g_activeChip = "All";
std::string g_selectedEntryName;
bool g_editorIsNew = true;
bool g_detailPasswordVisible = false;
bool g_formPasswordVisible = false;

HWND g_hMain;
HWND g_hDividerSidebar, g_hDividerList;
HBRUSH g_hbrBorder;

// login
HWND g_hLoginBadge, g_hLoginTitle, g_hLoginSubtitle, g_hLoginPwLabel, g_hLoginPw1, g_hLoginEye,
     g_hLoginStrengthBar, g_hLoginStrengthLabel, g_hLoginPw2Label, g_hLoginPw2, g_hLoginBtn, g_hLoginStatus;

// sidebar
HWND g_hSidebarBadge, g_hSidebarBrand, g_hNavVault, g_hNavSettings, g_hNavLock;

// vault list pane
HWND g_hSearch, g_hAddBtn, g_hChipAll, g_hChipFav, g_hChipScrollLeft, g_hChipCatSlot, g_hChipScrollRight,
     g_hList, g_hVaultStatus;
std::vector<std::string> g_chipCategories; // distinct, sorted categories actually used in the vault
int g_chipCatIndex = 0; // which one is currently shown in the scrollable slot

// detail pane - empty state
HWND g_hDetailEmpty;

// detail pane - view state
HWND g_hViewAvatar, g_hViewName, g_hViewCategory, g_hViewFavBtn, g_hViewEditBtn, g_hViewDeleteBtn,
     g_hViewUserLbl, g_hViewUserVal, g_hViewCopyUser,
     g_hViewPassLbl, g_hViewPassVal, g_hViewShowPass, g_hViewCopyPass,
     g_hViewSiteLbl, g_hViewSiteVal, g_hViewCopySite,
     g_hViewNotesLbl, g_hViewNotesVal;

// detail pane - form (add/edit)
HWND g_hFormTitle, g_hFormNameLbl, g_hFormName, g_hFormUserLbl, g_hFormUser,
     g_hFormPassLbl, g_hFormPass, g_hFormGen, g_hFormShowChk,
     g_hFormStrengthBar, g_hFormStrengthLabel,
     g_hFormSiteLbl, g_hFormSite, g_hFormCategoryLbl, g_hFormCategory, g_hFormFavChk,
     g_hFormNotesLbl, g_hFormNotes, g_hFormOk, g_hFormCancel;

// settings
HWND g_hSetTitle, g_hSecHdr, g_hAutoLockLbl, g_hAutoInstant, g_hAutoCustom, g_hAutoCustomMinutesEdit,
     g_hAutoCustomMinutesLbl, g_hAutoNever,
     g_hChangePwBtn, g_hAboutText,
     g_hBackupHdr, g_hLocalBackupInfo, g_hSecondaryLbl, g_hSecondaryPathDisplay,
     g_hChooseFolderBtn, g_hRemoveBackupBtn;

// change password sub-panel (own screen)
HWND g_hCpTitle, g_hCpPw1Lbl, g_hCpPw1, g_hCpStrengthBar, g_hCpStrengthLabel,
     g_hCpPw2Lbl, g_hCpPw2, g_hCpOk, g_hCpCancel, g_hCpStatus;

HFONT g_hFont, g_hFontBold, g_hFontLarge, g_hFontSmall;

// ---- Nocturne palette (from the exported design tokens) ----
COLORREF g_colBg       = RGB(22, 24, 38);   // #161826
COLORREF g_colSurface  = RGB(35, 37, 50);   // #232532
COLORREF g_colText     = RGB(233, 233, 237);// #e9e9ed
COLORREF g_colMuted    = RGB(147, 151, 171);// neutral-500
COLORREF g_colBorder   = RGB(63, 66, 77);   // neutral-800
COLORREF g_colAccent   = RGB(145, 132, 217);// #9184d9
COLORREF g_colDanger   = RGB(224, 122, 122);

Gdiplus::Color GC(COLORREF c, BYTE alpha = 255) {
    return Gdiplus::Color(alpha, GetRValue(c), GetGValue(c), GetBValue(c));
}

HBRUSH g_hbrBg, g_hbrSurface;
ULONG_PTR g_gdiplusToken;

void InitGdiResources() {
    g_hbrBg = CreateSolidBrush(g_colBg);
    g_hbrSurface = CreateSolidBrush(g_colSurface);
    g_hbrBorder = CreateSolidBrush(g_colBorder);
}

void EnableDarkTitleBar(HWND hwnd) {
    HMODULE hDwm = LoadLibraryA("dwmapi.dll");
    if (!hDwm) return;
    typedef HRESULT(WINAPI* PFN_DwmSetWindowAttribute)(HWND, DWORD, LPCVOID, DWORD);
    auto pFn = (PFN_DwmSetWindowAttribute)GetProcAddress(hDwm, "DwmSetWindowAttribute");
    if (pFn) {
        BOOL enable = TRUE;
        const DWORD DWMWA_USE_IMMERSIVE_DARK_MODE_LOCAL = 20;
        pFn(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_LOCAL, &enable, sizeof(enable));
    }
    FreeLibrary(hDwm);
}

// ---- drawing helpers ----

void FillRoundedRect(Gdiplus::Graphics& g, const Gdiplus::Rect& r, int radius, const Gdiplus::Color& fill) {
    Gdiplus::GraphicsPath path;
    int d = radius * 2;
    path.AddArc(r.X, r.Y, d, d, 180, 90);
    path.AddArc(r.X + r.Width - d, r.Y, d, d, 270, 90);
    path.AddArc(r.X + r.Width - d, r.Y + r.Height - d, d, d, 0, 90);
    path.AddArc(r.X, r.Y + r.Height - d, d, d, 90, 90);
    path.CloseFigure();
    Gdiplus::SolidBrush brush(fill);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.FillPath(&brush, &path);
}

void DrawRoundedRectBorder(Gdiplus::Graphics& g, const Gdiplus::Rect& r, int radius, const Gdiplus::Color& borderColor, float width = 1.0f) {
    Gdiplus::GraphicsPath path;
    int d = radius * 2;
    path.AddArc(r.X, r.Y, d, d, 180, 90);
    path.AddArc(r.X + r.Width - d, r.Y, d, d, 270, 90);
    path.AddArc(r.X + r.Width - d, r.Y + r.Height - d, d, d, 0, 90);
    path.AddArc(r.X, r.Y + r.Height - d, d, d, 90, 90);
    path.CloseFigure();
    Gdiplus::Pen pen(borderColor, width);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.DrawPath(&pen, &path);
}

void DrawCenteredText(Gdiplus::Graphics& g, const std::string& text, HFONT hFont, const Gdiplus::RectF& rect, const Gdiplus::Color& color, Gdiplus::StringAlignment hAlign = Gdiplus::StringAlignmentCenter) {
    HDC hdc = g.GetHDC();
    Gdiplus::Font font(hdc, hFont);
    g.ReleaseHDC(hdc);
    Gdiplus::SolidBrush brush(color);
    Gdiplus::StringFormat fmt;
    fmt.SetAlignment(hAlign);
    fmt.SetLineAlignment(Gdiplus::StringAlignmentCenter);
    std::wstring wtext(text.begin(), text.end());
    g.SetTextRenderingHint(Gdiplus::TextRenderingHintClearTypeGridFit);
    g.DrawString(wtext.c_str(), -1, &font, rect, &fmt, &brush);
}

// Simple padlock glyph: rounded body + arc shackle, drawn in the given box.
void DrawPadlockIcon(Gdiplus::Graphics& g, const Gdiplus::Rect& box, const Gdiplus::Color& color) {
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    int bodyW = (int)(box.Width * 0.62f);
    int bodyH = (int)(box.Height * 0.44f);
    int bodyX = box.X + (box.Width - bodyW) / 2;
    int bodyY = box.Y + (int)(box.Height * 0.46f);
    Gdiplus::Rect body(bodyX, bodyY, bodyW, bodyH);
    FillRoundedRect(g, body, 3, color);

    int shackleW = (int)(box.Width * 0.42f);
    int shackleH = (int)(box.Height * 0.40f);
    int shackleX = box.X + (box.Width - shackleW) / 2;
    int shackleY = bodyY - shackleH / 2;
    Gdiplus::Pen pen(color, 2.4f);
    Gdiplus::Rect shackleRect(shackleX, shackleY, shackleW, shackleH);
    g.DrawArc(&pen, shackleRect, 180, 180);
}

// ---- Enter-key-submits subclass for single-line edit controls ----
WNDPROC g_origEditProc = nullptr;

LRESULT CALLBACK EditEnterSubclassProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_KEYDOWN && wp == VK_RETURN) {
        int targetId = (int)(INT_PTR)GetPropA(hwnd, "PwvEnterTarget");
        if (targetId != 0) {
            PostMessageA(g_hMain, WM_COMMAND, MAKEWPARAM(targetId, BN_CLICKED), 0);
            return 0;
        }
    }
    return CallWindowProcA(g_origEditProc, hwnd, msg, wp, lp);
}

void MakeEnterSubmit(HWND hEdit, int targetCommandId) {
    if (!g_origEditProc) g_origEditProc = (WNDPROC)GetWindowLongPtrA(hEdit, GWLP_WNDPROC);
    SetWindowLongPtrA(hEdit, GWLP_WNDPROC, (LONG_PTR)EditEnterSubclassProc);
    SetPropA(hEdit, "PwvEnterTarget", (HANDLE)(INT_PTR)targetCommandId);
}

// ---- small helpers ----

void SetStatus(HWND label, const std::string& text, bool autoClearTimer = false) {
    SetWindowTextA(label, text.c_str());
    if (autoClearTimer) SetTimer(g_hMain, TIMER_CLEAR_STATUS, 4000, NULL);
}

void ClearSensitiveMemory() {
    for (auto& e : g_vault.entries) std::fill(e.password.begin(), e.password.end(), '\0');
    g_vault.entries.clear();
    std::fill(g_masterPassword.begin(), g_masterPassword.end(), '\0');
    g_masterPassword.clear();
}

std::string GetEditText(HWND h) {
    int len = GetWindowTextLengthA(h);
    std::string s(len, '\0');
    if (len > 0) GetWindowTextA(h, &s[0], len + 1);
    return s;
}

void CopyToClipboard(HWND hwnd, const std::string& text) {
    if (!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (hMem) {
        void* p = GlobalLock(hMem);
        memcpy(p, text.c_str(), text.size() + 1);
        GlobalUnlock(hMem);
        SetClipboardData(CF_TEXT, hMem);
    }
    CloseClipboard();
    SetTimer(g_hMain, TIMER_CLEAR_CLIPBOARD, 20000, NULL);
}

Entry* FindEntry(const std::string& name) {
    for (auto& e : g_vault.entries) if (e.name == name) return &e;
    return nullptr;
}

std::string InitialOf(const std::string& name) {
    if (name.empty()) return "?";
    char c = name[0];
    if (c >= 'a' && c <= 'z') c -= 32;
    return std::string(1, c);
}

bool EntryMatchesFilter(const Entry& e) {
    if (g_activeChip == "Favorites") {
        if (!e.favorite) return false;
    } else if (g_activeChip != "All") {
        if (e.category != g_activeChip) return false;
    }
    if (!g_searchText.empty()) {
        std::string nameLower = e.name, userLower = e.username, searchLower = g_searchText;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
        std::transform(userLower.begin(), userLower.end(), userLower.begin(), ::tolower);
        std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), ::tolower);
        if (nameLower.find(searchLower) == std::string::npos &&
            userLower.find(searchLower) == std::string::npos) return false;
    }
    return true;
}

// Rebuilds the list of distinct categories actually used across the vault
// (excluding blank), so the scrollable chip can reach any of them -- not
// just a fixed Work/Finance pair.
void RebuildChipCategories() {
    std::vector<std::string> cats;
    for (auto& e : g_vault.entries) if (!e.category.empty()) cats.push_back(e.category);
    std::sort(cats.begin(), cats.end());
    cats.erase(std::unique(cats.begin(), cats.end()), cats.end());
    g_chipCategories = cats;
    if (g_chipCatIndex >= (int)g_chipCategories.size()) {
        g_chipCatIndex = g_chipCategories.empty() ? 0 : (int)g_chipCategories.size() - 1;
    }
}

// Updates the scrollable category chip's label, enabled state of the
// arrows, and hides the whole group if no entry has a category yet.
void RefreshChipCategorySlot() {
    bool any = !g_chipCategories.empty();
    ShowWindow(g_hChipScrollLeft, any ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hChipCatSlot, any ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hChipScrollRight, any ? SW_SHOW : SW_HIDE);
    if (!any) return;
    SetWindowTextA(g_hChipCatSlot, g_chipCategories[g_chipCatIndex].c_str());
    EnableWindow(g_hChipScrollLeft, g_chipCatIndex > 0);
    EnableWindow(g_hChipScrollRight, g_chipCatIndex < (int)g_chipCategories.size() - 1);
    InvalidateRect(g_hChipScrollLeft, NULL, TRUE);
    InvalidateRect(g_hChipCatSlot, NULL, TRUE);
    InvalidateRect(g_hChipScrollRight, NULL, TRUE);
}

std::vector<std::string> GetFilteredSortedNames() {
    std::vector<std::string> names;
    for (auto& e : g_vault.entries) if (EntryMatchesFilter(e)) names.push_back(e.name);
    std::sort(names.begin(), names.end());
    return names;
}

HWND MakeCtrl(const char* cls, const char* text, int x, int y, int w, int hh, DWORD style, int id,
              HFONT font = nullptr, bool muted = false) {
    HWND h = CreateWindowExA(0, cls, text, style | WS_CHILD,
        x, y, w, hh, g_hMain, (HMENU)(INT_PTR)id, GetModuleHandleA(NULL), NULL);
    SendMessageA(h, WM_SETFONT, (WPARAM)(font ? font : g_hFont), TRUE);
    if (muted) SetPropA(h, "PwvMuted", (HANDLE)1);
    return h;
}

constexpr DWORD BTN_STYLE = BS_OWNERDRAW | WS_TABSTOP;
constexpr int SIDEBAR_W = 200;
constexpr int CONTENT_X = 216;
constexpr int LIST_W = 260;
constexpr int DETAIL_X = CONTENT_X + LIST_W + 16; // 492

void CreateAllControls() {
    // ================= Login screen =================
    int colX = 40;
    g_hLoginBadge = MakeCtrl("STATIC", "", colX, 40, 56, 56, SS_OWNERDRAW, 0);
    g_hLoginTitle = MakeCtrl("STATIC", "Secure your vault", colX, 110, 420, 32, 0, 0, g_hFontLarge);
    g_hLoginSubtitle = MakeCtrl("STATIC",
        "Create a master password. It's the only key to your vault -- it can't be recovered.",
        colX, 148, 420, 40, 0, 0, nullptr, true);
    g_hLoginPwLabel = MakeCtrl("STATIC", "Master password", colX, 198, 300, 18, 0, 0, g_hFontSmall, true);
    g_hLoginPw1 = MakeCtrl("EDIT", "", colX, 218, 380, 34, WS_BORDER | WS_TABSTOP | ES_PASSWORD, ID_LOGIN_PW1);
    g_hLoginEye = MakeCtrl("BUTTON", "Show", colX + 384, 218, 56, 34, BTN_STYLE, ID_LOGIN_EYE);
    g_hLoginStrengthBar = MakeCtrl("STATIC", "", colX, 260, 380, 8, SS_OWNERDRAW, 0);
    g_hLoginStrengthLabel = MakeCtrl("STATIC", "", colX, 272, 380, 18, 0, 0, g_hFontSmall, true);
    g_hLoginPw2Label = MakeCtrl("STATIC", "Confirm password", colX, 298, 300, 18, 0, 0, g_hFontSmall, true);
    g_hLoginPw2 = MakeCtrl("EDIT", "", colX, 318, 380, 34, WS_BORDER | WS_TABSTOP | ES_PASSWORD, ID_LOGIN_PW2);
    g_hLoginBtn = MakeCtrl("BUTTON", "Create Vault", colX, 368, 440, 40, BTN_STYLE, ID_LOGIN_BTN);
    g_hLoginStatus = MakeCtrl("STATIC", "", colX, 418, 440, 40, 0, 0, nullptr, true);

    SendMessageW(g_hLoginPw1, EM_SETCUEBANNER, TRUE, (LPARAM)L"At least 8 characters");
    SendMessageW(g_hLoginPw2, EM_SETCUEBANNER, TRUE, (LPARAM)L"Re-enter password");
    MakeEnterSubmit(g_hLoginPw1, ID_LOGIN_BTN);
    MakeEnterSubmit(g_hLoginPw2, ID_LOGIN_BTN);

    // ================= Sidebar (shown once unlocked) =================
    g_hSidebarBadge = MakeCtrl("STATIC", "", 20, 18, 32, 32, SS_OWNERDRAW, 0);
    g_hSidebarBrand = MakeCtrl("STATIC", "My Vault", 60, 24, 130, 24, 0, 0, g_hFontBold);
    g_hNavVault = MakeCtrl("BUTTON", "Vault", 12, 68, 176, 36, BTN_STYLE, ID_NAV_VAULT);
    g_hNavSettings = MakeCtrl("BUTTON", "Settings", 12, 108, 176, 36, BTN_STYLE, ID_NAV_SETTINGS);
    g_hNavLock = MakeCtrl("BUTTON", "Lock vault", 12, 596, 176, 36, BTN_STYLE, ID_NAV_LOCK);

    RECT clientRc; GetClientRect(g_hMain, &clientRc);
    g_hDividerSidebar = CreateWindowExA(0, "STATIC", "", WS_CHILD,
        SIDEBAR_W, 0, 2, clientRc.bottom, g_hMain, (HMENU)0, GetModuleHandleA(NULL), NULL);
    g_hDividerList = CreateWindowExA(0, "STATIC", "", WS_CHILD,
        CONTENT_X + LIST_W + 8, 0, 2, clientRc.bottom, g_hMain, (HMENU)0, GetModuleHandleA(NULL), NULL);

    // ================= Vault list pane =================
    g_hSearch = MakeCtrl("EDIT", "", CONTENT_X, 20, 200, 30, WS_BORDER | WS_TABSTOP, ID_SEARCH);
    SendMessageW(g_hSearch, EM_SETCUEBANNER, TRUE, (LPARAM)L"Search vault");
    g_hAddBtn = MakeCtrl("BUTTON", "+", CONTENT_X + 208, 20, 36, 30, BTN_STYLE, ID_ADD_BTN);

    int chipY = 62, chipH = 26, chipGap = 6;
    int cx = CONTENT_X;
    g_hChipAll = MakeCtrl("BUTTON", "All", cx, chipY, 48, chipH, BTN_STYLE, ID_CHIP_ALL); cx += 48 + chipGap;
    g_hChipFav = MakeCtrl("BUTTON", "Favorites", cx, chipY, 76, chipH, BTN_STYLE, ID_CHIP_FAV); cx += 76 + chipGap + 2;
    g_hChipScrollLeft = MakeCtrl("BUTTON", "<", cx, chipY, 18, chipH, BTN_STYLE, ID_CHIP_SCROLL_LEFT); cx += 18 + 3;
    g_hChipCatSlot = MakeCtrl("BUTTON", "", cx, chipY, 76, chipH, BTN_STYLE, ID_CHIP_CAT_SLOT); cx += 76 + 3;
    g_hChipScrollRight = MakeCtrl("BUTTON", ">", cx, chipY, 18, chipH, BTN_STYLE, ID_CHIP_SCROLL_RIGHT);

    g_hList = MakeCtrl("LISTBOX", "", CONTENT_X, 98, LIST_W, 480,
        WS_BORDER | WS_TABSTOP | WS_VSCROLL | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS | LBS_NOTIFY, ID_LIST);
    g_hVaultStatus = MakeCtrl("STATIC", "", CONTENT_X, 584, LIST_W, 20, 0, 0, g_hFontSmall, true);

    // ================= Detail pane: empty state =================
    g_hDetailEmpty = MakeCtrl("STATIC", "Select a password to view details",
        DETAIL_X, 280, 400, 24, SS_CENTER, 0, nullptr, true);

    // ================= Detail pane: view state =================
    g_hViewAvatar = MakeCtrl("STATIC", "", DETAIL_X, 16, 48, 48, SS_OWNERDRAW, 0);
    g_hViewName = MakeCtrl("STATIC", "", DETAIL_X + 60, 20, 300, 28, 0, 0, g_hFontLarge);
    g_hViewCategory = MakeCtrl("STATIC", "", DETAIL_X + 60, 54, 130, 20, 0, 0, g_hFontSmall, true);
    g_hViewFavBtn = MakeCtrl("BUTTON", "Favorite", DETAIL_X + 200, 52, 110, 22, BS_AUTOCHECKBOX | WS_TABSTOP, ID_VIEW_FAV_BTN);
    g_hViewEditBtn = MakeCtrl("BUTTON", "Edit", DETAIL_X + 284, 16, 60, 28, BTN_STYLE, ID_VIEW_EDIT_BTN);
    g_hViewDeleteBtn = MakeCtrl("BUTTON", "Delete", DETAIL_X + 352, 16, 60, 28, BTN_STYLE, ID_VIEW_DELETE_BTN);

    g_hViewUserLbl = MakeCtrl("STATIC", "USERNAME", DETAIL_X, 92, 300, 18, 0, 0, g_hFontSmall, true);
    g_hViewUserVal = MakeCtrl("EDIT", "", DETAIL_X, 112, 340, 30, WS_BORDER | ES_READONLY, 0);
    g_hViewCopyUser = MakeCtrl("BUTTON", "Copy", DETAIL_X + 346, 112, 50, 30, BTN_STYLE, ID_VIEW_COPY_USER);

    g_hViewPassLbl = MakeCtrl("STATIC", "PASSWORD", DETAIL_X, 156, 300, 18, 0, 0, g_hFontSmall, true);
    g_hViewPassVal = MakeCtrl("EDIT", "", DETAIL_X, 176, 260, 30, WS_BORDER | ES_READONLY | ES_PASSWORD, 0);
    g_hViewShowPass = MakeCtrl("BUTTON", "Show", DETAIL_X + 266, 176, 50, 30, BTN_STYLE, ID_VIEW_SHOW_PASS);
    g_hViewCopyPass = MakeCtrl("BUTTON", "Copy", DETAIL_X + 322, 176, 50, 30, BTN_STYLE, ID_VIEW_COPY_PASS);

    g_hViewSiteLbl = MakeCtrl("STATIC", "WEBSITE", DETAIL_X, 220, 300, 18, 0, 0, g_hFontSmall, true);
    g_hViewSiteVal = MakeCtrl("EDIT", "", DETAIL_X, 240, 340, 30, WS_BORDER | ES_READONLY, 0);
    g_hViewCopySite = MakeCtrl("BUTTON", "Copy", DETAIL_X + 346, 240, 50, 30, BTN_STYLE, ID_VIEW_COPY_SITE);

    g_hViewNotesLbl = MakeCtrl("STATIC", "NOTES", DETAIL_X, 284, 300, 18, 0, 0, g_hFontSmall, true);
    g_hViewNotesVal = MakeCtrl("EDIT", "", DETAIL_X, 304, 396, 70,
        WS_BORDER | ES_READONLY | ES_MULTILINE | WS_VSCROLL, 0);
    SendMessageA(g_hViewPassVal, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);

    // ================= Detail pane: add/edit form =================
    g_hFormTitle = MakeCtrl("STATIC", "Add Entry", DETAIL_X, 16, 400, 28, 0, 0, g_hFontLarge);
    g_hFormNameLbl = MakeCtrl("STATIC", "Name", DETAIL_X, 56, 200, 18, 0, 0, g_hFontSmall, true);
    g_hFormName = MakeCtrl("EDIT", "", DETAIL_X, 76, 396, 28, WS_BORDER | WS_TABSTOP, ID_FORM_NAME);
    g_hFormUserLbl = MakeCtrl("STATIC", "Username", DETAIL_X, 112, 200, 18, 0, 0, g_hFontSmall, true);
    g_hFormUser = MakeCtrl("EDIT", "", DETAIL_X, 132, 396, 28, WS_BORDER | WS_TABSTOP, ID_FORM_USER);
    g_hFormPassLbl = MakeCtrl("STATIC", "Password", DETAIL_X, 168, 200, 18, 0, 0, g_hFontSmall, true);
    g_hFormPass = MakeCtrl("EDIT", "", DETAIL_X, 188, 260, 28, WS_BORDER | WS_TABSTOP | ES_PASSWORD, ID_FORM_PASS);
    g_hFormGen = MakeCtrl("BUTTON", "Generate", DETAIL_X + 266, 188, 130, 28, BTN_STYLE, ID_FORM_GEN);
    g_hFormShowChk = MakeCtrl("BUTTON", "Show password", DETAIL_X, 222, 200, 20, BS_AUTOCHECKBOX | WS_TABSTOP, ID_FORM_SHOWCHK);
    g_hFormStrengthBar = MakeCtrl("STATIC", "", DETAIL_X, 246, 260, 8, SS_OWNERDRAW, 0);
    g_hFormStrengthLabel = MakeCtrl("STATIC", "", DETAIL_X, 258, 260, 18, 0, 0, g_hFontSmall, true);
    g_hFormSiteLbl = MakeCtrl("STATIC", "Website", DETAIL_X, 282, 200, 18, 0, 0, g_hFontSmall, true);
    g_hFormSite = MakeCtrl("EDIT", "", DETAIL_X, 302, 396, 28, WS_BORDER | WS_TABSTOP, ID_FORM_SITE);
    g_hFormCategoryLbl = MakeCtrl("STATIC", "Category", DETAIL_X, 338, 180, 18, 0, 0, g_hFontSmall, true);
    g_hFormCategory = MakeCtrl("COMBOBOX", "", DETAIL_X, 358, 180, 200,
        WS_BORDER | WS_TABSTOP | CBS_DROPDOWN | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS, ID_FORM_CATEGORY);
    g_hFormFavChk = MakeCtrl("BUTTON", "Favorite", DETAIL_X + 200, 362, 140, 20, BS_AUTOCHECKBOX | WS_TABSTOP, ID_FORM_FAVCHK);
    g_hFormNotesLbl = MakeCtrl("STATIC", "Notes", DETAIL_X, 396, 200, 18, 0, 0, g_hFontSmall, true);
    g_hFormNotes = MakeCtrl("EDIT", "", DETAIL_X, 416, 396, 64,
        WS_BORDER | WS_TABSTOP | ES_MULTILINE | WS_VSCROLL, ID_FORM_NOTES);
    g_hFormOk = MakeCtrl("BUTTON", "Save", DETAIL_X, 496, 120, 36, BTN_STYLE, ID_FORM_OK);
    g_hFormCancel = MakeCtrl("BUTTON", "Cancel", DETAIL_X + 128, 496, 120, 36, BTN_STYLE, ID_FORM_CANCEL);

    const char* categories[] = { "", "Personal", "Work", "Finance", "Other" };
    for (auto c : categories) SendMessageA(g_hFormCategory, CB_ADDSTRING, 0, (LPARAM)c);
    SendMessageA(g_hFormPass, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
    MakeEnterSubmit(g_hFormName, ID_FORM_OK);
    MakeEnterSubmit(g_hFormUser, ID_FORM_OK);
    MakeEnterSubmit(g_hFormPass, ID_FORM_OK);
    MakeEnterSubmit(g_hFormSite, ID_FORM_OK);

    // ================= Settings screen =================
    g_hSetTitle = MakeCtrl("STATIC", "Settings", CONTENT_X, 20, 300, 32, 0, 0, g_hFontLarge);
    g_hSecHdr = MakeCtrl("STATIC", "Security", CONTENT_X, 70, 300, 24, 0, 0, g_hFontBold);
    g_hAutoLockLbl = MakeCtrl("STATIC", "Auto-lock", CONTENT_X, 104, 300, 20, 0, 0, g_hFontSmall, true);
    int alx = CONTENT_X;
    g_hAutoInstant = MakeCtrl("BUTTON", "Instant", alx, 126, 80, 32, BTN_STYLE, ID_SET_AUTOLOCK_INSTANT); alx += 84;
    g_hAutoCustom = MakeCtrl("BUTTON", "Custom", alx, 126, 80, 32, BTN_STYLE, ID_SET_AUTOLOCK_CUSTOM); alx += 84;
    g_hAutoCustomMinutesEdit = MakeCtrl("EDIT", "5", alx, 126, 44, 32, WS_BORDER | WS_TABSTOP | ES_NUMBER, ID_SET_AUTOLOCK_MINUTES); alx += 48;
    g_hAutoCustomMinutesLbl = MakeCtrl("STATIC", "min", alx, 132, 32, 20, 0, 0, g_hFontSmall, true); alx += 40;
    g_hAutoNever = MakeCtrl("BUTTON", "Never", alx, 126, 80, 32, BTN_STYLE, ID_SET_AUTOLOCK_NEVER);
    g_hChangePwBtn = MakeCtrl("BUTTON", "Change master password", CONTENT_X, 172, 220, 36, BTN_STYLE, ID_SET_CHANGEPW_BTN);

    g_hBackupHdr = MakeCtrl("STATIC", "Backup", CONTENT_X, 232, 300, 24, 0, 0, g_hFontBold);
    g_hLocalBackupInfo = MakeCtrl("STATIC",
        "Local backups: the last 5 saves are kept automatically in .pwvault\\backups",
        CONTENT_X, 260, 480, 36, 0, 0, g_hFontSmall, true);
    g_hSecondaryLbl = MakeCtrl("STATIC", "Secondary backup location", CONTENT_X, 304, 300, 20, 0, 0, g_hFontSmall, true);
    g_hSecondaryPathDisplay = MakeCtrl("EDIT", "Not configured", CONTENT_X, 326, 380, 28, WS_BORDER | ES_READONLY, 0);
    g_hChooseFolderBtn = MakeCtrl("BUTTON", "Choose Folder...", CONTENT_X + 390, 326, 150, 28, BTN_STYLE, ID_SET_CHOOSE_FOLDER);
    g_hRemoveBackupBtn = MakeCtrl("BUTTON", "Remove Backup Location", CONTENT_X, 362, 180, 30, BTN_STYLE, ID_SET_REMOVE_BACKUP);

    g_hAboutText = MakeCtrl("STATIC",
        "pwvault -- vault format 3. AES-256-CTR + HMAC-SHA256, PBKDF2 (200,000 iterations).",
        CONTENT_X, 406, 480, 40, 0, 0, g_hFontSmall, true);

    // ================= Change master password screen =================
    g_hCpTitle = MakeCtrl("STATIC", "Change Master Password", CONTENT_X, 20, 400, 28, 0, 0, g_hFontLarge);
    g_hCpPw1Lbl = MakeCtrl("STATIC", "New master password", CONTENT_X, 64, 300, 18, 0, 0, g_hFontSmall, true);
    g_hCpPw1 = MakeCtrl("EDIT", "", CONTENT_X, 84, 340, 30, WS_BORDER | WS_TABSTOP | ES_PASSWORD, ID_CP_PW1);
    g_hCpStrengthBar = MakeCtrl("STATIC", "", CONTENT_X, 120, 340, 8, SS_OWNERDRAW, 0);
    g_hCpStrengthLabel = MakeCtrl("STATIC", "", CONTENT_X, 132, 340, 18, 0, 0, g_hFontSmall, true);
    g_hCpPw2Lbl = MakeCtrl("STATIC", "Confirm", CONTENT_X, 156, 300, 18, 0, 0, g_hFontSmall, true);
    g_hCpPw2 = MakeCtrl("EDIT", "", CONTENT_X, 176, 340, 30, WS_BORDER | WS_TABSTOP | ES_PASSWORD, ID_CP_PW2);
    g_hCpStatus = MakeCtrl("STATIC", "", CONTENT_X, 212, 400, 22, 0, 0, nullptr, true);
    g_hCpOk = MakeCtrl("BUTTON", "Save", CONTENT_X, 246, 120, 34, BTN_STYLE, ID_CP_OK);
    g_hCpCancel = MakeCtrl("BUTTON", "Cancel", CONTENT_X + 128, 246, 120, 34, BTN_STYLE, ID_CP_CANCEL);
    MakeEnterSubmit(g_hCpPw1, ID_CP_OK);
    MakeEnterSubmit(g_hCpPw2, ID_CP_OK);
}

// ---- visibility management ----

void HideAll(std::initializer_list<HWND> ctrls) {
    for (auto h : ctrls) ShowWindow(h, SW_HIDE);
}
void ShowAll(std::initializer_list<HWND> ctrls) {
    for (auto h : ctrls) ShowWindow(h, SW_SHOW);
}

void UpdateVisibility() {
    // Login screen controls
    HideAll({ g_hLoginBadge, g_hLoginTitle, g_hLoginSubtitle, g_hLoginPwLabel, g_hLoginPw1, g_hLoginEye,
              g_hLoginStrengthBar, g_hLoginStrengthLabel, g_hLoginPw2Label, g_hLoginPw2, g_hLoginBtn, g_hLoginStatus });
    // Sidebar
    HideAll({ g_hSidebarBadge, g_hSidebarBrand, g_hNavVault, g_hNavSettings, g_hNavLock,
              g_hDividerSidebar, g_hDividerList });
    // Vault list pane
    HideAll({ g_hSearch, g_hAddBtn, g_hChipAll, g_hChipFav, g_hChipScrollLeft, g_hChipCatSlot, g_hChipScrollRight,
              g_hList, g_hVaultStatus });
    // Detail: empty
    HideAll({ g_hDetailEmpty });
    // Detail: view
    HideAll({ g_hViewAvatar, g_hViewName, g_hViewCategory, g_hViewFavBtn, g_hViewEditBtn, g_hViewDeleteBtn,
              g_hViewUserLbl, g_hViewUserVal, g_hViewCopyUser,
              g_hViewPassLbl, g_hViewPassVal, g_hViewShowPass, g_hViewCopyPass,
              g_hViewSiteLbl, g_hViewSiteVal, g_hViewCopySite,
              g_hViewNotesLbl, g_hViewNotesVal });
    // Detail: form
    HideAll({ g_hFormTitle, g_hFormNameLbl, g_hFormName, g_hFormUserLbl, g_hFormUser,
              g_hFormPassLbl, g_hFormPass, g_hFormGen, g_hFormShowChk,
              g_hFormStrengthBar, g_hFormStrengthLabel,
              g_hFormSiteLbl, g_hFormSite, g_hFormCategoryLbl, g_hFormCategory, g_hFormFavChk,
              g_hFormNotesLbl, g_hFormNotes, g_hFormOk, g_hFormCancel });
    // Settings
    HideAll({ g_hSetTitle, g_hSecHdr, g_hAutoLockLbl, g_hAutoInstant, g_hAutoCustom,
              g_hAutoCustomMinutesEdit, g_hAutoCustomMinutesLbl, g_hAutoNever,
              g_hChangePwBtn, g_hAboutText,
              g_hBackupHdr, g_hLocalBackupInfo, g_hSecondaryLbl, g_hSecondaryPathDisplay,
              g_hChooseFolderBtn, g_hRemoveBackupBtn });
    // Change password
    HideAll({ g_hCpTitle, g_hCpPw1Lbl, g_hCpPw1, g_hCpStrengthBar, g_hCpStrengthLabel,
              g_hCpPw2Lbl, g_hCpPw2, g_hCpOk, g_hCpCancel, g_hCpStatus });

    if (g_appState == AppState::LOGIN) {
        ShowAll({ g_hLoginBadge, g_hLoginTitle, g_hLoginSubtitle, g_hLoginPwLabel, g_hLoginPw1, g_hLoginEye,
                  g_hLoginBtn, g_hLoginStatus });
        if (!g_vaultFileExisted) {
            ShowAll({ g_hLoginStrengthBar, g_hLoginStrengthLabel, g_hLoginPw2Label, g_hLoginPw2 });
        }
        SetWindowTextA(g_hMain, "pwvault (locked)");
        SetFocus(g_hLoginPw1);
        return;
    }

    // Unlocked: sidebar always visible
    ShowAll({ g_hSidebarBadge, g_hSidebarBrand, g_hNavVault, g_hNavSettings, g_hNavLock, g_hDividerSidebar });
    SetWindowTextA(g_hMain, "pwvault");

    if (g_navView == NavView::SETTINGS) {
        ShowAll({ g_hSetTitle, g_hSecHdr, g_hAutoLockLbl, g_hAutoInstant, g_hAutoCustom,
                  g_hAutoCustomMinutesEdit, g_hAutoCustomMinutesLbl, g_hAutoNever,
                  g_hChangePwBtn, g_hAboutText,
                  g_hBackupHdr, g_hLocalBackupInfo, g_hSecondaryLbl, g_hSecondaryPathDisplay, g_hChooseFolderBtn });
        SetWindowTextA(g_hSecondaryPathDisplay,
            g_secondaryBackupDir.empty() ? "Not configured" : g_secondaryBackupDir.c_str());
        ShowWindow(g_hRemoveBackupBtn, g_secondaryBackupDir.empty() ? SW_HIDE : SW_SHOW);
        return;
    }
    if (g_navView == NavView::CHANGEPW) {
        ShowAll({ g_hCpTitle, g_hCpPw1Lbl, g_hCpPw1, g_hCpStrengthBar, g_hCpStrengthLabel,
                  g_hCpPw2Lbl, g_hCpPw2, g_hCpOk, g_hCpCancel, g_hCpStatus });
        SetFocus(g_hCpPw1);
        return;
    }

    // NavView::VAULT
    ShowAll({ g_hSearch, g_hAddBtn, g_hChipAll, g_hChipFav, g_hList, g_hVaultStatus,
              g_hDividerList });
    RefreshChipCategorySlot();

    switch (g_detailMode) {
    case DetailMode::EMPTY:
        ShowAll({ g_hDetailEmpty });
        break;
    case DetailMode::VIEW:
        ShowAll({ g_hViewAvatar, g_hViewName, g_hViewCategory, g_hViewFavBtn, g_hViewEditBtn, g_hViewDeleteBtn,
                  g_hViewUserLbl, g_hViewUserVal, g_hViewCopyUser,
                  g_hViewPassLbl, g_hViewPassVal, g_hViewShowPass, g_hViewCopyPass,
                  g_hViewSiteLbl, g_hViewSiteVal, g_hViewCopySite,
                  g_hViewNotesLbl, g_hViewNotesVal });
        break;
    case DetailMode::ADD:
    case DetailMode::EDIT:
        ShowAll({ g_hFormTitle, g_hFormNameLbl, g_hFormName, g_hFormUserLbl, g_hFormUser,
                  g_hFormPassLbl, g_hFormPass, g_hFormGen, g_hFormShowChk,
                  g_hFormStrengthBar, g_hFormStrengthLabel,
                  g_hFormSiteLbl, g_hFormSite, g_hFormCategoryLbl, g_hFormCategory, g_hFormFavChk,
                  g_hFormNotesLbl, g_hFormNotes, g_hFormOk, g_hFormCancel });
        SetFocus(g_hFormUser);
        break;
    }
}

void RefreshEntryList() {
    RebuildChipCategories();
    RefreshChipCategorySlot();
    SendMessageA(g_hList, LB_RESETCONTENT, 0, 0);
    for (auto& n : GetFilteredSortedNames()) SendMessageA(g_hList, LB_ADDSTRING, 0, (LPARAM)n.c_str());
    InvalidateRect(g_hList, NULL, TRUE);
}

std::string GetSelectedListName() {
    int sel = (int)SendMessageA(g_hList, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR) return "";
    char buf[512];
    SendMessageA(g_hList, LB_GETTEXT, sel, (LPARAM)buf);
    return std::string(buf);
}

void PopulateDetailView(const Entry& e) {
    SetWindowTextA(g_hViewName, e.name.c_str());
    SetWindowTextA(g_hViewCategory, e.category.empty() ? "Uncategorized" : e.category.c_str());
    SendMessageA(g_hViewFavBtn, BM_SETCHECK, e.favorite ? BST_CHECKED : BST_UNCHECKED, 0);
    SetWindowTextA(g_hViewUserVal, e.username.c_str());
    SetWindowTextA(g_hViewPassVal, e.password.c_str());
    SetWindowTextA(g_hViewSiteVal, e.website.c_str());
    SetWindowTextA(g_hViewNotesVal, e.notes.c_str());
    g_detailPasswordVisible = false;
    SendMessageA(g_hViewPassVal, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
    SetWindowTextA(g_hViewShowPass, "Show");
    InvalidateRect(g_hViewAvatar, NULL, TRUE);
}

void PopulateFormForAdd() {
    g_editorIsNew = true;
    SetWindowTextA(g_hFormTitle, "Add Entry");
    SetWindowTextA(g_hFormName, "");
    EnableWindow(g_hFormName, TRUE);
    SetWindowTextA(g_hFormUser, "");
    SetWindowTextA(g_hFormPass, "");
    SetWindowTextA(g_hFormSite, "");
    SetWindowTextA(g_hFormNotes, "");
    SetWindowTextA(g_hFormCategory, "");
    SendMessageA(g_hFormFavChk, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessageA(g_hFormShowChk, BM_SETCHECK, BST_UNCHECKED, 0);
    g_formPasswordVisible = false;
    SendMessageA(g_hFormPass, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
    InvalidateRect(g_hFormStrengthBar, NULL, TRUE);
    SetWindowTextA(g_hFormStrengthLabel, "");
}

void PopulateFormForEdit(const Entry& e) {
    g_editorIsNew = false;
    SetWindowTextA(g_hFormTitle, "Edit Entry");
    SetWindowTextA(g_hFormName, e.name.c_str());
    EnableWindow(g_hFormName, FALSE);
    SetWindowTextA(g_hFormUser, e.username.c_str());
    SetWindowTextA(g_hFormPass, e.password.c_str());
    SetWindowTextA(g_hFormSite, e.website.c_str());
    SetWindowTextA(g_hFormNotes, e.notes.c_str());
    SetWindowTextA(g_hFormCategory, e.category.c_str());
    SendMessageA(g_hFormFavChk, BM_SETCHECK, e.favorite ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageA(g_hFormShowChk, BM_SETCHECK, BST_UNCHECKED, 0);
    g_formPasswordVisible = false;
    SendMessageA(g_hFormPass, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
    InvalidateRect(g_hFormStrengthBar, NULL, TRUE);
    {
        int s = ComputePasswordStrength(e.password);
        const char* labels[] = { "", "Weak", "Fair", "Strong" };
        SetWindowTextA(g_hFormStrengthLabel, labels[s]);
    }
}

void UpdateChipStyles() {
    InvalidateRect(g_hChipAll, NULL, TRUE);
    InvalidateRect(g_hChipFav, NULL, TRUE);
    InvalidateRect(g_hChipCatSlot, NULL, TRUE);
}

// ---- auto-lock ----

void DoLock(); // fwd decl, defined below

// Sets (or extends) the deadline and arms a 1-second heartbeat to check it.
// Deliberately NOT a single long-duration SetTimer: WM_TIMER is the lowest
// -priority Windows message and only gets synthesized once the queue is
// fully idle, so a single 60000ms+ timer can be starved indefinitely by
// ordinary mouse-move traffic while the window has focus -- which looks
// exactly like "never locks until I click away". A 1-second timer checking
// an absolute GetTickCount64() deadline is effectively immune to that.
void ApplyAutoLockTimer() {
    KillTimer(g_hMain, TIMER_AUTOLOCK);
    if (g_appState != AppState::UNLOCKED) return;
    if (g_autoLock != AutoLockMode::CUSTOM) return; // INSTANT handled on deactivate; NEVER has no timer
    int minutes = g_autoLockMinutes > 0 ? g_autoLockMinutes : 5;
    g_autoLockDeadlineTick = GetTickCount64() + (ULONGLONG)minutes * 60ULL * 1000ULL;
    SetTimer(g_hMain, TIMER_AUTOLOCK, 1000, NULL);
}

void ResetAutoLockTimer() {
    if (g_appState == AppState::UNLOCKED && g_autoLock == AutoLockMode::CUSTOM) {
        ApplyAutoLockTimer(); // extends the deadline from now
    }
}

void UpdateAutoLockButtonStyles() {
    InvalidateRect(g_hAutoInstant, NULL, TRUE);
    InvalidateRect(g_hAutoCustom, NULL, TRUE);
    InvalidateRect(g_hAutoNever, NULL, TRUE);
}

void SaveConfig(); // fwd decl, defined below (with the rest of config persistence)

void OnAutoLockOptionClicked(AutoLockMode mode) {
    g_autoLock = mode;
    UpdateAutoLockButtonStyles();
    ApplyAutoLockTimer();
    SaveConfig();
}

void OnAutoLockMinutesChanged() {
    std::string text = GetEditText(g_hAutoCustomMinutesEdit);
    int minutes = text.empty() ? 0 : std::atoi(text.c_str());
    if (minutes < 1) minutes = 1;
    if (minutes > 999) minutes = 999;
    g_autoLockMinutes = minutes;
    if (g_autoLock == AutoLockMode::CUSTOM) ApplyAutoLockTimer();
    SaveConfig();
}

// ---- login ----

void UpdateStrengthUI(HWND passwordEdit, HWND bar, HWND label) {
    std::string pw = GetEditText(passwordEdit);
    int s = ComputePasswordStrength(pw);
    InvalidateRect(bar, NULL, TRUE);
    const char* labels[] = { "", "Weak", "Fair", "Strong" };
    SetWindowTextA(label, labels[s]);
}

void UpdateLoginStrengthUI() {
    UpdateStrengthUI(g_hLoginPw1, g_hLoginStrengthBar, g_hLoginStrengthLabel);
}

void UpdateFormStrengthUI() {
    UpdateStrengthUI(g_hFormPass, g_hFormStrengthBar, g_hFormStrengthLabel);
}

void UpdateCpStrengthUI() {
    UpdateStrengthUI(g_hCpPw1, g_hCpStrengthBar, g_hCpStrengthLabel);
}

void OnLoginEyeToggle() {
    static bool visible = false;
    visible = !visible;
    SendMessageA(g_hLoginPw1, EM_SETPASSWORDCHAR, visible ? 0 : (WPARAM)'*', 0);
    RedrawWindow(g_hLoginPw1, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
    SetWindowTextA(g_hLoginEye, visible ? "Hide" : "Show");
}

// ---- secondary backup location ----

std::string ConfigPath() {
    size_t slashPos = g_vault.path.find_last_of("\\/");
    std::string dir = (slashPos == std::string::npos) ? "." : g_vault.path.substr(0, slashPos);
    return dir + "\\config.txt";
}

// Not sensitive data -- just a folder path and a couple of settings -- so
// this is deliberately plain text. Format: line 1 = secondary backup dir
// (may be blank), line 2 = auto-lock mode, line 3 = custom minutes. Lines
// 2-3 are new; a config.txt from an older version that only has line 1
// still loads fine and just falls back to the defaults for the rest.
void LoadConfig() {
    std::ifstream f(ConfigPath());
    if (!f) return;
    std::getline(f, g_secondaryBackupDir);

    std::string modeStr;
    if (std::getline(f, modeStr)) {
        if (modeStr == "INSTANT") g_autoLock = AutoLockMode::INSTANT;
        else if (modeStr == "NEVER") g_autoLock = AutoLockMode::NEVER;
        else if (modeStr == "CUSTOM") g_autoLock = AutoLockMode::CUSTOM;
    }
    std::string minutesStr;
    if (std::getline(f, minutesStr) && !minutesStr.empty()) {
        int minutes = std::atoi(minutesStr.c_str());
        if (minutes >= 1 && minutes <= 999) g_autoLockMinutes = minutes;
    }
}

void SaveConfig() {
    std::ofstream f(ConfigPath(), std::ios::trunc);
    const char* modeStr = g_autoLock == AutoLockMode::INSTANT ? "INSTANT"
                         : g_autoLock == AutoLockMode::NEVER ? "NEVER"
                         : "CUSTOM";
    f << g_secondaryBackupDir << "\n" << modeStr << "\n" << g_autoLockMinutes;
}

// Opens the classic Windows "choose a folder" dialog. Returns "" if the
// user cancelled.
std::string PickFolder(HWND owner) {
    BROWSEINFOA bi = {};
    bi.hwndOwner = owner;
    bi.lpszTitle = "Choose a folder for vault backups";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
    if (!pidl) return "";
    char path[MAX_PATH] = { 0 };
    SHGetPathFromIDListA(pidl, path);
    CoTaskMemFree(pidl);
    return std::string(path);
}

// Mirrors the just-written primary vault file to the optional secondary
// location, with its own independent backup rotation -- so even total loss
// of the primary drive/folder doesn't lose the vault. Failure here is
// reported but never blocks the primary save from having already succeeded.
bool MirrorToSecondaryLocation(std::string& warnOut) {
    if (g_secondaryBackupDir.empty()) return true;

    if (!CreateDirectoryA(g_secondaryBackupDir.c_str(), NULL) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        warnOut = "Could not reach the secondary backup location.";
        return false;
    }
    std::string destVault = g_secondaryBackupDir + "\\vault.dat";
    RotateBackups(destVault);

    if (!CopyFileA(g_vault.path.c_str(), destVault.c_str(), FALSE)) {
        warnOut = "Could not write to the secondary backup location.";
        return false;
    }
    return true;
}

// All GUI save paths should go through this instead of calling save_vault()
// directly, so the secondary mirror never gets forgotten at a new call site.
bool DoSaveVault(std::string& err) {
    if (!save_vault(g_vault, g_masterPassword, err)) return false;
    std::string warn;
    if (!MirrorToSecondaryLocation(warn)) {
        SetStatus(g_hVaultStatus, warn, true);
    }
    return true;
}

void OnChooseBackupFolder(HWND hwnd) {
    std::string folder = PickFolder(hwnd);
    if (folder.empty()) return;
    g_secondaryBackupDir = folder;
    SaveConfig();
    std::string warn;
    MirrorToSecondaryLocation(warn); // seed it immediately rather than waiting for the next edit
    UpdateVisibility();
    if (!warn.empty()) MessageBoxA(hwnd, warn.c_str(), "pwvault", MB_ICONWARNING);
}

void OnRemoveBackupFolder() {
    g_secondaryBackupDir.clear();
    SaveConfig();
    UpdateVisibility();
}


void OnLoginSubmit() {
    std::string pw1 = GetEditText(g_hLoginPw1);
    if (pw1.empty()) { SetStatus(g_hLoginStatus, "Password cannot be empty."); return; }

    if (!g_vaultFileExisted) {
        std::string pw2 = GetEditText(g_hLoginPw2);
        if (pw1 != pw2) { SetStatus(g_hLoginStatus, "Passwords do not match."); return; }
        if (pw1.size() < 8) { SetStatus(g_hLoginStatus, "Use at least 8 characters."); return; }
        g_vault.entries.clear();
        g_masterPassword = pw1;
        std::string err;
        if (!DoSaveVault(err)) {
            SetStatus(g_hLoginStatus, err);
            g_masterPassword.clear();
            return;
        }
        g_vaultFileExisted = true;
        g_appState = AppState::UNLOCKED;
        g_navView = NavView::VAULT;
        g_detailMode = DetailMode::EMPTY;
        RefreshEntryList();
        UpdateVisibility();
        ApplyAutoLockTimer();
        return;
    }

    std::string err;
    bool migrated = false;
    if (!load_vault(g_vault, pw1, err, migrated)) {
        SetStatus(g_hLoginStatus, err);
        SetWindowTextA(g_hLoginPw1, "");
        SetFocus(g_hLoginPw1);
        return;
    }
    g_masterPassword = pw1;
    if (migrated) {
        std::string saveErr;
        DoSaveVault(saveErr); // upgrade file to v3 silently
    }
    g_appState = AppState::UNLOCKED;
    g_navView = NavView::VAULT;
    g_detailMode = DetailMode::EMPTY;
    RefreshEntryList();
    UpdateVisibility();
    ApplyAutoLockTimer();
}

void DoLock() {
    ClearSensitiveMemory();
    g_vaultFileExisted = file_exists(g_vault.path);
    g_appState = AppState::LOGIN;
    g_navView = NavView::VAULT;
    g_detailMode = DetailMode::EMPTY;
    g_selectedEntryName.clear();
    g_searchText.clear();
    g_activeChip = "All";
    KillTimer(g_hMain, TIMER_AUTOLOCK);

    SetWindowTextA(g_hLoginBtn, g_vaultFileExisted ? "Unlock" : "Create Vault");
    SetWindowTextA(g_hLoginTitle, g_vaultFileExisted ? "Unlock your vault" : "Secure your vault");
    SetWindowTextA(g_hLoginSubtitle, g_vaultFileExisted
        ? "Enter your master password to continue."
        : "Create a master password. It's the only key to your vault -- it can't be recovered.");
    SetWindowTextA(g_hLoginPw1, "");
    SetWindowTextA(g_hLoginPw2, "");
    SetWindowTextA(g_hSearch, "");
    SetWindowTextA(g_hLoginStatus, "");
    UpdateVisibility();
}

// ---- nav ----

void OnNavClicked(NavView view) {
    g_navView = view;
    if (view == NavView::VAULT) {
        g_detailMode = DetailMode::EMPTY;
        RefreshEntryList();
    }
    UpdateVisibility();
}

// ---- vault list / detail ----

void OnSearchChanged() {
    g_searchText = GetEditText(g_hSearch);
    RefreshEntryList();
}

void OnChipClicked(const std::string& chip) {
    g_activeChip = chip;
    UpdateChipStyles();
    RefreshEntryList();
}

void OnListSelectionChanged() {
    std::string name = GetSelectedListName();
    if (name.empty()) return;
    g_selectedEntryName = name;
    Entry* e = FindEntry(name);
    if (!e) return;
    g_detailMode = DetailMode::VIEW;
    PopulateDetailView(*e);
    UpdateVisibility();
}

void OnAdd() {
    PopulateFormForAdd();
    g_detailMode = DetailMode::ADD;
    UpdateVisibility();
}

void OnEditSelected() {
    if (g_selectedEntryName.empty()) return;
    Entry* e = FindEntry(g_selectedEntryName);
    if (!e) return;
    PopulateFormForEdit(*e);
    g_detailMode = DetailMode::EDIT;
    UpdateVisibility();
}

void OnFormOk(HWND hwnd) {
    std::string name = g_editorIsNew ? GetEditText(g_hFormName) : g_selectedEntryName;
    std::string user = GetEditText(g_hFormUser);
    std::string pass = GetEditText(g_hFormPass);
    std::string site = GetEditText(g_hFormSite);
    std::string notes = GetEditText(g_hFormNotes);
    std::string category = GetEditText(g_hFormCategory);
    bool favorite = SendMessageA(g_hFormFavChk, BM_GETCHECK, 0, 0) == BST_CHECKED;

    if (name.empty()) { MessageBoxA(hwnd, "Name cannot be empty.", "pwvault", MB_ICONWARNING); return; }

    if (g_editorIsNew) {
        if (FindEntry(name)) {
            MessageBoxA(hwnd, "An entry with that name already exists.", "pwvault", MB_ICONWARNING);
            return;
        }
        Entry e;
        e.name = name; e.username = user; e.password = pass; e.website = site;
        e.notes = notes; e.category = category; e.favorite = favorite;
        g_vault.entries.push_back(e);
    } else {
        Entry* e = FindEntry(g_selectedEntryName);
        if (e) {
            e->username = user; e->password = pass; e->website = site;
            e->notes = notes; e->category = category; e->favorite = favorite;
        }
    }

    std::string err;
    if (!DoSaveVault(err)) MessageBoxA(hwnd, err.c_str(), "pwvault", MB_ICONERROR);

    g_selectedEntryName = name;
    g_detailMode = DetailMode::VIEW;
    RefreshEntryList();
    Entry* saved = FindEntry(name);
    if (saved) PopulateDetailView(*saved);
    UpdateVisibility();
    SetStatus(g_hVaultStatus, std::string(g_editorIsNew ? "Added '" : "Saved '") + name + "'.", true);
}

void OnFormCancel() {
    g_detailMode = g_selectedEntryName.empty() ? DetailMode::EMPTY : DetailMode::VIEW;
    if (g_detailMode == DetailMode::VIEW) {
        Entry* e = FindEntry(g_selectedEntryName);
        if (e) PopulateDetailView(*e);
        else g_detailMode = DetailMode::EMPTY;
    }
    UpdateVisibility();
}

void OnFormGen() {
    std::string pw = generate_password(20, true, true, true, true);
    SetWindowTextA(g_hFormPass, pw.c_str());
}

void OnFormShowToggle() {
    bool show = SendMessageA(g_hFormShowChk, BM_GETCHECK, 0, 0) == BST_CHECKED;
    SendMessageA(g_hFormPass, EM_SETPASSWORDCHAR, show ? 0 : (WPARAM)'*', 0);
    RedrawWindow(g_hFormPass, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
}

void OnDeleteSelected(HWND hwnd) {
    if (g_selectedEntryName.empty()) return;
    std::string q = "Delete entry '" + g_selectedEntryName + "'?";
    if (MessageBoxA(hwnd, q.c_str(), "pwvault", MB_YESNO | MB_ICONQUESTION) != IDYES) return;

    auto it = std::find_if(g_vault.entries.begin(), g_vault.entries.end(),
                            [&](const Entry& e) { return e.name == g_selectedEntryName; });
    if (it != g_vault.entries.end()) g_vault.entries.erase(it);
    std::string err;
    if (!DoSaveVault(err)) MessageBoxA(hwnd, err.c_str(), "pwvault", MB_ICONERROR);

    std::string removed = g_selectedEntryName;
    g_selectedEntryName.clear();
    g_detailMode = DetailMode::EMPTY;
    RefreshEntryList();
    UpdateVisibility();
    SetStatus(g_hVaultStatus, "Removed '" + removed + "'.", true);
}

void OnViewShowPassToggle() {
    g_detailPasswordVisible = !g_detailPasswordVisible;
    SendMessageA(g_hViewPassVal, EM_SETPASSWORDCHAR, g_detailPasswordVisible ? 0 : (WPARAM)'*', 0);
    RedrawWindow(g_hViewPassVal, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
    SetWindowTextA(g_hViewShowPass, g_detailPasswordVisible ? "Hide" : "Show");
}

void OnViewFavToggle() {
    if (g_selectedEntryName.empty()) return;
    Entry* e = FindEntry(g_selectedEntryName);
    if (!e) return;
    e->favorite = SendMessageA(g_hViewFavBtn, BM_GETCHECK, 0, 0) == BST_CHECKED;
    std::string err;
    DoSaveVault(err);
    if (g_activeChip == "Favorites") RefreshEntryList();
}

void OnCopyUsername(HWND hwnd) {
    Entry* e = FindEntry(g_selectedEntryName);
    if (!e) return;
    CopyToClipboard(hwnd, e->username);
    SetStatus(g_hVaultStatus, "Username copied.", true);
}
void OnCopyPassword(HWND hwnd) {
    Entry* e = FindEntry(g_selectedEntryName);
    if (!e) return;
    CopyToClipboard(hwnd, e->password);
    SetStatus(g_hVaultStatus, "Password copied (clipboard clears in 20s).", true);
}
void OnCopyWebsite(HWND hwnd) {
    Entry* e = FindEntry(g_selectedEntryName);
    if (!e) return;
    CopyToClipboard(hwnd, e->website);
    SetStatus(g_hVaultStatus, "Website copied.", true);
}

// ---- settings / change password ----

void OnChangeMasterPasswordClicked() {
    SetWindowTextA(g_hCpPw1, "");
    SetWindowTextA(g_hCpPw2, "");
    SetWindowTextA(g_hCpStatus, "");
    InvalidateRect(g_hCpStrengthBar, NULL, TRUE);
    SetWindowTextA(g_hCpStrengthLabel, "");
    g_navView = NavView::CHANGEPW;
    UpdateVisibility();
}

void OnCpOk(HWND hwnd) {
    std::string p1 = GetEditText(g_hCpPw1);
    std::string p2 = GetEditText(g_hCpPw2);
    if (p1.empty()) { SetWindowTextA(g_hCpStatus, "Password cannot be empty."); return; }
    if (p1 != p2) { SetWindowTextA(g_hCpStatus, "Passwords do not match."); return; }
    std::string err;
    std::string oldPassword = g_masterPassword;
    g_masterPassword = p1;
    if (!DoSaveVault(err)) {
        g_masterPassword = oldPassword;
        MessageBoxA(hwnd, err.c_str(), "pwvault", MB_ICONERROR);
        return;
    }
    g_navView = NavView::SETTINGS;
    UpdateVisibility();
    SetStatus(g_hVaultStatus, "Master password changed.", true);
}

void OnCpCancel() {
    g_navView = NavView::SETTINGS;
    UpdateVisibility();
}

// ---- owner-draw helpers: which buttons are "selected/toggled" or "primary" ----

bool IsChipSelected(int id) {
    if (id == ID_CHIP_ALL) return g_activeChip == "All";
    if (id == ID_CHIP_FAV) return g_activeChip == "Favorites";
    if (id == ID_CHIP_CAT_SLOT) {
        return !g_chipCategories.empty() && g_activeChip == g_chipCategories[g_chipCatIndex];
    }
    return false;
}
bool IsNavSelected(int id) {
    if (id == ID_NAV_VAULT) return g_navView == NavView::VAULT;
    if (id == ID_NAV_SETTINGS) return (g_navView == NavView::SETTINGS || g_navView == NavView::CHANGEPW);
    return false;
}
bool IsAutoLockSelected(int id) {
    if (id == ID_SET_AUTOLOCK_INSTANT) return g_autoLock == AutoLockMode::INSTANT;
    if (id == ID_SET_AUTOLOCK_CUSTOM) return g_autoLock == AutoLockMode::CUSTOM;
    if (id == ID_SET_AUTOLOCK_NEVER) return g_autoLock == AutoLockMode::NEVER;
    return false;
}
bool IsPrimaryButton(int id) {
    return id == ID_LOGIN_BTN || id == ID_FORM_OK || id == ID_CP_OK;
}

void DrawOwnerButton(DRAWITEMSTRUCT* dis) {
    Gdiplus::Graphics g(dis->hDC);
    Gdiplus::Rect r(dis->rcItem.left, dis->rcItem.top,
                     dis->rcItem.right - dis->rcItem.left, dis->rcItem.bottom - dis->rcItem.top);
    int id = dis->CtlID;
    bool disabled = (dis->itemState & ODS_DISABLED) != 0;
    bool toggled = !disabled && (IsChipSelected(id) || IsNavSelected(id) || IsAutoLockSelected(id));
    bool primary = !disabled && IsPrimaryButton(id);
    bool pressed = (dis->itemState & ODS_SELECTED) != 0;

    Gdiplus::Color fill, border, textColor;
    if (disabled) {
        fill = GC(g_colBg);
        border = GC(g_colBorder, 90);
        textColor = GC(g_colMuted, 130);
    } else if (toggled) {
        fill = GC(g_colAccent, pressed ? 70 : 46);
        border = GC(g_colAccent);
        textColor = GC(g_colAccent);
    } else if (primary) {
        fill = pressed ? GC(g_colAccent, 40) : GC(g_colBg);
        border = GC(g_colAccent);
        textColor = GC(g_colAccent);
    } else {
        fill = pressed ? GC(g_colSurface) : GC(g_colBg);
        border = GC(g_colBorder);
        textColor = GC(g_colText);
    }

    int radius = (r.Height <= 30) ? 6 : 8;
    FillRoundedRect(g, r, radius, fill);
    Gdiplus::Rect borderR(r.X + 1, r.Y + 1, r.Width - 2, r.Height - 2);
    DrawRoundedRectBorder(g, borderR, radius, border, 1.2f);

    char buf[256];
    GetWindowTextA(dis->hwndItem, buf, sizeof(buf));
    Gdiplus::RectF textRect((Gdiplus::REAL)r.X, (Gdiplus::REAL)r.Y, (Gdiplus::REAL)r.Width, (Gdiplus::REAL)r.Height);
    DrawCenteredText(g, buf, g_hFont, textRect, textColor);
}

BOOL HandleDrawItem(DRAWITEMSTRUCT* dis) {
    if (dis->CtlType == ODT_BUTTON) {
        DrawOwnerButton(dis);
        return TRUE;
    }
    if (dis->CtlType == ODT_STATIC) {
        Gdiplus::Graphics g(dis->hDC);
        Gdiplus::Rect r(dis->rcItem.left, dis->rcItem.top,
                         dis->rcItem.right - dis->rcItem.left, dis->rcItem.bottom - dis->rcItem.top);

        if (dis->hwndItem == g_hLoginBadge || dis->hwndItem == g_hSidebarBadge) {
            int radius = (dis->hwndItem == g_hSidebarBadge) ? 8 : 14;
            FillRoundedRect(g, r, radius, GC(g_colAccent, 60));
            Gdiplus::Rect iconBox(r.X + r.Width / 4, r.Y + r.Height / 4, r.Width / 2, r.Height / 2);
            DrawPadlockIcon(g, iconBox, GC(g_colAccent));
            return TRUE;
        }
        if (dis->hwndItem == g_hViewAvatar) {
            Gdiplus::GraphicsPath path;
            path.AddEllipse(r);
            Gdiplus::SolidBrush brush(GC(g_colSurface));
            g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
            g.FillPath(&brush, &path);
            Gdiplus::Pen pen(GC(g_colBorder), 1.0f);
            g.DrawPath(&pen, &path);
            Gdiplus::RectF tr((Gdiplus::REAL)r.X, (Gdiplus::REAL)r.Y, (Gdiplus::REAL)r.Width, (Gdiplus::REAL)r.Height);
            DrawCenteredText(g, InitialOf(g_selectedEntryName), g_hFontBold, tr, GC(g_colText));
            return TRUE;
        }
        if (dis->hwndItem == g_hLoginStrengthBar || dis->hwndItem == g_hFormStrengthBar ||
            dis->hwndItem == g_hCpStrengthBar) {
            HWND sourceEdit = (dis->hwndItem == g_hLoginStrengthBar) ? g_hLoginPw1
                             : (dis->hwndItem == g_hFormStrengthBar) ? g_hFormPass
                             : g_hCpPw1;
            int strength = ComputePasswordStrength(GetEditText(sourceEdit));
            int gap = 8;
            int segW = (r.Width - 2 * gap) / 3;
            for (int i = 0; i < 3; i++) {
                Gdiplus::Rect seg(r.X + i * (segW + gap), r.Y, segW, r.Height);
                Gdiplus::Color c = (i < strength) ? GC(g_colAccent) : GC(g_colMuted, 90);
                FillRoundedRect(g, seg, r.Height / 2, c);
            }
            return TRUE;
        }
        return FALSE;
    }
    if (dis->CtlType == ODT_COMBOBOX) {
        Gdiplus::Graphics g(dis->hDC);
        Gdiplus::Rect r(dis->rcItem.left, dis->rcItem.top,
                         dis->rcItem.right - dis->rcItem.left, dis->rcItem.bottom - dis->rcItem.top);
        bool selected = (dis->itemState & ODS_SELECTED) != 0;
        Gdiplus::SolidBrush bgBrush(selected ? GC(g_colAccent, 60) : GC(g_colSurface));
        g.FillRectangle(&bgBrush, r);
        if ((int)dis->itemID >= 0) {
            char buf[256] = { 0 };
            SendMessageA(dis->hwndItem, CB_GETLBTEXT, dis->itemID, (LPARAM)buf);
            Gdiplus::RectF tr((Gdiplus::REAL)(r.X + 6), (Gdiplus::REAL)r.Y, (Gdiplus::REAL)(r.Width - 12), (Gdiplus::REAL)r.Height);
            DrawCenteredText(g, buf, g_hFont, tr, GC(g_colText), Gdiplus::StringAlignmentNear);
        }
        return TRUE;
    }
    if (dis->CtlType == ODT_LISTBOX) {
        Gdiplus::Graphics g(dis->hDC);
        Gdiplus::Rect r(dis->rcItem.left, dis->rcItem.top,
                         dis->rcItem.right - dis->rcItem.left, dis->rcItem.bottom - dis->rcItem.top);
        bool selected = (dis->itemState & ODS_SELECTED) != 0;
        Gdiplus::SolidBrush bgBrush(selected ? GC(g_colAccent, 40) : GC(g_colSurface));
        g.FillRectangle(&bgBrush, r);

        if ((int)dis->itemID >= 0) {
            char buf[512] = { 0 };
            SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)buf);
            Entry* e = FindEntry(buf);
            if (e) {
                Gdiplus::Rect avR(r.X + 10, r.Y + 8, 36, 36);
                Gdiplus::GraphicsPath path;
                path.AddEllipse(avR);
                Gdiplus::SolidBrush avBrush(GC(g_colBg));
                g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
                g.FillPath(&avBrush, &path);
                Gdiplus::RectF avTextR((Gdiplus::REAL)avR.X, (Gdiplus::REAL)avR.Y, (Gdiplus::REAL)avR.Width, (Gdiplus::REAL)avR.Height);
                DrawCenteredText(g, InitialOf(e->name), g_hFontBold, avTextR, GC(g_colText));

                Gdiplus::RectF nameR((Gdiplus::REAL)(r.X + 56), (Gdiplus::REAL)(r.Y + 7), (Gdiplus::REAL)(r.Width - 70), 20.0f);
                DrawCenteredText(g, e->name, g_hFontBold, nameR, GC(g_colText), Gdiplus::StringAlignmentNear);
                Gdiplus::RectF userR((Gdiplus::REAL)(r.X + 56), (Gdiplus::REAL)(r.Y + 27), (Gdiplus::REAL)(r.Width - 70), 18.0f);
                DrawCenteredText(g, e->username, g_hFontSmall, userR, GC(g_colMuted), Gdiplus::StringAlignmentNear);
                if (e->favorite) {
                    Gdiplus::RectF favR((Gdiplus::REAL)(r.X + r.Width - 26), (Gdiplus::REAL)(r.Y + 16), 20.0f, 20.0f);
                    DrawCenteredText(g, "*", g_hFontBold, favR, GC(g_colAccent));
                }
            }
        }
        return TRUE;
    }
    return FALSE;
}

// Repositions the login screen as one block, centered horizontally and
// vertically in the window, using the same relative layout it was
// originally authored with (just anchored dynamically instead of at a
// fixed top-left corner).
void CenterLoginScreen() {
    RECT rc; GetClientRect(g_hMain, &rc);
    const int colW = 440;
    const int blockH = 418;
    int colX = (rc.right - colW) / 2;
    if (colX < 20) colX = 20;
    int baseY = (rc.bottom - blockH) / 2;
    if (baseY < 20) baseY = 20;

    MoveWindow(g_hLoginBadge, colX, baseY + 0, 56, 56, TRUE);
    MoveWindow(g_hLoginTitle, colX, baseY + 70, colW, 32, TRUE);
    MoveWindow(g_hLoginSubtitle, colX, baseY + 108, colW, 40, TRUE);
    MoveWindow(g_hLoginPwLabel, colX, baseY + 158, 300, 18, TRUE);
    MoveWindow(g_hLoginPw1, colX, baseY + 178, 380, 34, TRUE);
    MoveWindow(g_hLoginEye, colX + 384, baseY + 178, 56, 34, TRUE);
    MoveWindow(g_hLoginStrengthBar, colX, baseY + 220, 380, 8, TRUE);
    MoveWindow(g_hLoginStrengthLabel, colX, baseY + 232, 380, 18, TRUE);
    MoveWindow(g_hLoginPw2Label, colX, baseY + 258, 300, 18, TRUE);
    MoveWindow(g_hLoginPw2, colX, baseY + 278, 380, 34, TRUE);
    MoveWindow(g_hLoginBtn, colX, baseY + 328, colW, 40, TRUE);
    MoveWindow(g_hLoginStatus, colX, baseY + 378, colW, 40, TRUE);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hMain = hwnd;
        g_hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        g_hFontBold = CreateFontA(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        g_hFontLarge = CreateFontA(26, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        g_hFontSmall = CreateFontA(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

        CreateAllControls();
        CenterLoginScreen();
        g_vault.path = default_vault_path();
        LoadConfig();
        SetWindowTextA(g_hAutoCustomMinutesEdit, std::to_string(g_autoLockMinutes).c_str());
        DoLock();
        return 0;
    }
    case WM_COMMAND: {
        ResetAutoLockTimer();
        int id = LOWORD(wp);
        int code = HIWORD(wp);

        if (id == ID_LOGIN_PW1 && code == EN_CHANGE) UpdateLoginStrengthUI();
        else if (id == ID_FORM_PASS && code == EN_CHANGE) UpdateFormStrengthUI();
        else if (id == ID_CP_PW1 && code == EN_CHANGE) UpdateCpStrengthUI();
        else if (id == ID_SEARCH && code == EN_CHANGE) OnSearchChanged();
        else if (id == ID_LOGIN_BTN && code == BN_CLICKED) OnLoginSubmit();
        else if (id == ID_LOGIN_EYE) OnLoginEyeToggle();
        else if (id == ID_NAV_VAULT) OnNavClicked(NavView::VAULT);
        else if (id == ID_NAV_SETTINGS) OnNavClicked(NavView::SETTINGS);
        else if (id == ID_NAV_LOCK) DoLock();
        else if (id == ID_ADD_BTN) OnAdd();
        else if (id == ID_CHIP_ALL) OnChipClicked("All");
        else if (id == ID_CHIP_FAV) OnChipClicked("Favorites");
        else if (id == ID_CHIP_CAT_SLOT) {
            if (!g_chipCategories.empty()) OnChipClicked(g_chipCategories[g_chipCatIndex]);
        }
        else if (id == ID_CHIP_SCROLL_LEFT) {
            if (g_chipCatIndex > 0) { g_chipCatIndex--; RefreshChipCategorySlot(); }
        }
        else if (id == ID_CHIP_SCROLL_RIGHT) {
            if (g_chipCatIndex < (int)g_chipCategories.size() - 1) { g_chipCatIndex++; RefreshChipCategorySlot(); }
        }
        else if (id == ID_LIST && code == LBN_SELCHANGE) OnListSelectionChanged();
        else if (id == ID_VIEW_EDIT_BTN) OnEditSelected();
        else if (id == ID_VIEW_DELETE_BTN) OnDeleteSelected(hwnd);
        else if (id == ID_VIEW_FAV_BTN) OnViewFavToggle();
        else if (id == ID_VIEW_SHOW_PASS) OnViewShowPassToggle();
        else if (id == ID_VIEW_COPY_USER) OnCopyUsername(hwnd);
        else if (id == ID_VIEW_COPY_PASS) OnCopyPassword(hwnd);
        else if (id == ID_VIEW_COPY_SITE) OnCopyWebsite(hwnd);
        else if (id == ID_FORM_GEN) OnFormGen();
        else if (id == ID_FORM_SHOWCHK) OnFormShowToggle();
        else if (id == ID_FORM_OK) OnFormOk(hwnd);
        else if (id == ID_FORM_CANCEL) OnFormCancel();
        else if (id == ID_SET_AUTOLOCK_INSTANT) OnAutoLockOptionClicked(AutoLockMode::INSTANT);
        else if (id == ID_SET_AUTOLOCK_CUSTOM) OnAutoLockOptionClicked(AutoLockMode::CUSTOM);
        else if (id == ID_SET_AUTOLOCK_NEVER) OnAutoLockOptionClicked(AutoLockMode::NEVER);
        else if (id == ID_SET_AUTOLOCK_MINUTES && code == EN_CHANGE) OnAutoLockMinutesChanged();
        else if (id == ID_SET_CHANGEPW_BTN) OnChangeMasterPasswordClicked();
        else if (id == ID_SET_CHOOSE_FOLDER) OnChooseBackupFolder(hwnd);
        else if (id == ID_SET_REMOVE_BACKUP) OnRemoveBackupFolder();
        else if (id == ID_CP_OK) OnCpOk(hwnd);
        else if (id == ID_CP_CANCEL) OnCpCancel();
        return 0;
    }
    case WM_DRAWITEM:
        return HandleDrawItem((DRAWITEMSTRUCT*)lp);
    case WM_MEASUREITEM: {
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lp;
        if ((int)mis->CtlID == ID_LIST) mis->itemHeight = 52;
        else if ((int)mis->CtlID == ID_FORM_CATEGORY) mis->itemHeight = 22;
        return TRUE;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        HWND hCtrl = (HWND)lp;
        if (hCtrl == g_hDividerSidebar || hCtrl == g_hDividerList) {
            return (LRESULT)g_hbrBorder;
        }
        SetBkMode(hdc, TRANSPARENT);
        bool muted = GetPropA(hCtrl, "PwvMuted") != NULL;
        SetTextColor(hdc, muted ? g_colMuted : g_colText);
        return (LRESULT)g_hbrBg;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetBkColor(hdc, g_colSurface);
        SetTextColor(hdc, g_colText);
        return (LRESULT)g_hbrSurface;
    }
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wp;
        SetBkColor(hdc, g_colSurface);
        SetTextColor(hdc, g_colText);
        return (LRESULT)g_hbrSurface;
    }
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wp;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, g_colText);
        return (LRESULT)g_hbrBg;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        FillRect(hdc, &ps.rcPaint, g_hbrBg);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ACTIVATE:
        if (LOWORD(wp) == WA_INACTIVE && g_appState == AppState::UNLOCKED &&
            g_autoLock == AutoLockMode::INSTANT) {
            DoLock();
        }
        return 0;
    case WM_TIMER:
        if (wp == TIMER_CLEAR_STATUS) {
            SetWindowTextA(g_hVaultStatus, "");
            KillTimer(hwnd, TIMER_CLEAR_STATUS);
        } else if (wp == TIMER_CLEAR_CLIPBOARD) {
            if (OpenClipboard(hwnd)) { EmptyClipboard(); CloseClipboard(); }
            KillTimer(hwnd, TIMER_CLEAR_CLIPBOARD);
        } else if (wp == TIMER_AUTOLOCK) {
            if (GetTickCount64() >= g_autoLockDeadlineTick) DoLock();
        }
        return 0;
    case WM_CLOSE:
        ClearSensitiveMemory();
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

} // namespace

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    CoInitialize(NULL); // required by SHBrowseForFolder (the backup-folder picker)

    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL);

    InitGdiResources();

    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = g_hbrBg;
    wc.lpszClassName = "PwVaultMainClass";
    wc.hIcon = LoadIconA(NULL, IDI_APPLICATION);
    RegisterClassExA(&wc);

    HWND hMain = CreateWindowExA(0, "PwVaultMainClass", "pwvault",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 960, 700, NULL, NULL, hInstance, NULL);

    EnableDarkTitleBar(hMain);

    ShowWindow(hMain, nCmdShow);
    UpdateWindow(hMain);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            HWND focused = GetFocus();
            int targetId = (int)(INT_PTR)GetPropA(focused, "PwvEnterTarget");
            if (targetId != 0) {
                PostMessageA(hMain, WM_COMMAND, MAKEWPARAM(targetId, BN_CLICKED), 0);
                continue; // handled -- don't let IsDialogMessageA swallow it too
            }
        }
        if (!IsDialogMessageA(hMain, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }

    Gdiplus::GdiplusShutdown(g_gdiplusToken);
    CoUninitialize();
    return 0;
}
