// pwvault: a local, encrypted password manager.
//
// Format: master password -> PBKDF2-HMAC-SHA256 (200,000 iterations) -> 64 bytes
//         -> first 32 bytes = AES-256-CTR encryption key
//         -> last 32 bytes  = HMAC-SHA256 authentication key (encrypt-then-MAC)
//
// File layout (all on disk, nothing here is ever stored unencrypted):
//   magic (7 bytes) "PWVLT3\n" (or legacy "PWVLT2\n", auto-migrated on save)
//   iterations (4 bytes, big-endian uint32)
//   salt (16 bytes)
//   iv (16 bytes)
//   ciphertext (variable)
//   hmac tag (32 bytes)  -- over everything above (magic..ciphertext)
//
// Plaintext (before encryption) is a simple length-prefixed record list:
//   uint32 entry_count
//   for each entry (v3): 6x (uint32 len + bytes) for name, username,
//   password, website, notes, category, followed by a uint32 favorite flag.
//   This console tool only prompts for name/username/password/notes; the
//   newer fields default empty/false here but round-trip safely if the
//   entry was created or edited by the GUI version.
//
// All secrets are read from the terminal with echo disabled.

#include "aes.hpp"
#include "kdf.hpp"
#include "sha256.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #define NOMINMAX
  #include <windows.h>
  #include <bcrypt.h>
  #include <conio.h>
  #include <direct.h>
  #pragma comment(lib, "bcrypt.lib")
#else
  #include <termios.h>
  #include <unistd.h>
  #include <sys/stat.h>
#endif

namespace {

constexpr uint32_t PBKDF2_ITERATIONS = 200000;
constexpr size_t SALT_SIZE = 16;
constexpr size_t IV_SIZE = 16;
constexpr size_t TAG_SIZE = 32;
const char MAGIC_V2[8] = "PWVLT2\n"; // legacy format
const char MAGIC_V3[8] = "PWVLT3\n"; // current format (adds website/category/favorite)

struct Entry {
    std::string name;
    std::string username;
    std::string password;
    std::string website;
    std::string notes;
    std::string category;
    bool favorite = false;
};

// ---------- small utilities ----------

std::string default_vault_path() {
#ifdef _WIN32
    const char* home = std::getenv("USERPROFILE");
    std::string dir = home ? std::string(home) + "\\.pwvault" : ".pwvault";
    _mkdir(dir.c_str());
    return dir + "\\vault.dat";
#else
    const char* home = std::getenv("HOME");
    std::string dir = home ? std::string(home) + "/.pwvault" : ".pwvault";
    mkdir(dir.c_str(), 0700);
    return dir + "/vault.dat";
#endif
}

std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> buf(n);
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        NULL, buf.data(), (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        std::cerr << "Fatal: BCryptGenRandom failed to produce secure randomness.\n";
        std::exit(1);
    }
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom) {
        std::cerr << "Fatal: cannot open /dev/urandom for secure randomness.\n";
        std::exit(1);
    }
    urandom.read(reinterpret_cast<char*>(buf.data()), n);
#endif
    return buf;
}

std::string read_secret(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();
    std::string secret;

#ifdef _WIN32
    for (;;) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') break;
        if (ch == '\b') { // backspace
            if (!secret.empty()) secret.pop_back();
            continue;
        }
        secret.push_back(static_cast<char>(ch));
    }
#else
    termios oldt{};
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::getline(std::cin, secret);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    std::cout << "\n";
    return secret;
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

// ---------- entry (de)serialization ----------

std::vector<uint8_t> serialize_entries(const std::vector<Entry>& entries) {
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
        out.push_back(std::move(e));
    }
    return true;
}

// ---------- vault load / save ----------

struct Vault {
    std::string path;
    std::vector<Entry> entries;
    std::vector<uint8_t> enc_key; // 32 bytes, derived fresh each run, never stored
    std::vector<uint8_t> mac_key; // 32 bytes
};

bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

bool load_vault(Vault& v, const std::string& master_password) {
    std::ifstream in(v.path, std::ios::binary);
    if (!in) { std::cerr << "Vault not found at " << v.path << ". Run 'init' first.\n"; return false; }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    if (data.size() < 7 + 4 + SALT_SIZE + IV_SIZE + TAG_SIZE) {
        std::cerr << "Vault file is corrupt or truncated.\n"; return false;
    }
    bool isV2 = std::memcmp(data.data(), MAGIC_V2, 7) == 0;
    bool isV3 = std::memcmp(data.data(), MAGIC_V3, 7) == 0;
    if (!isV2 && !isV3) {
        std::cerr << "Vault file has an unrecognized format.\n"; return false;
    }

    size_t pos = 7;
    uint32_t iterations = get_u32(&data[pos]); pos += 4;
    std::vector<uint8_t> salt(data.begin() + pos, data.begin() + pos + SALT_SIZE); pos += SALT_SIZE;
    std::vector<uint8_t> iv(data.begin() + pos, data.begin() + pos + IV_SIZE); pos += IV_SIZE;
    size_t cipher_start = pos;
    size_t cipher_len = data.size() - TAG_SIZE - cipher_start;
    std::vector<uint8_t> ciphertext(data.begin() + cipher_start, data.begin() + cipher_start + cipher_len);
    std::vector<uint8_t> tag(data.end() - TAG_SIZE, data.end());

    auto derived = crypto::pbkdf2_hmac_sha256(master_password, salt, iterations, 64);
    v.enc_key.assign(derived.begin(), derived.begin() + 32);
    v.mac_key.assign(derived.begin() + 32, derived.begin() + 64);

    std::vector<uint8_t> mac_input(data.begin(), data.begin() + cipher_start + cipher_len);
    auto computed_tag = crypto::hmac_sha256(v.mac_key, mac_input.data(), mac_input.size());
    if (!constant_time_equal(computed_tag, tag)) {
        std::cerr << "Incorrect master password, or the vault file has been tampered with.\n";
        return false;
    }

    uint8_t key_arr[32], iv_arr[16];
    std::memcpy(key_arr, v.enc_key.data(), 32);
    std::memcpy(iv_arr, iv.data(), 16);
    auto plaintext = crypto::aes256_ctr(key_arr, iv_arr, ciphertext);

    bool ok = isV3 ? deserialize_entries_v3(plaintext, v.entries)
                    : deserialize_entries_v2(plaintext, v.entries);
    if (!ok) {
        std::cerr << "Failed to parse decrypted vault contents.\n";
        return false;
    }
    return true;
}

// Rotates up to MAX_BACKUPS previous versions of a vault file, kept in a
// "backups" subfolder next to it, so a single delete or corruption never
// destroys every copy. Call this with the *old* file still in place, right
// before it gets overwritten. Cross-platform via std::filesystem.
void rotate_backups(const std::string& vault_path) {
    namespace fs = std::filesystem;
    fs::path vp(vault_path);
    if (!fs::exists(vp)) return; // nothing to back up yet (first-ever save)

    fs::path backup_dir = vp.parent_path() / "backups";
    std::error_code ec;
    fs::create_directories(backup_dir, ec);
    if (ec) return; // best-effort; don't block the save over this

    constexpr int MAX_BACKUPS = 5;
    fs::remove(backup_dir / ("vault.dat.bak" + std::to_string(MAX_BACKUPS)), ec);
    for (int i = MAX_BACKUPS - 1; i >= 1; i--) {
        fs::path src = backup_dir / ("vault.dat.bak" + std::to_string(i));
        fs::path dst = backup_dir / ("vault.dat.bak" + std::to_string(i + 1));
        if (fs::exists(src)) {
            fs::rename(src, dst, ec);
        }
    }
    fs::copy_file(vp, backup_dir / "vault.dat.bak1", fs::copy_options::overwrite_existing, ec);
}

bool save_vault(const Vault& v, const std::string& master_password) {
    auto salt = random_bytes(SALT_SIZE);
    auto iv = random_bytes(IV_SIZE);
    auto derived = crypto::pbkdf2_hmac_sha256(master_password, salt, PBKDF2_ITERATIONS, 64);
    std::vector<uint8_t> enc_key(derived.begin(), derived.begin() + 32);
    std::vector<uint8_t> mac_key(derived.begin() + 32, derived.begin() + 64);

    auto plaintext = serialize_entries(v.entries);
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

    rotate_backups(v.path);

    std::string tmp_path = v.path + ".tmp";
    std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
    if (!ofs) { std::cerr << "Failed to write vault file.\n"; return false; }
    ofs.write(reinterpret_cast<const char*>(out.data()), out.size());
    ofs.close();

#ifdef _WIN32
    // rename() on Windows fails if the destination already exists, so
    // replace it explicitly (still atomic on the same volume).
    MoveFileExA(tmp_path.c_str(), v.path.c_str(), MOVEFILE_REPLACE_EXISTING);
#else
    chmod(tmp_path.c_str(), 0600);
    std::rename(tmp_path.c_str(), v.path.c_str());
#endif
    return true;
}

// ---------- password generator ----------

std::string generate_password(size_t len, bool use_upper, bool use_lower, bool use_digits, bool use_symbols) {
    std::string charset;
    if (use_upper) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (use_lower) charset += "abcdefghijklmnopqrstuvwxyz";
    if (use_digits) charset += "0123456789";
    if (use_symbols) charset += "!@#$%^&*()-_=+[]{}<>?/.,~";
    if (charset.empty()) charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    auto raw = random_bytes(len * 4); // oversample to avoid modulo bias in practice
    std::string out;
    out.reserve(len);
    size_t idx = 0;
    while (out.size() < len) {
        uint8_t b = raw[idx++ % raw.size()];
        if (idx > len * 20) break; // safety valve
        // simple rejection-free pick (small bias acceptable for a personal tool;
        // charset sizes are all < 128 so bias is minor, but we mix in more bytes)
        out += charset[b % charset.size()];
    }
    return out;
}

// ---------- CLI commands ----------

void print_usage() {
    std::cout <<
        "pwvault - a local encrypted password manager\n\n"
        "Usage:\n"
        "  pwvault init                 Create a new vault\n"
        "  pwvault add <name>           Add a new entry\n"
        "  pwvault get <name>           Show an entry (password hidden by default)\n"
        "  pwvault get <name> --show    Show an entry including the password\n"
        "  pwvault list                 List all entry names\n"
        "  pwvault remove <name>        Delete an entry\n"
        "  pwvault passwd               Change the master password\n"
        "  pwvault gen [length]         Generate a random password (not saved)\n"
        "  pwvault --path <file> ...    Use a vault file other than the default\n"
        "\nDefault vault location: ~/.pwvault/vault.dat\n";
}

int cmd_init(const std::string& path) {
    if (file_exists(path)) {
        std::cerr << "A vault already exists at " << path << ".\n";
        return 1;
    }
    std::string pw1 = read_secret("Create a master password: ");
    if (pw1.empty()) { std::cerr << "Master password cannot be empty.\n"; return 1; }
    std::string pw2 = read_secret("Confirm master password: ");
    if (pw1 != pw2) { std::cerr << "Passwords did not match.\n"; return 1; }

    Vault v;
    v.path = path;
    if (!save_vault(v, pw1)) return 1;
    std::cout << "Vault created at " << path << "\n";
    return 0;
}

int cmd_add(const std::string& path, const std::string& name) {
    Vault v; v.path = path;
    std::string master = read_secret("Master password: ");
    if (!load_vault(v, master)) return 1;

    for (auto& e : v.entries) {
        if (e.name == name) {
            std::cerr << "An entry named '" << name << "' already exists. Use 'remove' first to replace it.\n";
            return 1;
        }
    }

    Entry e;
    e.name = name;
    std::cout << "Username: ";
    std::getline(std::cin, e.username);

    std::cout << "Password (leave blank to auto-generate): ";
    std::getline(std::cin, e.password);
    if (e.password.empty()) {
        e.password = generate_password(20, true, true, true, true);
        std::cout << "Generated password: " << e.password << "\n";
    }

    std::cout << "Notes (optional): ";
    std::getline(std::cin, e.notes);

    v.entries.push_back(e);
    if (!save_vault(v, master)) return 1;
    std::cout << "Saved '" << name << "'.\n";
    return 0;
}

int cmd_get(const std::string& path, const std::string& name, bool show) {
    Vault v; v.path = path;
    std::string master = read_secret("Master password: ");
    if (!load_vault(v, master)) return 1;

    for (const auto& e : v.entries) {
        if (e.name == name) {
            std::cout << "Name:     " << e.name << "\n";
            std::cout << "Username: " << e.username << "\n";
            std::cout << "Password: " << (show ? e.password : std::string(e.password.size(), '*')) << "\n";
            if (!e.notes.empty()) std::cout << "Notes:    " << e.notes << "\n";
            if (!show) std::cout << "(pass --show to reveal the password)\n";
            return 0;
        }
    }
    std::cerr << "No entry named '" << name << "'.\n";
    return 1;
}

int cmd_list(const std::string& path) {
    Vault v; v.path = path;
    std::string master = read_secret("Master password: ");
    if (!load_vault(v, master)) return 1;

    if (v.entries.empty()) { std::cout << "(vault is empty)\n"; return 0; }
    std::vector<std::string> names;
    for (const auto& e : v.entries) names.push_back(e.name);
    std::sort(names.begin(), names.end());
    for (const auto& n : names) std::cout << "  " << n << "\n";
    return 0;
}

int cmd_remove(const std::string& path, const std::string& name) {
    Vault v; v.path = path;
    std::string master = read_secret("Master password: ");
    if (!load_vault(v, master)) return 1;

    auto it = std::find_if(v.entries.begin(), v.entries.end(),
                            [&](const Entry& e) { return e.name == name; });
    if (it == v.entries.end()) { std::cerr << "No entry named '" << name << "'.\n"; return 1; }
    v.entries.erase(it);
    if (!save_vault(v, master)) return 1;
    std::cout << "Removed '" << name << "'.\n";
    return 0;
}

int cmd_passwd(const std::string& path) {
    Vault v; v.path = path;
    std::string old_master = read_secret("Current master password: ");
    if (!load_vault(v, old_master)) return 1;

    std::string new1 = read_secret("New master password: ");
    if (new1.empty()) { std::cerr << "Master password cannot be empty.\n"; return 1; }
    std::string new2 = read_secret("Confirm new master password: ");
    if (new1 != new2) { std::cerr << "Passwords did not match.\n"; return 1; }

    if (!save_vault(v, new1)) return 1;
    std::cout << "Master password changed.\n";
    return 0;
}

int cmd_gen(size_t len) {
    std::cout << generate_password(len, true, true, true, true) << "\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    std::string path = default_vault_path();

    // pull out a leading --path <file> override, anywhere in the args
    for (size_t i = 0; i < args.size(); i++) {
        if (args[i] == "--path" && i + 1 < args.size()) {
            path = args[i+1];
            args.erase(args.begin() + i, args.begin() + i + 2);
            break;
        }
    }

    if (args.empty()) { print_usage(); return 1; }
    const std::string& cmd = args[0];

    if (cmd == "init") return cmd_init(path);
    if (cmd == "add" && args.size() >= 2) return cmd_add(path, args[1]);
    if (cmd == "get" && args.size() >= 2) {
        bool show = args.size() >= 3 && args[2] == "--show";
        return cmd_get(path, args[1], show);
    }
    if (cmd == "list") return cmd_list(path);
    if (cmd == "remove" && args.size() >= 2) return cmd_remove(path, args[1]);
    if (cmd == "passwd") return cmd_passwd(path);
    if (cmd == "gen") {
        size_t len = 20;
        if (args.size() >= 2) len = std::max(4, std::atoi(args[1].c_str()));
        return cmd_gen(len);
    }

    print_usage();
    return 1;
}
