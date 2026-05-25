#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#include "aes_cipher.hpp"

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Terminal helpers — cross-platform password input (no echo)
// ---------------------------------------------------------------------------

#ifdef _WIN32
#  include <conio.h>
static std::string read_password(const char* prompt) {
    std::cout << prompt << std::flush;
    std::string pw;
    int c;
    while (true) {
        c = _getch();
        if (c == '\r' || c == '\n') break;
        if (c == '\b' || c == 127) {          // backspace
            if (!pw.empty()) pw.pop_back();
        } else if (c != 0 && c != 0xE0) {     // skip function/arrow-key prefixes
            pw += static_cast<char>(c);
        }
    }
    std::cout << '\n';
    return pw;
}
#else
#  include <termios.h>
#  include <unistd.h>
static std::string read_password(const char* prompt) {
    std::cout << prompt << std::flush;
    termios old_tty{}, new_tty{};
    tcgetattr(STDIN_FILENO, &old_tty);
    new_tty = old_tty;
    new_tty.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tty);
    std::string pw;
    std::getline(std::cin, pw);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_tty);
    std::cout << '\n';
    return pw;
}
#endif

// ---------------------------------------------------------------------------
// Info display
// ---------------------------------------------------------------------------

static void print_banner() {
    std::cout << "╔══════════════════════════════════════╗\n"
              << "║        AES-256 File Encryptor        ║\n"
              << "╚══════════════════════════════════════╝\n\n";
}

static void print_mode_info() {
    std::cout <<
        "Non-AEAD modes (integrity via external HMAC-SHA256):\n"
        "  ECB      Electronic Code Book     no IV, deterministic — avoid for secrets\n"
        "  CBC      Cipher Block Chaining     random IV, sequential\n"
        "  CFB      Cipher Feedback           random IV, self-synchronising stream\n"
        "  OFB      Output Feedback           random IV, keystream independent of data\n"
        "  CTR      Counter                   random IV, parallelisable\n\n"
        "AEAD modes (built-in 16-byte auth tag, no external HMAC):\n"
        "  GCM      Galois/Counter Mode       NIST SP 800-38D, 12-byte nonce, streaming\n"
        "  CCM      Counter with CBC-MAC      NIST SP 800-38C, 12-byte nonce, full-buffer(*)\n"
        "  GCM-SIV  GCM-SIV (RFC 8452)       nonce-misuse resistant, deterministic\n"
        "  SIV      AES-SIV (RFC 5297)        nonce-misuse resistant, deterministic, no nonce\n"
        "           Note: CCM-SIV is not a standardised mode; SIV (RFC 5297) is used instead.\n\n"
        "(*) CCM buffers the entire file in memory during encryption/decryption.\n\n";
}

static void print_usage(const char* prog) {
    print_banner();
    std::cout << "Usage:\n"
              << "  " << prog << " encrypt <mode> <input> <output>\n"
              << "  " << prog << " decrypt <input> <output>\n"
              << "  " << prog << " info    <encrypted_file>\n\n";
    print_mode_info();
    std::cout << "Examples:\n"
              << "  " << prog << " encrypt CBC  secret.txt  secret.enc\n"
              << "  " << prog << " decrypt      secret.enc  secret.txt\n"
              << "  " << prog << " info         secret.enc\n";
}

// ---------------------------------------------------------------------------
// 'info' sub-command — display header without decrypting
// ---------------------------------------------------------------------------

static void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    std::cout << std::dec;
}

static int cmd_info(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        std::cerr << "Cannot open: " << path << '\n';
        return 1;
    }

    const auto file_size = static_cast<std::streamoff>(f.tellg());
    const auto hdr_size  = static_cast<std::streamoff>(sizeof(crypto::FileHeader));
    if (file_size < hdr_size) {
        std::cerr << "File is too small to be a valid .enc file.\n";
        return 1;
    }

    f.seekg(0);
    crypto::FileHeader hdr{};
    f.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (f.gcount() != static_cast<std::streamsize>(sizeof(hdr)) ||
        std::memcmp(hdr.magic, crypto::FileHeader::MAGIC, 4) != 0) {
        std::cerr << "Not a valid v3 .enc file (wrong magic bytes).\n";
        return 1;
    }
    if (hdr.mode > static_cast<uint8_t>(crypto::Mode::SIV)) {
        std::cerr << "Unknown mode byte in file header.\n";
        return 1;
    }

    const auto mode     = static_cast<crypto::Mode>(hdr.mode);
    const auto tag_size = static_cast<std::streamoff>(crypto::auth_tag_size(mode));
    const auto min_size = hdr_size + tag_size;

    if (file_size < min_size) {
        std::cerr << "File is too small (missing auth tag).\n";
        return 1;
    }

    // Read auth tag (HMAC or AEAD) from end of file
    std::vector<uint8_t> tag(static_cast<size_t>(tag_size));
    f.seekg(-tag_size, std::ios::end);
    f.read(reinterpret_cast<char*>(tag.data()), tag_size);

    const auto cipher_size = file_size - min_size;

    const bool is_aead = crypto::mode_is_aead(mode);

    std::cout << "File      : " << path << "\n"
              << "Mode      : AES-256-" << crypto::mode_to_string(mode) << "\n"
              << "AEAD      : " << (is_aead ? "yes" : "no") << "\n"
              << "Ciphertext: " << cipher_size << " bytes\n"
              << "Salt      : "; print_hex(hdr.salt, crypto::SALT_LEN);
    std::cout << "\nIV/Nonce  : "; print_hex(hdr.iv, crypto::IV_LEN);
    std::cout << "\n" << (is_aead ? "AEAD tag  " : "HMAC-SHA256")
              << ": "; print_hex(tag.data(), tag.size());
    std::cout << "\nKDF       : PBKDF2-HMAC-SHA256, "
              << crypto::PBKDF2_ITERATIONS << " iterations\n"
              << "Integrity : "
              << (is_aead ? "AEAD tag (16 bytes, embedded in file)"
                           : "Encrypt-then-MAC (HMAC-SHA256, 32 bytes)")
              << "\n";
    return 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    const std::string action = argv[1];

    if (action == "info") {
        if (argc != 3) { print_usage(argv[0]); return 1; }
        return cmd_info(argv[2]);
    }

    if (action == "encrypt") {
        if (argc != 5) { print_usage(argv[0]); return 1; }

        crypto::Mode mode;
        try { mode = crypto::mode_from_string(argv[2]); }
        catch (const std::exception& ex) {
            std::cerr << "Error: " << ex.what() << '\n';
            return 1;
        }

        const std::string in  = argv[3];
        const std::string out = argv[4];

        if (!fs::exists(in)) {
            std::cerr << "Input file not found: " << in << '\n';
            return 1;
        }
        if (fs::exists(out)) {
            std::cerr << "Output file already exists: " << out
                      << " (remove it first)\n";
            return 1;
        }

        print_banner();
        std::cout << "Mode   : AES-256-" << crypto::mode_to_string(mode) << '\n'
                  << "Input  : " << in  << " (" << fs::file_size(in) << " bytes)\n"
                  << "Output : " << out << "\n\n";

        const auto pw  = read_password("Enter password: ");
        const auto pw2 = read_password("Confirm password: ");
        if (pw != pw2) { std::cerr << "Passwords do not match.\n"; return 1; }
        if (pw.empty()) { std::cerr << "Password must not be empty.\n"; return 1; }

        std::cout << "Encrypting…\n";
        try {
            crypto::encrypt_file(in, out, pw, mode);
        } catch (const std::exception& ex) {
            std::cerr << "Error: " << ex.what() << '\n';
            if (fs::exists(out)) fs::remove(out);  // remove partial output
            return 1;
        }
        std::cout << "Done. Encrypted file: " << out
                  << " (" << fs::file_size(out) << " bytes)\n";
        return 0;
    }

    if (action == "decrypt") {
        if (argc != 4) { print_usage(argv[0]); return 1; }

        const std::string in  = argv[2];
        const std::string out = argv[3];

        if (!fs::exists(in)) {
            std::cerr << "Input file not found: " << in << '\n';
            return 1;
        }
        if (fs::exists(out)) {
            std::cerr << "Output file already exists: " << out
                      << " (remove it first)\n";
            return 1;
        }

        print_banner();
        const auto pw = read_password("Enter password: ");

        std::cout << "Decrypting…\n";
        try {
            crypto::decrypt_file(in, out, pw);
        } catch (const std::exception& ex) {
            std::cerr << "Error: " << ex.what() << '\n';
            if (fs::exists(out)) fs::remove(out);  // remove partial output
            return 1;
        }
        std::cout << "Done. Decrypted file: " << out
                  << " (" << fs::file_size(out) << " bytes)\n";
        return 0;
    }

    std::cerr << "Unknown command: " << action << '\n';
    print_usage(argv[0]);
    return 1;
}
