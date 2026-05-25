#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace crypto {

// clang-format off
enum class Mode : uint8_t {
    // --- Non-AEAD (external HMAC-SHA256 integrity) ---
    ECB     = 0,  // Electronic Code Book        — no IV, deterministic; avoid for secrets
    CBC     = 1,  // Cipher Block Chaining        — random IV, sequential
    CFB     = 2,  // Cipher Feedback              — random IV, self-synchronising stream
    OFB     = 3,  // Output Feedback              — random IV, keystream ⊥ data
    CTR     = 4,  // Counter                      — random IV, parallelisable

    // --- AEAD (built-in authentication tag, 16 bytes) ---
    GCM     = 5,  // Galois/Counter Mode          — NIST SP 800-38D, 12-byte nonce, streaming
    CCM     = 6,  // Counter with CBC-MAC         — NIST SP 800-38C, 12-byte nonce, full-buffer
    GCM_SIV = 7,  // GCM-SIV (RFC 8452)          — nonce-misuse-resistant; requires OpenSSL ≥ 3.2
    SIV     = 8,  // AES-SIV (RFC 5297)           — nonce-misuse-resistant, deterministic, no nonce
                  //   Note: "CCM-SIV" is not a standardised mode; SIV (RFC 5297) is used instead.
};
// clang-format on

Mode        mode_from_string(std::string_view s);
std::string mode_to_string(Mode m);
bool        mode_is_aead(Mode m);      // true for GCM, CCM, GCM_SIV, SIV
bool        mode_needs_iv(Mode m);     // false for ECB and SIV
size_t      auth_tag_size(Mode m);     // 16 for AEAD, 32 for non-AEAD

static constexpr size_t KEY_LEN           = 32;   // AES-256 encryption key
static constexpr size_t HMAC_KEY_LEN      = 32;   // HMAC-SHA256 key (non-AEAD)
static constexpr size_t HMAC_TAG_LEN      = 32;   // HMAC-SHA256 output (non-AEAD)
static constexpr size_t AES_TAG_LEN       = 16;   // AEAD authentication tag
static constexpr size_t IV_LEN            = 16;   // header IV field (12 bytes used for AEAD nonces)
static constexpr size_t SALT_LEN          = 16;
static constexpr size_t PBKDF2_ITERATIONS = 100'000;
static constexpr size_t TOTAL_KEY_LEN     = KEY_LEN + HMAC_KEY_LEN;  // 64 bytes from PBKDF2

using Key     = std::array<uint8_t, KEY_LEN>;
using HMACKey = std::array<uint8_t, HMAC_KEY_LEN>;
using HMACTag = std::array<uint8_t, HMAC_TAG_LEN>;
using IV      = std::array<uint8_t, IV_LEN>;
using Salt    = std::array<uint8_t, SALT_LEN>;

// PBKDF2 yields TOTAL_KEY_LEN (64) bytes:
//   enc[0..31]  → AES-256 key  (all modes)
//   mac[32..63] → HMAC key     (non-AEAD) / second half of 64-byte SIV key (SIV mode)
struct DerivedKeys {
    Key     enc;
    HMACKey mac;
};

// Progress callback: fn(bytes_done, bytes_total).
// Called from a worker thread; must be thread-safe (Qt signals are fine).
using ProgressFn = std::function<void(int64_t, int64_t)>;

// File format (v3):
//   [4]    magic  "AES\x03"  (file) | "AES\x04" (folder archive)
//   [1]    mode   (uint8_t)
//   [16]   salt   (PBKDF2 salt)
//   [16]   iv     (non-AEAD: full 16-byte IV; GCM/CCM/GCM-SIV: 12-byte nonce in [0..11];
//                  SIV: unused zeros)
//   ---- header ends (37 bytes) ----
//   [N]    ciphertext
//   [32]   HMAC-SHA256(mac_key, header||ciphertext)   ← non-AEAD only
//   [16]   AEAD auth tag                              ← AEAD only
struct FileHeader {
    static constexpr char MAGIC[4]        = {'A', 'E', 'S', '\x03'};
    static constexpr char FOLDER_MAGIC[4] = {'A', 'E', 'S', '\x04'};
    uint8_t magic[4];
    uint8_t mode;
    uint8_t salt[SALT_LEN];
    uint8_t iv[IV_LEN];
};
static_assert(sizeof(FileHeader) == 37);

DerivedKeys derive_keys(std::string_view password, const Salt& salt);
Salt        random_salt();
IV          random_iv();

void encrypt_file(const std::string& in_path,
                  const std::string& out_path,
                  std::string_view   password,
                  Mode               mode,
                  ProgressFn         on_progress = nullptr);

void decrypt_file(const std::string& in_path,
                  const std::string& out_path,
                  std::string_view   password,
                  ProgressFn         on_progress = nullptr);

// Folder encryption: packs dir_path into a CDIR archive then encrypts it.
void encrypt_dir(const std::string& dir_path,
                 const std::string& out_path,
                 std::string_view   password,
                 Mode               mode,
                 ProgressFn         on_progress = nullptr);

// Folder decryption: decrypts the archive then extracts into out_dir.
void decrypt_dir(const std::string& in_path,
                 const std::string& out_dir,
                 std::string_view   password,
                 ProgressFn         on_progress = nullptr);

// Returns true when in_path is an encrypted folder archive (FOLDER_MAGIC).
bool is_dir_archive(const std::string& in_path);

}  // namespace crypto
