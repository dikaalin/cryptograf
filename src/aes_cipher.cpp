#include "aes_cipher.hpp"
#include "gcmsiv.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>

#include <openssl/crypto.h>   // CRYPTO_memcmp
#include <openssl/evp.h>
#include <openssl/params.h>   // OSSL_PARAM
#include <openssl/rand.h>

namespace crypto {

// ---------------------------------------------------------------------------
// Mode helpers
// ---------------------------------------------------------------------------

Mode mode_from_string(std::string_view s) {
    std::string up(s.size(), '\0');
    std::transform(s.begin(), s.end(), up.begin(), ::toupper);
    if (up == "ECB")                        return Mode::ECB;
    if (up == "CBC")                        return Mode::CBC;
    if (up == "CFB")                        return Mode::CFB;
    if (up == "OFB")                        return Mode::OFB;
    if (up == "CTR")                        return Mode::CTR;
    if (up == "GCM")                        return Mode::GCM;
    if (up == "CCM")                        return Mode::CCM;
    if (up == "GCM-SIV" || up == "GCMSIV") return Mode::GCM_SIV;
    if (up == "SIV")                        return Mode::SIV;
    throw std::invalid_argument("Unknown mode: " + std::string(s));
}

std::string mode_to_string(Mode m) {
    switch (m) {
        case Mode::ECB:     return "ECB";
        case Mode::CBC:     return "CBC";
        case Mode::CFB:     return "CFB";
        case Mode::OFB:     return "OFB";
        case Mode::CTR:     return "CTR";
        case Mode::GCM:     return "GCM";
        case Mode::CCM:     return "CCM";
        case Mode::GCM_SIV: return "GCM-SIV";
        case Mode::SIV:     return "SIV";
    }
    return "???";
}

bool mode_is_aead(Mode m) {
    return static_cast<uint8_t>(m) >= static_cast<uint8_t>(Mode::GCM);
}

bool mode_needs_iv(Mode m) { return m != Mode::ECB && m != Mode::SIV; }

size_t auth_tag_size(Mode m) {
    return mode_is_aead(m) ? AES_TAG_LEN : HMAC_TAG_LEN;
}

// Bytes of the 16-byte IV field used as a nonce for AEAD modes.
// SIV is deterministic and takes no nonce.
static size_t nonce_len(Mode m) {
    switch (m) {
        case Mode::GCM:
        case Mode::CCM:
        case Mode::GCM_SIV: return 12;
        default:             return 0;
    }
}

// ---------------------------------------------------------------------------
// RAII: cipher handle — owns pointer only when obtained via EVP_CIPHER_fetch
// ---------------------------------------------------------------------------

struct CipherRef {
    EVP_CIPHER* ptr;
    bool        owns;

    const EVP_CIPHER* get() const { return ptr; }
    explicit operator bool() const { return ptr != nullptr; }

    ~CipherRef() { if (owns && ptr) EVP_CIPHER_free(ptr); }
    CipherRef(EVP_CIPHER* p, bool o) : ptr(p), owns(o) {}
    CipherRef(CipherRef&& o) noexcept
        : ptr(o.ptr), owns(o.owns) { o.ptr = nullptr; o.owns = false; }
    CipherRef(const CipherRef&) = delete;
    CipherRef& operator=(const CipherRef&) = delete;
};

static CipherRef static_ref(const EVP_CIPHER* c) {
    return CipherRef{const_cast<EVP_CIPHER*>(c), false};
}

static CipherRef fetch_cipher(const char* name, Mode m) {
    EVP_CIPHER* c = EVP_CIPHER_fetch(nullptr, name, nullptr);
    if (!c) {
        std::string msg = std::string(name) + " is not available";
        if (m == Mode::GCM_SIV)
            msg += " — requires OpenSSL ≥ 3.2 (installed: " OPENSSL_VERSION_TEXT ")";
        throw std::runtime_error(msg);
    }
    return CipherRef{c, true};
}

static CipherRef make_cipher(Mode m) {
    switch (m) {
        case Mode::ECB:     return static_ref(EVP_aes_256_ecb());
        case Mode::CBC:     return static_ref(EVP_aes_256_cbc());
        case Mode::CFB:     return static_ref(EVP_aes_256_cfb128());
        case Mode::OFB:     return static_ref(EVP_aes_256_ofb());
        case Mode::CTR:     return static_ref(EVP_aes_256_ctr());
        case Mode::GCM:     return static_ref(EVP_aes_256_gcm());
        case Mode::CCM:     return static_ref(EVP_aes_256_ccm());
        case Mode::GCM_SIV: throw std::logic_error("GCM_SIV is handled by gcmsiv:: directly");
        case Mode::SIV:     return fetch_cipher("AES-256-SIV", m);
    }
    throw std::runtime_error("Unknown mode");
}

// ---------------------------------------------------------------------------
// RAII: AES cipher context
// ---------------------------------------------------------------------------

struct EvpCtx {
    EVP_CIPHER_CTX* ctx;
    EvpCtx() : ctx(EVP_CIPHER_CTX_new()) {
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }
    ~EvpCtx() { EVP_CIPHER_CTX_free(ctx); }
    EvpCtx(const EvpCtx&)            = delete;
    EvpCtx& operator=(const EvpCtx&) = delete;
};

// ---------------------------------------------------------------------------
// RAII: HMAC-SHA256 context (OpenSSL 3.x EVP_MAC API)
// ---------------------------------------------------------------------------

struct HmacCtx {
    EVP_MAC*     mac = nullptr;
    EVP_MAC_CTX* ctx = nullptr;

    explicit HmacCtx(const uint8_t* key, size_t key_len) {
        mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        if (!mac) throw std::runtime_error("EVP_MAC_fetch failed");
        ctx = EVP_MAC_CTX_new(mac);
        if (!ctx) throw std::runtime_error("EVP_MAC_CTX_new failed");
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0),
            OSSL_PARAM_END
        };
        if (EVP_MAC_init(ctx, key, key_len, params) != 1)
            throw std::runtime_error("EVP_MAC_init failed");
    }

    void update(const void* data, size_t len) {
        if (len == 0) return;
        if (EVP_MAC_update(ctx, static_cast<const uint8_t*>(data), len) != 1)
            throw std::runtime_error("EVP_MAC_update failed");
    }

    HMACTag finalize() {
        HMACTag out{};
        size_t  sz = out.size();
        if (EVP_MAC_final(ctx, out.data(), &sz, out.size()) != 1)
            throw std::runtime_error("EVP_MAC_final failed");
        return out;
    }

    ~HmacCtx() { EVP_MAC_CTX_free(ctx); EVP_MAC_free(mac); }
    HmacCtx(const HmacCtx&)            = delete;
    HmacCtx& operator=(const HmacCtx&) = delete;
};

// ---------------------------------------------------------------------------
// Key derivation — one PBKDF2 call yields 64 bytes
// ---------------------------------------------------------------------------

DerivedKeys derive_keys(std::string_view password, const Salt& salt) {
    std::array<uint8_t, TOTAL_KEY_LEN> raw{};
    if (!PKCS5_PBKDF2_HMAC(password.data(),
                            static_cast<int>(password.size()),
                            salt.data(),
                            static_cast<int>(salt.size()),
                            PBKDF2_ITERATIONS,
                            EVP_sha256(),
                            static_cast<int>(raw.size()),
                            raw.data()))
        throw std::runtime_error("PBKDF2 key derivation failed");

    DerivedKeys dk{};
    std::copy_n(raw.begin(),           KEY_LEN,      dk.enc.begin());
    std::copy_n(raw.begin() + KEY_LEN, HMAC_KEY_LEN, dk.mac.begin());
    return dk;
}

Salt random_salt() {
    Salt s{};
    if (RAND_bytes(s.data(), static_cast<int>(s.size())) != 1)
        throw std::runtime_error("RAND_bytes (salt) failed");
    return s;
}

IV random_iv() {
    IV iv{};
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1)
        throw std::runtime_error("RAND_bytes (iv) failed");
    return iv;
}

// Build contiguous 64-byte SIV key from DerivedKeys (enc || mac).
static std::array<uint8_t, TOTAL_KEY_LEN> make_siv_key(const DerivedKeys& k) {
    std::array<uint8_t, TOTAL_KEY_LEN> buf{};
    std::memcpy(buf.data(),           k.enc.data(), KEY_LEN);
    std::memcpy(buf.data() + KEY_LEN, k.mac.data(), HMAC_KEY_LEN);
    return buf;
}

// Read entire input stream into a buffer.
static std::vector<uint8_t> read_all(std::ifstream& in) {
    std::vector<uint8_t> buf;
    char tmp[65536];
    while (in.read(tmp, sizeof(tmp)) || in.gcount() > 0)
        buf.insert(buf.end(), tmp, tmp + in.gcount());
    return buf;
}

// ---------------------------------------------------------------------------
// Non-AEAD encryption — Encrypt-then-MAC
// Streams plaintext → ciphertext while computing HMAC in parallel.
// Appends 32-byte HMAC-SHA256 tag at end.
// ---------------------------------------------------------------------------

static void encrypt_non_aead(std::ifstream& in, std::ofstream& out,
                              const DerivedKeys& keys,
                              const uint8_t* raw_hdr, size_t hdr_size,
                              Mode mode, const IV& iv) {
    CipherRef cipher = make_cipher(mode);
    HmacCtx   hmac(keys.mac.data(), HMAC_KEY_LEN);
    hmac.update(raw_hdr, hdr_size);

    EvpCtx aes;
    if (EVP_EncryptInit_ex(aes.ctx, cipher.get(), nullptr,
                           keys.enc.data(),
                           mode_needs_iv(mode) ? iv.data() : nullptr) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    static constexpr size_t CHUNK = 65536;
    std::vector<uint8_t> ibuf(CHUNK), obuf(CHUNK + EVP_MAX_BLOCK_LENGTH);
    int len = 0;

    while (in) {
        in.read(reinterpret_cast<char*>(ibuf.data()), CHUNK);
        int n = static_cast<int>(in.gcount());
        if (n == 0) break;
        if (EVP_EncryptUpdate(aes.ctx, obuf.data(), &len, ibuf.data(), n) != 1)
            throw std::runtime_error("EVP_EncryptUpdate failed");
        out.write(reinterpret_cast<const char*>(obuf.data()), len);
        hmac.update(obuf.data(), static_cast<size_t>(len));
    }

    if (EVP_EncryptFinal_ex(aes.ctx, obuf.data(), &len) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    out.write(reinterpret_cast<const char*>(obuf.data()), len);
    hmac.update(obuf.data(), static_cast<size_t>(len));

    const HMACTag tag = hmac.finalize();
    out.write(reinterpret_cast<const char*>(tag.data()),
              static_cast<std::streamsize>(tag.size()));
}

// ---------------------------------------------------------------------------
// AEAD encryption
//
// GCM / GCM-SIV : two-step init, streaming plaintext, GET_TAG after Final
// CCM            : two-step init, declare tag length + plaintext length,
//                  single EVP_EncryptUpdate call (CCM limitation), GET_TAG
// SIV            : two-step init with 64-byte key, streaming, GET_TAG after Final
//
// All modes append a 16-byte AEAD authentication tag at end of file.
// ---------------------------------------------------------------------------

static void encrypt_aead(std::ifstream& in, std::ofstream& out,
                         const DerivedKeys& keys, Mode mode, const IV& iv) {
    // GCM-SIV: RFC 8452 manual implementation (nonce = first 12 bytes of iv)
    if (mode == Mode::GCM_SIV) {
        auto pt     = read_all(in);
        auto result = gcmsiv::encrypt(keys.enc.data(), iv.data(),
                                      nullptr, 0,
                                      pt.data(), pt.size());
        out.write(reinterpret_cast<const char*>(result.data()),
                  static_cast<std::streamsize>(result.size()));
        return;
    }

    CipherRef cipher = make_cipher(mode);
    EvpCtx    ctx;

    const size_t nlen = nonce_len(mode);
    auto         sk   = make_siv_key(keys);
    const uint8_t* key_ptr = (mode == Mode::SIV) ? sk.data() : keys.enc.data();

    // Step 1: set cipher type only
    EVP_EncryptInit_ex(ctx.ctx, cipher.get(), nullptr, nullptr, nullptr);

    // Adjust nonce length when it differs from the cipher's default
    if (nlen > 0 &&
        nlen != static_cast<size_t>(EVP_CIPHER_get_iv_length(cipher.get())))
        EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            static_cast<int>(nlen), nullptr);

    // CCM: declare authentication tag length before key/nonce
    if (mode == Mode::CCM)
        EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_AEAD_SET_TAG, AES_TAG_LEN, nullptr);

    // Step 2: set key and nonce
    EVP_EncryptInit_ex(ctx.ctx, nullptr, nullptr,
                       key_ptr,
                       nlen > 0 ? iv.data() : nullptr);

    if (mode == Mode::CCM) {
        // CCM restriction: total plaintext length must be declared before data;
        // the entire plaintext must be processed in a single EncryptUpdate call.
        auto plaintext = read_all(in);
        int len = 0;
        EVP_EncryptUpdate(ctx.ctx, nullptr, &len, nullptr,
                          static_cast<int>(plaintext.size()));

        std::vector<uint8_t> ct(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        if (EVP_EncryptUpdate(ctx.ctx, ct.data(), &len,
                              plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1)
            throw std::runtime_error("CCM EVP_EncryptUpdate failed");
        int flen = 0;
        EVP_EncryptFinal_ex(ctx.ctx, ct.data() + len, &flen);
        out.write(reinterpret_cast<const char*>(ct.data()), len + flen);
    } else {
        // GCM / GCM-SIV / SIV: stream in chunks
        static constexpr size_t CHUNK = 65536;
        std::vector<uint8_t> ibuf(CHUNK), obuf(CHUNK + EVP_MAX_BLOCK_LENGTH);
        int len = 0;

        while (in) {
            in.read(reinterpret_cast<char*>(ibuf.data()), CHUNK);
            int n = static_cast<int>(in.gcount());
            if (n == 0) break;
            if (EVP_EncryptUpdate(ctx.ctx, obuf.data(), &len, ibuf.data(), n) != 1)
                throw std::runtime_error("EVP_EncryptUpdate (AEAD) failed");
            out.write(reinterpret_cast<const char*>(obuf.data()), len);
        }

        if (EVP_EncryptFinal_ex(ctx.ctx, obuf.data(), &len) != 1)
            throw std::runtime_error("EVP_EncryptFinal_ex (AEAD) failed");
        out.write(reinterpret_cast<const char*>(obuf.data()), len);
    }

    // Retrieve and append the 16-byte authentication tag
    std::array<uint8_t, AES_TAG_LEN> tag{};
    if (EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_AEAD_GET_TAG,
                             AES_TAG_LEN, tag.data()) != 1)
        throw std::runtime_error("EVP_CTRL_AEAD_GET_TAG failed");
    out.write(reinterpret_cast<const char*>(tag.data()), AES_TAG_LEN);
}

// ---------------------------------------------------------------------------
// Non-AEAD decryption — 2-pass: verify HMAC, then decrypt.
// No plaintext byte is written until the HMAC check passes.
// ---------------------------------------------------------------------------

static void decrypt_non_aead(std::ifstream& f, std::ofstream& out,
                              const uint8_t* raw_hdr, size_t hdr_size,
                              const DerivedKeys& keys, Mode mode, const IV& iv,
                              size_t cipher_size) {
    // --- Pass 1: HMAC verification ---
    HMACTag stored_tag{};
    f.seekg(-static_cast<std::streamoff>(HMAC_TAG_LEN), std::ios::end);
    f.read(reinterpret_cast<char*>(stored_tag.data()), HMAC_TAG_LEN);

    HmacCtx hmac(keys.mac.data(), HMAC_KEY_LEN);
    hmac.update(raw_hdr, hdr_size);

    f.seekg(static_cast<std::streamoff>(hdr_size));
    {
        static constexpr size_t CHUNK = 65536;
        std::vector<uint8_t> buf(CHUNK);
        size_t rem = cipher_size;
        while (rem > 0) {
            size_t n = std::min(rem, CHUNK);
            f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(n));
            size_t got = static_cast<size_t>(f.gcount());
            if (got == 0) break;
            hmac.update(buf.data(), got);
            rem -= got;
        }
    }

    if (CRYPTO_memcmp(hmac.finalize().data(), stored_tag.data(), HMAC_TAG_LEN) != 0)
        throw std::runtime_error(
            "HMAC verification failed — file is tampered or password is wrong");

    // --- Pass 2: decryption ---
    CipherRef cipher = make_cipher(mode);
    EvpCtx    aes;
    if (EVP_DecryptInit_ex(aes.ctx, cipher.get(), nullptr,
                           keys.enc.data(),
                           mode_needs_iv(mode) ? iv.data() : nullptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    f.seekg(static_cast<std::streamoff>(hdr_size));

    static constexpr size_t CHUNK = 65536;
    std::vector<uint8_t> ibuf(CHUNK), obuf(CHUNK + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    size_t rem = cipher_size;

    while (rem > 0) {
        size_t n = std::min(rem, CHUNK);
        f.read(reinterpret_cast<char*>(ibuf.data()), static_cast<std::streamsize>(n));
        int got = static_cast<int>(f.gcount());
        if (got == 0) break;
        if (EVP_DecryptUpdate(aes.ctx, obuf.data(), &len, ibuf.data(), got) != 1)
            throw std::runtime_error("EVP_DecryptUpdate failed");
        out.write(reinterpret_cast<const char*>(obuf.data()), len);
        rem -= static_cast<size_t>(got);
    }

    if (EVP_DecryptFinal_ex(aes.ctx, obuf.data(), &len) != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed (padding error)");
    out.write(reinterpret_cast<const char*>(obuf.data()), len);
}

// ---------------------------------------------------------------------------
// AEAD decryption — read 16-byte AEAD tag from end, then decrypt + verify.
//
// Per-mode init strategy (confirmed by OpenSSL 3.0 API testing):
//
//   GCM / GCM-SIV : two-step init (cipher then key+nonce), stream ciphertext,
//                   SET_TAG before EVP_DecryptFinal_ex — Final verifies.
//
//   CCM            : two-step init, SET_TAG *before* key init,
//                   declare total length, single DecryptUpdate call —
//                   verification happens inside DecryptUpdate.
//
//   SIV            : one-step init (cipher + key together), then SET_TAG,
//                   then stream ciphertext — Final verifies.
//                   (Unlike GCM, splitting init into two steps resets the tag
//                   state in OpenSSL 3.0 SIV, causing silent verification bypass.)
// ---------------------------------------------------------------------------

static void decrypt_aead(std::ifstream& f, std::ofstream& out,
                         const DerivedKeys& keys, Mode mode, const IV& iv,
                         size_t cipher_size) {
    std::array<uint8_t, AES_TAG_LEN> tag{};
    f.seekg(-static_cast<std::streamoff>(AES_TAG_LEN), std::ios::end);
    f.read(reinterpret_cast<char*>(tag.data()), AES_TAG_LEN);

    // GCM-SIV: RFC 8452 manual implementation (nonce = first 12 bytes of iv)
    if (mode == Mode::GCM_SIV) {
        f.seekg(static_cast<std::streamoff>(sizeof(FileHeader)));
        std::vector<uint8_t> ct(cipher_size);
        f.read(reinterpret_cast<char*>(ct.data()),
               static_cast<std::streamsize>(cipher_size));
        auto pt = gcmsiv::decrypt(keys.enc.data(), iv.data(),
                                   nullptr, 0,
                                   ct.data(), cipher_size,
                                   tag.data());
        out.write(reinterpret_cast<const char*>(pt.data()),
                  static_cast<std::streamsize>(pt.size()));
        return;
    }

    CipherRef cipher = make_cipher(mode);
    EvpCtx    ctx;

    f.seekg(static_cast<std::streamoff>(sizeof(FileHeader)));

    if (mode == Mode::CCM) {
        // CCM: two-step init; tag and length must be declared before data.
        EVP_DecryptInit_ex(ctx.ctx, cipher.get(), nullptr, nullptr, nullptr);

        size_t nlen = nonce_len(mode);
        if (nlen != static_cast<size_t>(EVP_CIPHER_get_iv_length(cipher.get())))
            EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                static_cast<int>(nlen), nullptr);

        EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_AEAD_SET_TAG,
                             AES_TAG_LEN, tag.data());
        EVP_DecryptInit_ex(ctx.ctx, nullptr, nullptr, keys.enc.data(), iv.data());

        std::vector<uint8_t> ct(cipher_size);
        f.read(reinterpret_cast<char*>(ct.data()),
               static_cast<std::streamsize>(cipher_size));

        std::vector<uint8_t> pt(cipher_size + EVP_MAX_BLOCK_LENGTH);
        int len = 0;
        EVP_DecryptUpdate(ctx.ctx, nullptr, &len, nullptr,
                          static_cast<int>(cipher_size));
        if (EVP_DecryptUpdate(ctx.ctx, pt.data(), &len,
                              ct.data(), static_cast<int>(cipher_size)) != 1)
            throw std::runtime_error(
                "AEAD (CCM) verification failed — file is tampered or password is wrong");
        out.write(reinterpret_cast<const char*>(pt.data()), len);

    } else if (mode == Mode::SIV) {
        // SIV: one-step init (cipher + key in the same call), then SET_TAG.
        // Splitting into two EVP_DecryptInit_ex calls resets the tag state in
        // OpenSSL 3.0's SIV implementation, producing wrong output without error.
        auto sk = make_siv_key(keys);
        EVP_DecryptInit_ex(ctx.ctx, cipher.get(), nullptr, sk.data(), nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_AEAD_SET_TAG,
                             AES_TAG_LEN, tag.data());

        static constexpr size_t CHUNK = 65536;
        std::vector<uint8_t> ibuf(CHUNK), obuf(CHUNK + EVP_MAX_BLOCK_LENGTH);
        int len = 0;
        size_t rem = cipher_size;

        while (rem > 0) {
            size_t n = std::min(rem, CHUNK);
            f.read(reinterpret_cast<char*>(ibuf.data()), static_cast<std::streamsize>(n));
            int got = static_cast<int>(f.gcount());
            if (got == 0) break;
            if (EVP_DecryptUpdate(ctx.ctx, obuf.data(), &len, ibuf.data(), got) != 1)
                throw std::runtime_error(
                    "AEAD (SIV) verification failed — file is tampered or password is wrong");
            out.write(reinterpret_cast<const char*>(obuf.data()), len);
            rem -= static_cast<size_t>(got);
        }

        if (EVP_DecryptFinal_ex(ctx.ctx, obuf.data(), &len) != 1)
            throw std::runtime_error(
                "AEAD (SIV) verification failed — file is tampered or password is wrong");
        out.write(reinterpret_cast<const char*>(obuf.data()), len);

    } else {
        // GCM / GCM-SIV: two-step init, stream ciphertext, SET_TAG before Final.
        EVP_DecryptInit_ex(ctx.ctx, cipher.get(), nullptr, nullptr, nullptr);

        size_t nlen = nonce_len(mode);
        if (nlen != static_cast<size_t>(EVP_CIPHER_get_iv_length(cipher.get())))
            EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                static_cast<int>(nlen), nullptr);

        EVP_DecryptInit_ex(ctx.ctx, nullptr, nullptr, keys.enc.data(), iv.data());

        static constexpr size_t CHUNK = 65536;
        std::vector<uint8_t> ibuf(CHUNK), obuf(CHUNK + EVP_MAX_BLOCK_LENGTH);
        int len = 0;
        size_t rem = cipher_size;

        while (rem > 0) {
            size_t n = std::min(rem, CHUNK);
            f.read(reinterpret_cast<char*>(ibuf.data()), static_cast<std::streamsize>(n));
            int got = static_cast<int>(f.gcount());
            if (got == 0) break;
            if (EVP_DecryptUpdate(ctx.ctx, obuf.data(), &len, ibuf.data(), got) != 1)
                throw std::runtime_error("EVP_DecryptUpdate (AEAD) failed");
            out.write(reinterpret_cast<const char*>(obuf.data()), len);
            rem -= static_cast<size_t>(got);
        }

        // Set tag before Final — GCM/GCM-SIV verify at EVP_DecryptFinal_ex
        EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_AEAD_SET_TAG,
                             AES_TAG_LEN, tag.data());
        if (EVP_DecryptFinal_ex(ctx.ctx, obuf.data(), &len) != 1)
            throw std::runtime_error(
                "AEAD verification failed — file is tampered or password is wrong");
        out.write(reinterpret_cast<const char*>(obuf.data()), len);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void encrypt_file(const std::string& in_path,
                  const std::string& out_path,
                  std::string_view   password,
                  Mode               mode) {
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input file: " + in_path);

    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw std::runtime_error("Cannot open output file: " + out_path);

    const Salt salt = random_salt();

    // Build IV/nonce field (always 16 bytes in header):
    //   non-AEAD          : full 16-byte random IV (zeros for ECB)
    //   GCM/CCM/GCM-SIV  : 12-byte random nonce in [0..11], rest zeros
    //   SIV               : all zeros (deterministic; nonce not applicable)
    IV iv{};
    if (!mode_is_aead(mode)) {
        if (mode_needs_iv(mode)) iv = random_iv();
    } else if (nonce_len(mode) > 0) {
        if (RAND_bytes(iv.data(), static_cast<int>(nonce_len(mode))) != 1)
            throw std::runtime_error("RAND_bytes (nonce) failed");
    }

    const auto keys = derive_keys(password, salt);

    FileHeader hdr{};
    std::memcpy(hdr.magic, FileHeader::MAGIC, 4);
    hdr.mode = static_cast<uint8_t>(mode);
    std::memcpy(hdr.salt, salt.data(), SALT_LEN);
    std::memcpy(hdr.iv,   iv.data(),   IV_LEN);
    out.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    if (!out) throw std::runtime_error("Write error on header");

    if (mode_is_aead(mode))
        encrypt_aead(in, out, keys, mode, iv);
    else
        encrypt_non_aead(in, out, keys,
                         reinterpret_cast<const uint8_t*>(&hdr), sizeof(hdr),
                         mode, iv);

    if (!out) throw std::runtime_error("Write error on output file");
}

void decrypt_file(const std::string& in_path,
                  const std::string& out_path,
                  std::string_view   password) {
    std::ifstream f(in_path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open input file: " + in_path);

    uint8_t raw_hdr[sizeof(FileHeader)];
    f.read(reinterpret_cast<char*>(raw_hdr), sizeof(raw_hdr));
    if (f.gcount() != static_cast<std::streamsize>(sizeof(raw_hdr)))
        throw std::runtime_error("File too short or not a valid .enc file");

    FileHeader hdr{};
    std::memcpy(&hdr, raw_hdr, sizeof(hdr));
    if (std::memcmp(hdr.magic, FileHeader::MAGIC, 4) != 0)
        throw std::runtime_error("Invalid file header — not a v3 .enc file");
    if (hdr.mode > static_cast<uint8_t>(Mode::SIV))
        throw std::runtime_error("Unknown cipher mode in file header");

    const auto mode = static_cast<Mode>(hdr.mode);

    Salt salt{};  IV iv{};
    std::memcpy(salt.data(), hdr.salt, SALT_LEN);
    std::memcpy(iv.data(),   hdr.iv,   IV_LEN);

    f.seekg(0, std::ios::end);
    auto file_size   = static_cast<std::streamoff>(f.tellg());
    auto tag_size    = static_cast<std::streamoff>(auth_tag_size(mode));
    auto hdr_size    = static_cast<std::streamoff>(sizeof(FileHeader));
    auto ct_size_off = file_size - hdr_size - tag_size;
    if (ct_size_off < 0)
        throw std::runtime_error("File too short to be a valid .enc file");
    auto cipher_size = static_cast<size_t>(ct_size_off);

    const auto keys = derive_keys(password, salt);

    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw std::runtime_error("Cannot open output file: " + out_path);

    if (mode_is_aead(mode))
        decrypt_aead(f, out, keys, mode, iv, cipher_size);
    else
        decrypt_non_aead(f, out, raw_hdr, sizeof(raw_hdr),
                         keys, mode, iv, cipher_size);

    if (!out) throw std::runtime_error("Write error on output file");
}

}  // namespace crypto
