#include "gcmsiv.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace gcmsiv {

// ---------------------------------------------------------------------------
// AES-256-ECB block cipher (one block at a time, reusable context)
// ---------------------------------------------------------------------------

struct AesEcb {
    EVP_CIPHER_CTX* ctx;

    explicit AesEcb(const uint8_t key[32]) : ctx(EVP_CIPHER_CTX_new()) {
        if (!ctx) throw std::runtime_error("gcmsiv: EVP_CIPHER_CTX_new failed");
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr) != 1)
            throw std::runtime_error("gcmsiv: AES-256-ECB init failed");
    }
    ~AesEcb() { EVP_CIPHER_CTX_free(ctx); }

    void operator()(const uint8_t in[16], uint8_t out[16]) const {
        int len = 0;
        if (EVP_EncryptUpdate(ctx, out, &len, in, 16) != 1)
            throw std::runtime_error("gcmsiv: AES-256-ECB encrypt failed");
    }

    AesEcb(const AesEcb&)            = delete;
    AesEcb& operator=(const AesEcb&) = delete;
};

// ---------------------------------------------------------------------------
// POLYVAL — RFC 8452 Section 3
//
// Field: GF(2^128) with irreducible polynomial x^128 + x^127 + x^126 + x^121 + 1.
// Byte representation: LE bit order — byte[i] holds coefficients x^(8i)..x^(8i+7)
//   with the least-significant bit = lowest degree.
// "Multiply by x": left-shift the 128-bit LE integer; if the x^127 bit carries out,
//   XOR with the reduction constant (x^127 + x^126 + x^121 + 1):
//     byte[0]  ^= 0x01   (x^0 = 1)
//     byte[15] ^= 0xc2   (x^127 | x^126 | x^121 = 0x80 | 0x40 | 0x02)
//
// The POLYVAL step is dot(a, H) = a * H * x^{-128} (RFC 8452 Section 3).
// x^{-128} = x^127 + x^124 + x^121 + x^114 + 1 (RFC 8452 Section 7).
// We precompute H_dot = H * x^{-128} so each step needs only one multiplication.
// ---------------------------------------------------------------------------

// Multiplication in GF(2^128) with polynomial x^128 + x^127 + x^126 + x^121 + 1.
static void gf_mul(uint8_t r[16], const uint8_t a[16], const uint8_t b[16]) {
    uint8_t prod[16] = {};
    uint8_t v[16];
    std::memcpy(v, a, 16);

    for (int i = 0; i < 128; ++i) {
        if (b[i >> 3] & (static_cast<uint8_t>(1u) << (i & 7)))
            for (int j = 0; j < 16; ++j) prod[j] ^= v[j];

        const uint8_t carry = v[15] >> 7;
        for (int j = 15; j > 0; --j)
            v[j] = static_cast<uint8_t>((v[j] << 1) | (v[j - 1] >> 7));
        v[0] = static_cast<uint8_t>(v[0] << 1);
        if (carry) { v[0] ^= 0x01; v[15] ^= 0xc2; }
    }
    std::memcpy(r, prod, 16);
}

// x^{-128} = x^127 + x^124 + x^121 + x^114 + 1
// In LE byte representation:
//   x^0   → byte[0]  bit 0 = 0x01
//   x^114 → byte[14] bit 2 = 0x04
//   x^121 → byte[15] bit 1 = 0x02
//   x^124 → byte[15] bit 4 = 0x10
//   x^127 → byte[15] bit 7 = 0x80
static constexpr uint8_t XINV128[16] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x92
};

// Precompute H_dot = H * x^{-128} so polyval_update only needs one gf_mul.
static void make_hdot(uint8_t hdot[16], const uint8_t H[16]) {
    gf_mul(hdot, H, XINV128);
}

// POLYVAL update: acc = dot(acc XOR block, H) = (acc XOR block) * H_dot
static void polyval_update(uint8_t acc[16], const uint8_t Hdot[16],
                            const uint8_t block[16]) {
    for (int i = 0; i < 16; ++i) acc[i] ^= block[i];
    uint8_t tmp[16];
    gf_mul(tmp, acc, Hdot);
    std::memcpy(acc, tmp, 16);
}

// Feed arbitrary-length data through POLYVAL; last block zero-padded.
static void polyval_feed(uint8_t acc[16], const uint8_t Hdot[16],
                          const uint8_t* data, size_t len) {
    while (len >= 16) {
        polyval_update(acc, Hdot, data);
        data += 16;
        len  -= 16;
    }
    if (len > 0) {
        uint8_t block[16] = {};
        std::memcpy(block, data, len);
        polyval_update(acc, Hdot, block);
    }
}

// ---------------------------------------------------------------------------
// Key derivation (RFC 8452 Section 4)
//
//   For i = 0..5: in_block = LE32(i) || nonce (12 bytes)
//                 out_block = AES256(key, in_block)
//   auth_key (16 B) = out_block[0][0..7] || out_block[1][0..7]
//   enc_key  (32 B) = out_block[2][0..7] || ... || out_block[5][0..7]
// ---------------------------------------------------------------------------

static void derive_subkeys(const uint8_t key[32], const uint8_t nonce[12],
                            uint8_t auth_key[16], uint8_t enc_key[32]) {
    AesEcb aes(key);
    for (uint32_t i = 0; i < 6; ++i) {
        uint8_t in_blk[16] = {};
        in_blk[0] = static_cast<uint8_t>(i);
        in_blk[1] = static_cast<uint8_t>(i >> 8);
        in_blk[2] = static_cast<uint8_t>(i >> 16);
        in_blk[3] = static_cast<uint8_t>(i >> 24);
        std::memcpy(in_blk + 4, nonce, 12);

        uint8_t out_blk[16];
        aes(in_blk, out_blk);

        if (i < 2)
            std::memcpy(auth_key + i * 8,       out_blk, 8);
        else
            std::memcpy(enc_key  + (i - 2) * 8, out_blk, 8);
    }
}

// ---------------------------------------------------------------------------
// Tag computation (RFC 8452 Section 5)
// ---------------------------------------------------------------------------

static void write_le64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) { p[i] = static_cast<uint8_t>(v); v >>= 8; }
}

static void compute_tag(const uint8_t auth_key[16], const uint8_t enc_key[32],
                         const uint8_t nonce[12],
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t* pt,  size_t pt_len,
                         uint8_t tag[16]) {
    uint8_t Hdot[16];
    make_hdot(Hdot, auth_key);

    uint8_t acc[16] = {};
    polyval_feed(acc, Hdot, aad, aad_len);
    polyval_feed(acc, Hdot, pt,  pt_len);

    uint8_t len_block[16] = {};
    write_le64(len_block,     static_cast<uint64_t>(aad_len) * 8);
    write_le64(len_block + 8, static_cast<uint64_t>(pt_len)  * 8);
    polyval_update(acc, Hdot, len_block);

    for (int i = 0; i < 12; ++i) acc[i] ^= nonce[i];
    acc[15] &= 0x7f;

    AesEcb aes(enc_key);
    aes(acc, tag);
}

// ---------------------------------------------------------------------------
// GCM-SIV CTR mode
//
// counter_base = tag with bit 127 set (byte[15] |= 0x80).
// Block i uses counter_base with its low 32 bits (LE) incremented by i (i=1,2,...).
// ---------------------------------------------------------------------------

static void ctr_crypt(const uint8_t enc_key[32], const uint8_t tag[16],
                       const uint8_t* in, uint8_t* out, size_t len) {
    uint8_t counter[16];
    std::memcpy(counter, tag, 16);
    counter[15] |= 0x80;

    // RFC 8452 §4: counter starts at J0 itself and increments the low 32 bits
    const uint32_t ctr_base = static_cast<uint32_t>(counter[0])
                            | (static_cast<uint32_t>(counter[1]) << 8)
                            | (static_cast<uint32_t>(counter[2]) << 16)
                            | (static_cast<uint32_t>(counter[3]) << 24);

    AesEcb aes(enc_key);
    size_t off = 0;
    for (uint32_t blk = 0; off < len; ++blk) {
        const uint32_t c = ctr_base + blk;
        counter[0] = static_cast<uint8_t>(c);
        counter[1] = static_cast<uint8_t>(c >> 8);
        counter[2] = static_cast<uint8_t>(c >> 16);
        counter[3] = static_cast<uint8_t>(c >> 24);

        uint8_t ks[16];
        aes(counter, ks);

        const size_t n = std::min(static_cast<size_t>(16), len - off);
        for (size_t i = 0; i < n; ++i)
            out[off + i] = in[off + i] ^ ks[i];
        off += n;
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::vector<uint8_t> encrypt(
    const uint8_t key[32],   const uint8_t nonce[12],
    const uint8_t* aad,      size_t aad_len,
    const uint8_t* pt,       size_t pt_len) {

    uint8_t auth_key[16], enc_key[32];
    derive_subkeys(key, nonce, auth_key, enc_key);

    uint8_t tag[16];
    compute_tag(auth_key, enc_key, nonce, aad, aad_len, pt, pt_len, tag);

    std::vector<uint8_t> result(pt_len + 16);
    ctr_crypt(enc_key, tag, pt, result.data(), pt_len);
    std::memcpy(result.data() + pt_len, tag, 16);
    return result;
}

std::vector<uint8_t> decrypt(
    const uint8_t key[32],   const uint8_t nonce[12],
    const uint8_t* aad,      size_t aad_len,
    const uint8_t* ct,       size_t ct_len,
    const uint8_t tag[16]) {

    uint8_t auth_key[16], enc_key[32];
    derive_subkeys(key, nonce, auth_key, enc_key);

    std::vector<uint8_t> pt(ct_len);
    ctr_crypt(enc_key, tag, ct, pt.data(), ct_len);

    uint8_t expected_tag[16];
    compute_tag(auth_key, enc_key, nonce, aad, aad_len, pt.data(), ct_len, expected_tag);

    if (CRYPTO_memcmp(tag, expected_tag, 16) != 0)
        throw std::runtime_error(
            "AEAD (GCM-SIV) verification failed — file is tampered or password is wrong");

    return pt;
}

} // namespace gcmsiv
