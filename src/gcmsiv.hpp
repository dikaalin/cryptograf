#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

// RFC 8452 AES-256-GCM-SIV
// Manual implementation using OpenSSL AES-ECB as the only primitive.
// Compatible with OpenSSL 3.0 (does not require OpenSSL >= 3.2).
namespace gcmsiv {

// Returns ciphertext (pt_len bytes) || auth_tag (16 bytes).
std::vector<uint8_t> encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt,  size_t pt_len);

// Authenticates and decrypts.  tag is the 16-byte auth tag.
// Throws std::runtime_error if authentication fails.
std::vector<uint8_t> decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct,  size_t ct_len,
    const uint8_t tag[16]);

} // namespace gcmsiv
