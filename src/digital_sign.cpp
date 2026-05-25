#include "digital_sign.hpp"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>

// On Windows, fopen/std::ifstream use ANSI (system code page), not UTF-8.
// std::filesystem::path(std::u8string) converts UTF-8 → UTF-16 on Windows.
static std::filesystem::path to_fs_path(const std::string& utf8) {
#ifdef _WIN32
    return std::filesystem::path(std::u8string(utf8.begin(), utf8.end()));
#else
    return std::filesystem::path(utf8);
#endif
}

static std::vector<char> read_file_bytes(const std::string& utf8_path) {
    std::ifstream f(to_fs_path(utf8_path), std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open file: " + utf8_path);
    return {std::istreambuf_iterator<char>(f), {}};
}

static void write_file_bytes(const std::string& utf8_path,
                             const char* data, std::streamsize size) {
    std::ofstream f(to_fs_path(utf8_path), std::ios::binary);
    if (!f) throw std::runtime_error("Cannot create file: " + utf8_path);
    f.write(data, size);
    if (!f) throw std::runtime_error("Write error: " + utf8_path);
}

static std::string ssl_error() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

namespace crypto {

void generate_ec_keypair(const std::string& priv_path, const std::string& pub_path) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id: " + ssl_error());

    EVP_PKEY* pkey = nullptr;
    auto guard = [&]() { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey); };

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        { guard(); throw std::runtime_error("keygen_init: " + ssl_error()); }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
        { guard(); throw std::runtime_error("set_curve: " + ssl_error()); }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        { guard(); throw std::runtime_error("keygen: " + ssl_error()); }
    EVP_PKEY_CTX_free(ctx); ctx = nullptr;

    // Write private key via memory BIO to avoid fopen ANSI/UTF-8 issue on Windows
    {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) { EVP_PKEY_free(pkey); throw std::runtime_error("BIO_new (priv)"); }
        bool ok = PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 0;
        if (!ok) {
            BIO_free(bio); EVP_PKEY_free(pkey);
            throw std::runtime_error("PEM_write_bio_PrivateKey: " + ssl_error());
        }
        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(bio, &bptr);
        write_file_bytes(priv_path, bptr->data, static_cast<std::streamsize>(bptr->length));
        BIO_free(bio);
    }

    // Write public key via memory BIO
    {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) { EVP_PKEY_free(pkey); throw std::runtime_error("BIO_new (pub)"); }
        bool ok = PEM_write_bio_PUBKEY(bio, pkey) != 0;
        EVP_PKEY_free(pkey);
        if (!ok) {
            BIO_free(bio);
            throw std::runtime_error("PEM_write_bio_PUBKEY: " + ssl_error());
        }
        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(bio, &bptr);
        write_file_bytes(pub_path, bptr->data, static_cast<std::streamsize>(bptr->length));
        BIO_free(bio);
    }
}

void sign_file(const std::string& file_path, const std::string& key_path,
               const std::string& sig_path) {
    // Read private key via memory BIO (avoids fopen ANSI issue on Windows)
    auto keybuf = read_file_bytes(key_path);
    BIO* bio = BIO_new_mem_buf(keybuf.data(), static_cast<int>(keybuf.size()));
    if (!bio) throw std::runtime_error("BIO_new_mem_buf: " + ssl_error());
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("PEM_read_bio_PrivateKey: " + ssl_error());

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); throw std::runtime_error("EVP_MD_CTX_new"); }

    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("DigestSignInit: " + ssl_error());
    }

    std::ifstream in(to_fs_path(file_path), std::ios::binary);
    if (!in) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("Cannot open: " + file_path);
    }
    char buf[65536];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
        if (EVP_DigestSignUpdate(mdctx, buf, static_cast<size_t>(in.gcount())) <= 0) {
            EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
            throw std::runtime_error("DigestSignUpdate: " + ssl_error());
        }
    }

    size_t siglen = 0;
    if (EVP_DigestSignFinal(mdctx, nullptr, &siglen) <= 0) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("DigestSignFinal (size): " + ssl_error());
    }
    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSignFinal(mdctx, sig.data(), &siglen) <= 0) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("DigestSignFinal: " + ssl_error());
    }
    sig.resize(siglen);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    write_file_bytes(sig_path,
                     reinterpret_cast<const char*>(sig.data()),
                     static_cast<std::streamsize>(siglen));
}

bool verify_file(const std::string& file_path, const std::string& sig_path,
                 const std::string& key_path) {
    // Read public key via memory BIO
    auto keybuf = read_file_bytes(key_path);
    BIO* bio = BIO_new_mem_buf(keybuf.data(), static_cast<int>(keybuf.size()));
    if (!bio) throw std::runtime_error("BIO_new_mem_buf: " + ssl_error());
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("PEM_read_bio_PUBKEY: " + ssl_error());

    // Read signature file
    auto sigbuf = read_file_bytes(sig_path);
    std::vector<unsigned char> sig(sigbuf.begin(), sigbuf.end());

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); throw std::runtime_error("EVP_MD_CTX_new"); }

    if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("DigestVerifyInit: " + ssl_error());
    }

    std::ifstream in(to_fs_path(file_path), std::ios::binary);
    if (!in) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("Cannot open: " + file_path);
    }
    char buf[65536];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
        if (EVP_DigestVerifyUpdate(mdctx, buf, static_cast<size_t>(in.gcount())) <= 0) {
            EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
            throw std::runtime_error("DigestVerifyUpdate: " + ssl_error());
        }
    }

    int rc = EVP_DigestVerifyFinal(mdctx, sig.data(), sig.size());
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    if (rc == 1) return true;
    if (rc == 0) return false;
    throw std::runtime_error("DigestVerifyFinal: " + ssl_error());
}

} // namespace crypto
