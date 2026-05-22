#include "digital_sign.hpp"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <fstream>
#include <stdexcept>
#include <vector>

namespace crypto {

static std::string ssl_error() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

void generate_ec_keypair(const std::string& priv_path, const std::string& pub_path) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id: " + ssl_error());

    EVP_PKEY* pkey = nullptr;
    auto guard = [&]() { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey); };

    if (EVP_PKEY_keygen_init(ctx) <= 0)                                       { guard(); throw std::runtime_error("keygen_init: " + ssl_error()); }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) { guard(); throw std::runtime_error("set_curve: " + ssl_error()); }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)                                     { guard(); throw std::runtime_error("keygen: " + ssl_error()); }
    EVP_PKEY_CTX_free(ctx); ctx = nullptr;

    FILE* f = fopen(priv_path.c_str(), "wb");
    if (!f) { EVP_PKEY_free(pkey); throw std::runtime_error("Cannot create: " + priv_path); }
    bool ok = PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 0;
    fclose(f);
    if (!ok) { EVP_PKEY_free(pkey); throw std::runtime_error("PEM_write_PrivateKey: " + ssl_error()); }

    f = fopen(pub_path.c_str(), "wb");
    if (!f) { EVP_PKEY_free(pkey); throw std::runtime_error("Cannot create: " + pub_path); }
    ok = PEM_write_PUBKEY(f, pkey) != 0;
    fclose(f);
    EVP_PKEY_free(pkey);
    if (!ok) throw std::runtime_error("PEM_write_PUBKEY: " + ssl_error());
}

void sign_file(const std::string& file_path, const std::string& key_path,
               const std::string& sig_path) {
    FILE* f = fopen(key_path.c_str(), "rb");
    if (!f) throw std::runtime_error("Cannot open key: " + key_path);
    EVP_PKEY* pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!pkey) throw std::runtime_error("PEM_read_PrivateKey: " + ssl_error());

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); throw std::runtime_error("EVP_MD_CTX_new"); }

    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("DigestSignInit: " + ssl_error());
    }

    std::ifstream in(file_path, std::ios::binary);
    if (!in) { EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throw std::runtime_error("Cannot open: " + file_path); }
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

    std::ofstream out(sig_path, std::ios::binary);
    if (!out) throw std::runtime_error("Cannot write: " + sig_path);
    out.write(reinterpret_cast<const char*>(sig.data()), static_cast<std::streamsize>(siglen));
}

bool verify_file(const std::string& file_path, const std::string& sig_path,
                 const std::string& key_path) {
    FILE* f = fopen(key_path.c_str(), "rb");
    if (!f) throw std::runtime_error("Cannot open key: " + key_path);
    EVP_PKEY* pkey = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!pkey) throw std::runtime_error("PEM_read_PUBKEY: " + ssl_error());

    std::ifstream sf(sig_path, std::ios::binary);
    if (!sf) { EVP_PKEY_free(pkey); throw std::runtime_error("Cannot open sig: " + sig_path); }
    std::vector<unsigned char> sig(
        (std::istreambuf_iterator<char>(sf)),
        std::istreambuf_iterator<char>());

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); throw std::runtime_error("EVP_MD_CTX_new"); }

    if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
        throw std::runtime_error("DigestVerifyInit: " + ssl_error());
    }

    std::ifstream in(file_path, std::ios::binary);
    if (!in) { EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey); throw std::runtime_error("Cannot open: " + file_path); }
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
