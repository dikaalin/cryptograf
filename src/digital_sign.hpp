#pragma once
#include <string>

namespace crypto {

// Generate ECDSA P-256 key pair; writes PEM files
void generate_ec_keypair(const std::string& priv_path, const std::string& pub_path);

// Sign file with private key PEM; writes DER signature to sig_path
void sign_file(const std::string& file_path, const std::string& key_path,
               const std::string& sig_path);

// Verify file against signature using public key PEM
// Returns true = valid, false = invalid, throws on error
bool verify_file(const std::string& file_path, const std::string& sig_path,
                 const std::string& key_path);

} // namespace crypto
