// crypto.hpp — real cryptographic primitives for SliceBF (OpenSSL-backed).
// PRF  : HMAC-SHA-256 (checklist §3.3 admission gate)
// KDF  : HKDF-SHA-256 for subkey derivation
// AEAD : AES-128-GCM, 96-bit nonce, 128-bit tag
#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace sbf {

using Key32 = std::array<uint8_t, 32>;
using Key16 = std::array<uint8_t, 16>;

// 32-byte random master key.
Key32 random_key();

// HMAC-SHA-256(key, data) -> 32 bytes. This is the abstract PRF F.
std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t key_len,
                                    const uint8_t* data, size_t data_len);

// SHA-256(data) -> 32 bytes. Baseline implementations use this for the
// paper-specified cryptographic hash functions H1, H2, and H3.
std::array<uint8_t, 32> sha256(const uint8_t* data, size_t data_len);

// Convenience: PRF over a string message with a 32-byte key.
inline std::array<uint8_t, 32> prf(const Key32& key, const std::string& msg) {
    return hmac_sha256(key.data(), key.size(),
                       reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

// HKDF-SHA-256 expand of a single 32-byte subkey from ikm using an info label.
Key32 hkdf_sha256(const Key32& ikm, const std::string& info);

// Constant-time equality of two 32-byte MACs.
bool ct_equal(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b);

// AES-128-GCM. Returns nonce(12) || ciphertext || tag(16).  The optional
// associated data is authenticated but not encrypted.
std::vector<uint8_t> aead_encrypt(const Key16& key,
                                  const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& aad = {});
// Returns plaintext, or throws std::runtime_error on auth failure.
std::vector<uint8_t> aead_decrypt(const Key16& key,
                                  const std::vector<uint8_t>& blob,
                                  const std::vector<uint8_t>& aad = {});

// Deterministic AES-128-CTR expansion used for the per-position snapshot pad.
// Security requires a unique IV for every (generation, position, bit-plane)
// under one key; callers derive those IVs with the domain-separated PRF.
std::vector<uint8_t> aes128_ctr_prg(const Key16& key,
                                    const std::array<uint8_t, 16>& iv,
                                    size_t output_bytes);

}  // namespace sbf
