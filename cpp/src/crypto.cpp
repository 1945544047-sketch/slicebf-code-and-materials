#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <cstring>
#include <stdexcept>

namespace sbf {

Key32 random_key() {
    Key32 k{};
    if (RAND_bytes(k.data(), static_cast<int>(k.size())) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return k;
}

std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t key_len,
                                    const uint8_t* data, size_t data_len) {
    std::array<uint8_t, 32> out{};
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), key, static_cast<int>(key_len), data, data_len,
              out.data(), &out_len) || out_len != 32)
        throw std::runtime_error("HMAC-SHA256 failed");
    return out;
}

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t data_len) {
    std::array<uint8_t, 32> out{};
    unsigned int out_len = 0;
    if (EVP_Digest(data, data_len, out.data(), &out_len, EVP_sha256(),
                   nullptr) != 1 ||
        out_len != out.size()) {
        throw std::runtime_error("SHA-256 failed");
    }
    return out;
}

// HKDF: extract-then-expand (RFC 5869), single 32-byte output block.
Key32 hkdf_sha256(const Key32& ikm, const std::string& info) {
    // Extract: PRK = HMAC(salt=zero32, IKM). We use a zero salt (domain
    // separation is provided by distinct info labels).
    static const std::array<uint8_t, 32> zero_salt{};
    auto prk = hmac_sha256(zero_salt.data(), zero_salt.size(),
                           ikm.data(), ikm.size());
    // Expand: T(1) = HMAC(PRK, info || 0x01).
    std::vector<uint8_t> msg(info.begin(), info.end());
    msg.push_back(0x01);
    auto okm = hmac_sha256(prk.data(), prk.size(), msg.data(), msg.size());
    return okm;  // 32 bytes, exactly one block.
}

bool ct_equal(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    return CRYPTO_memcmp(a.data(), b.data(), 32) == 0;
}

std::vector<uint8_t> aead_encrypt(const Key16& key, const std::vector<uint8_t>& pt,
                                  const std::vector<uint8_t>& aad) {
    std::vector<uint8_t> nonce(12);
    if (RAND_bytes(nonce.data(), 12) != 1)
        throw std::runtime_error("RAND_bytes(nonce) failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::vector<uint8_t> ct(pt.size());
    std::array<uint8_t, 16> tag{};
    int len = 0, ct_len = 0;
    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
            throw std::runtime_error("GCM enc init failed");
        if (!aad.empty() &&
            EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                              static_cast<int>(aad.size())) != 1)
            throw std::runtime_error("GCM enc AAD failed");
        if (!pt.empty() &&
            EVP_EncryptUpdate(ctx, ct.data(), &len, pt.data(),
                              static_cast<int>(pt.size())) != 1)
            throw std::runtime_error("GCM enc update failed");
        ct_len = len;
        if (EVP_EncryptFinal_ex(ctx, ct.data() + ct_len, &len) != 1)
            throw std::runtime_error("GCM enc final failed");
        ct_len += len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
            throw std::runtime_error("GCM get tag failed");
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> blob;
    blob.reserve(12 + ct_len + 16);
    blob.insert(blob.end(), nonce.begin(), nonce.end());
    blob.insert(blob.end(), ct.begin(), ct.begin() + ct_len);
    blob.insert(blob.end(), tag.begin(), tag.end());
    return blob;
}

std::vector<uint8_t> aead_decrypt(const Key16& key, const std::vector<uint8_t>& blob,
                                  const std::vector<uint8_t>& aad) {
    if (blob.size() < 12 + 16) throw std::runtime_error("AEAD blob too short");
    const uint8_t* nonce = blob.data();
    const uint8_t* ct = blob.data() + 12;
    size_t ct_len = blob.size() - 12 - 16;
    const uint8_t* tag = blob.data() + 12 + ct_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::vector<uint8_t> pt(ct_len);
    int len = 0, pt_len = 0;
    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1)
            throw std::runtime_error("GCM dec init failed");
        if (!aad.empty() &&
            EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(),
                              static_cast<int>(aad.size())) != 1)
            throw std::runtime_error("GCM dec AAD failed");
        if (ct_len > 0 &&
            EVP_DecryptUpdate(ctx, pt.data(), &len, ct, static_cast<int>(ct_len)) != 1)
            throw std::runtime_error("GCM dec update failed");
        pt_len = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                const_cast<uint8_t*>(tag)) != 1)
            throw std::runtime_error("GCM set tag failed");
        if (EVP_DecryptFinal_ex(ctx, pt.data() + pt_len, &len) != 1)
            throw std::runtime_error("GCM auth verification failed");
        pt_len += len;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);
    pt.resize(pt_len);
    return pt;
}

std::vector<uint8_t> aes128_ctr_prg(const Key16& key,
                                    const std::array<uint8_t, 16>& iv,
                                    size_t output_bytes) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::vector<uint8_t> zeros(output_bytes, 0);
    std::vector<uint8_t> out(output_bytes);
    int len = 0, total = 0;
    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(),
                              iv.data()) != 1)
            throw std::runtime_error("CTR init failed");
        if (output_bytes &&
            EVP_EncryptUpdate(ctx, out.data(), &len, zeros.data(),
                              static_cast<int>(output_bytes)) != 1)
            throw std::runtime_error("CTR update failed");
        total = len;
        if (EVP_EncryptFinal_ex(ctx, out.data() + total, &len) != 1)
            throw std::runtime_error("CTR final failed");
        total += len;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);
    out.resize(static_cast<size_t>(total));
    return out;
}

}  // namespace sbf
