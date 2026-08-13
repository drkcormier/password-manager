// HMAC-SHA256 and PBKDF2-HMAC-SHA256. Standard constructions (RFC 2104 / RFC 8018).
#pragma once
#include "sha256.hpp"
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>

namespace crypto {

inline std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key_in, const uint8_t* msg, size_t msg_len) {
    constexpr size_t BLOCK = 64;
    std::vector<uint8_t> key = key_in;
    if (key.size() > BLOCK) {
        auto d = SHA256::hash(key.data(), key.size());
        key.assign(d.begin(), d.end());
    }
    key.resize(BLOCK, 0);

    std::vector<uint8_t> ipad(BLOCK), opad(BLOCK);
    for (size_t i = 0; i < BLOCK; i++) {
        ipad[i] = key[i] ^ 0x36;
        opad[i] = key[i] ^ 0x5c;
    }

    SHA256 inner;
    inner.update(ipad.data(), BLOCK);
    inner.update(msg, msg_len);
    auto inner_digest = inner.finalize();

    SHA256 outer;
    outer.update(opad.data(), BLOCK);
    outer.update(inner_digest.data(), inner_digest.size());
    auto final_digest = outer.finalize();

    return std::vector<uint8_t>(final_digest.begin(), final_digest.end());
}

// Derives `dklen` bytes of key material from `password` + `salt` using
// PBKDF2-HMAC-SHA256 with the given iteration count.
inline std::vector<uint8_t> pbkdf2_hmac_sha256(const std::string& password,
                                                const std::vector<uint8_t>& salt,
                                                uint32_t iterations,
                                                size_t dklen) {
    std::vector<uint8_t> pw(password.begin(), password.end());
    std::vector<uint8_t> out;
    out.reserve(dklen);

    uint32_t block_index = 1;
    while (out.size() < dklen) {
        std::vector<uint8_t> salt_block = salt;
        salt_block.push_back((block_index >> 24) & 0xff);
        salt_block.push_back((block_index >> 16) & 0xff);
        salt_block.push_back((block_index >> 8) & 0xff);
        salt_block.push_back(block_index & 0xff);

        std::vector<uint8_t> u = hmac_sha256(pw, salt_block.data(), salt_block.size());
        std::vector<uint8_t> t = u;

        for (uint32_t iter = 1; iter < iterations; iter++) {
            u = hmac_sha256(pw, u.data(), u.size());
            for (size_t i = 0; i < t.size(); i++) t[i] ^= u[i];
        }

        out.insert(out.end(), t.begin(), t.end());
        block_index++;
    }
    out.resize(dklen);
    return out;
}

} // namespace crypto
