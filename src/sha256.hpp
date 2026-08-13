// Minimal public-domain-style SHA-256 implementation.
// Standard FIPS 180-4 algorithm, header-only, no external dependencies.
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <array>

namespace crypto {

class SHA256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;

    SHA256() { reset(); }

    void reset() {
        h_ = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
              0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
        buffer_len_ = 0;
        total_len_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        total_len_ += len;
        while (len > 0) {
            size_t take = std::min(len, size_t(64) - buffer_len_);
            std::memcpy(buffer_.data() + buffer_len_, data, take);
            buffer_len_ += take;
            data += take;
            len -= take;
            if (buffer_len_ == 64) {
                transform(buffer_.data());
                buffer_len_ = 0;
            }
        }
    }

    void update(const std::vector<uint8_t>& data) { update(data.data(), data.size()); }

    std::array<uint8_t, DIGEST_SIZE> finalize() {
        uint64_t bit_len = total_len_ * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buffer_len_ != 56) update(&zero, 1);
        uint8_t len_bytes[8];
        for (int i = 0; i < 8; i++) len_bytes[i] = (bit_len >> (56 - 8*i)) & 0xff;
        update(len_bytes, 8);

        std::array<uint8_t, DIGEST_SIZE> out{};
        for (int i = 0; i < 8; i++) {
            out[i*4+0] = (h_[i] >> 24) & 0xff;
            out[i*4+1] = (h_[i] >> 16) & 0xff;
            out[i*4+2] = (h_[i] >> 8) & 0xff;
            out[i*4+3] = h_[i] & 0xff;
        }
        return out;
    }

    static std::array<uint8_t, DIGEST_SIZE> hash(const uint8_t* data, size_t len) {
        SHA256 s;
        s.update(data, len);
        return s.finalize();
    }

private:
    std::array<uint32_t, 8> h_;
    std::array<uint8_t, 64> buffer_;
    size_t buffer_len_;
    uint64_t total_len_;

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void transform(const uint8_t* chunk) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (chunk[i*4]<<24)|(chunk[i*4+1]<<16)|(chunk[i*4+2]<<8)|(chunk[i*4+3]);
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint32_t a=h_[0],b=h_[1],c=h_[2],d=h_[3],e=h_[4],f=h_[5],g=h_[6],hh=h_[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            hh=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d; h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=hh;
    }
};

} // namespace crypto
