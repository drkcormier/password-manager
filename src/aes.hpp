// AES-256 block cipher (FIPS 197) + CTR mode of operation.
// Standard algorithm, straightforward table-based implementation.
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <array>

namespace crypto {

class AES256 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t BLOCK_SIZE = 16;

    explicit AES256(const uint8_t key[KEY_SIZE]) { key_expansion(key); }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t state[16];
        std::memcpy(state, in, 16);
        add_round_key(state, 0);
        for (int round = 1; round < 14; round++) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round);
        }
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, 14);
        std::memcpy(out, state, 16);
    }

private:
    uint8_t round_keys_[15][16];

    static uint8_t xtime(uint8_t x) { return (x << 1) ^ ((x >> 7) * 0x1b); }
    static uint8_t mul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            a = xtime(a);
            b >>= 1;
        }
        return p;
    }

    static const uint8_t* sbox() {
        static const uint8_t s[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
        return s;
    }

    void key_expansion(const uint8_t key[32]) {
        uint8_t w[60][4];
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < 4; j++) w[i][j] = key[i*4+j];

        static const uint8_t rcon[7] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40};
        for (int i = 8; i < 60; i++) {
            uint8_t temp[4] = {w[i-1][0],w[i-1][1],w[i-1][2],w[i-1][3]};
            if (i % 8 == 0) {
                uint8_t t0 = temp[0];
                temp[0] = sbox()[temp[1]] ^ rcon[i/8 - 1];
                temp[1] = sbox()[temp[2]];
                temp[2] = sbox()[temp[3]];
                temp[3] = sbox()[t0];
            } else if (i % 8 == 4) {
                for (int k = 0; k < 4; k++) temp[k] = sbox()[temp[k]];
            }
            for (int j = 0; j < 4; j++) w[i][j] = w[i-8][j] ^ temp[j];
        }
        for (int round = 0; round < 15; round++)
            for (int c = 0; c < 4; c++)
                for (int r = 0; r < 4; r++)
                    round_keys_[round][c*4+r] = w[round*4+c][r];
    }

    void add_round_key(uint8_t state[16], int round) const {
        for (int i = 0; i < 16; i++) state[i] ^= round_keys_[round][i];
    }

    void sub_bytes(uint8_t state[16]) const {
        for (int i = 0; i < 16; i++) state[i] = sbox()[state[i]];
    }

    void shift_rows(uint8_t state[16]) const {
        uint8_t tmp[16];
        // state is column-major: state[col*4+row]
        for (int col = 0; col < 4; col++)
            for (int row = 0; row < 4; row++)
                tmp[col*4+row] = state[((col+row)%4)*4+row];
        std::memcpy(state, tmp, 16);
    }

    void mix_columns(uint8_t state[16]) const {
        for (int c = 0; c < 4; c++) {
            uint8_t a0 = state[c*4+0], a1 = state[c*4+1], a2 = state[c*4+2], a3 = state[c*4+3];
            state[c*4+0] = mul(a0,2) ^ mul(a1,3) ^ a2 ^ a3;
            state[c*4+1] = a0 ^ mul(a1,2) ^ mul(a2,3) ^ a3;
            state[c*4+2] = a0 ^ a1 ^ mul(a2,2) ^ mul(a3,3);
            state[c*4+3] = mul(a0,3) ^ a1 ^ a2 ^ mul(a3,2);
        }
    }
};

// AES-256-CTR: encrypt and decrypt are the same operation (XOR with keystream).
inline std::vector<uint8_t> aes256_ctr(const uint8_t key[32], const uint8_t iv[16],
                                        const std::vector<uint8_t>& input) {
    AES256 aes(key);
    std::vector<uint8_t> out(input.size());
    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    uint8_t keystream[16];

    size_t offset = 0;
    while (offset < input.size()) {
        aes.encrypt_block(counter, keystream);
        size_t chunk = std::min(size_t(16), input.size() - offset);
        for (size_t i = 0; i < chunk; i++) out[offset+i] = input[offset+i] ^ keystream[i];
        offset += chunk;
        // increment counter (big-endian 128-bit)
        for (int i = 15; i >= 0; i--) { if (++counter[i] != 0) break; }
    }
    return out;
}

} // namespace crypto
