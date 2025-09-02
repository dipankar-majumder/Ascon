#include <iostream>
#include <vector>
#include <random>
#include <cassert>
#include <algorithm> // for std::copy
#include <array>     // for std::array
#include <iomanip>   // for std::hex, setw, setfill
#include "Ascon128.hpp"

// flip a single bit in an 8-byte block (bit 0 = MSB of byte[0], bit 63 = LSB of byte[7])
static void flip_bit(std::vector<uint8_t>& block, int bit) {
    int byte = bit / 8;
    int off  = 7 - (bit % 8);
    block[byte] ^= uint8_t(1u << off);
}

int main() {
    // 0) RNG
    std::mt19937_64 rng{ std::random_device{}() };
    auto rnd_byte = [&]{ return uint8_t(rng() & 0xFF); };

    // 1) Random key & nonce
    std::vector<uint8_t> key(ASCON_KEY_SIZE), nonce(ASCON_NONCE_SIZE);
    for (auto &b : key)   b = rnd_byte();
    for (auto &b : nonce) b = rnd_byte();

    // 2) Three random 8-byte plaintexts
    std::vector<std::vector<uint8_t>> P(3, std::vector<uint8_t>(8));
    for (auto &blk : P)
        for (auto &b : blk)
            b = rnd_byte();

    // 3) Collect fault-free tags
    Ascon128 ascon;
    ascon.fault_enabled = false;

    // T[k][i] holds the 16-byte tag for the k-th base plaintext with its i-th bit flipped
    std::vector<std::vector<std::array<uint8_t, ASCON_TAG_SIZE>>> T(
      3, std::vector<std::array<uint8_t, ASCON_TAG_SIZE>>(64)
    );

    for (int k = 0; k < 3; k++) {
        for (int i = 0; i < 64; i++) {
            auto Q = P[k];
            flip_bit(Q, i);
            auto C = ascon.encrypt(key, nonce, {}, Q);
            assert(C.size() >= ASCON_TAG_SIZE);
            // copy last 16 bytes → tag
            std::copy(C.end() - ASCON_TAG_SIZE, C.end(), T[k][i].begin());
        }
    }

    // 4) Enable the persistent fault
    ascon.fault_enabled = true;
    ascon.fault_index   = 0x01;  // corrupt S-box input = 1
    ascon.fault_mask    = 0x03;  // flip its low 2 bits

    // 5) Collect faulty tags
    auto Tprime = T;  // same dimensions
    for (int k = 0; k < 3; k++) {
        for (int i = 0; i < 64; i++) {
            auto Q = P[k];
            flip_bit(Q, i);
            auto C = ascon.encrypt(key, nonce, {}, Q);
            assert(C.size() >= ASCON_TAG_SIZE);
            std::copy(C.end() - ASCON_TAG_SIZE, C.end(), Tprime[k][i].begin());
        }
    }

    // 6) Strong-adversary key recovery (Algorithm 1)
    std::array<int,   64>   j0, j1;
    std::array<uint8_t,64> K0_bits{}, K1_bits{};

    for (int bit = 0; bit < 64; bit++) {
        bool found0 = false, found1 = false;

        for (int i = 0; i < 64; i++) {
            // extract the bit 'bit' of tag T[0][i]
            uint8_t b0  = (T[0][i][bit/8]  >> (7 - (bit%8))) & 1;
            uint8_t b0p = (Tprime[0][i][bit/8] >> (7 - (bit%8))) & 1;
            if (!found0 && b0 != b0p) {
                j0[bit]     = i;
                K0_bits[bit] = b0;   // strong adversary knows the S-box differential
                found0 = true;
            }

            uint8_t b1  = (T[1][i][bit/8]  >> (7 - (bit%8))) & 1;
            uint8_t b1p = (Tprime[1][i][bit/8] >> (7 - (bit%8))) & 1;
            if (!found1 && b1 != b1p) {
                j1[bit]     = i;
                K1_bits[bit] = b1;
                found1 = true;
            }

            if (found0 && found1) break;
        }
        assert(found0 && found1);
    }

    // 7) Reconstruct 128-bit key from bit arrays
    std::vector<uint8_t> Krec(16, 0);
    for (int b = 0; b < 64; b++) {
        if (K0_bits[b]) {
            int byte = b/8, off = 7 - (b%8);
            Krec[byte] |= uint8_t(1u << off);
        }
        if (K1_bits[b]) {
            int byte = 8 + (b/8), off = 7 - (b%8);
            Krec[byte] |= uint8_t(1u << off);
        }
    }

    // 8) Print comparison
    auto print_hex = [&](const std::vector<uint8_t>& v) {
        std::cout << std::hex << std::setfill('0');
        for (auto x : v) {
            std::cout << std::setw(2) << int(x);
        }
        std::cout << std::dec;
    };

    std::cout << "=== CP-PFA Results ===\n";
    std::cout << "True key : ";  print_hex(key);   std::cout << "\n";
    std::cout << "Recov key: ";  print_hex(Krec);  std::cout << "\n";
    std::cout << (key == Krec ? "SUCCESS\n" : "FAIL\n");

    return 0;
}