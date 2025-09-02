#ifndef ASCON128_H
#define ASCON128_H

#include <cstdint>
#include <vector>
#include <string>

// ASCON-128 constants
const size_t ASCON_KEY_SIZE = 16;   // 128 bits
const size_t ASCON_NONCE_SIZE = 16; // 128 bits
const size_t ASCON_TAG_SIZE = 16;   // 128 bits
const size_t ASCON_RATE = 8;        // 64 bits (8 bytes)

class Ascon128
{
private:
    // ASCON state: 320 bits (5 x 64-bit words)
    uint64_t state[5];

    // The core ASCON permutation
    void permutation(int nr);

    // Helper functions for absorbing and squeezing data
    void absorb(const std::vector<uint8_t> &data);
    void absorb_and_encrypt(std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &plaintext);
    void absorb_and_decrypt(std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &ciphertext);

public:
    // Encryption method
    std::vector<uint8_t> encrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &associated_data,
        const std::vector<uint8_t> &plaintext);

    // Decryption method
    std::vector<uint8_t> decrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &associated_data,
        const std::vector<uint8_t> &ciphertext);
};

#endif // ASCON128_H