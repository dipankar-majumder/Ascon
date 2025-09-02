#ifndef ASCON128_H
#define ASCON128_H

#include <cstdint>
#include <vector>

static constexpr size_t ASCON_KEY_SIZE = 16;   // bytes
static constexpr size_t ASCON_NONCE_SIZE = 16; // bytes
static constexpr size_t ASCON_TAG_SIZE = 16;   // bytes
static constexpr size_t ASCON_RATE = 8;        // bytes

class Ascon128
{
public:
    // Fault‐injection controls (strong adversary = pick one bit-slice)
    bool fault_enabled = false;
    int fault_lane = 0;        // which bit‐slice [0..63] to corrupt
    uint8_t fault_mask = 0x03; // XOR into S-box output (flip low 2 bits)

    // AEAD interface
    std::vector<uint8_t> encrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &associated_data,
        const std::vector<uint8_t> &plaintext);

    std::vector<uint8_t> decrypt(
        const std::vector<uint8_t> &key,
        const std::vector<uint8_t> &nonce,
        const std::vector<uint8_t> &associated_data,
        const std::vector<uint8_t> &ciphertext);

private:
    uint64_t state[5]; // 320‐bit state (5×64)
    bool in_finalization = false;

    void permutation(int nr);
    void absorb(const std::vector<uint8_t> &data);
    void absorb_and_encrypt(
        std::vector<uint8_t> &ciphertext,
        const std::vector<uint8_t> &plaintext);
    void absorb_and_decrypt(
        std::vector<uint8_t> &plaintext,
        const std::vector<uint8_t> &ciphertext);
};

#endif // ASCON128_H