#ifndef ASCON128_H
#define ASCON128_H

#include <cstdint>
#include <vector>

// ASCON-128 parameters
static constexpr size_t ASCON_KEY_SIZE = 16;   // 128 bits
static constexpr size_t ASCON_NONCE_SIZE = 16; // 128 bits
static constexpr size_t ASCON_TAG_SIZE = 16;   // 128 bits
static constexpr size_t ASCON_RATE = 8;        // 64 bits

class Ascon128
{
public:
    // Fault‐injection controls (strong adversary model)
    bool fault_enabled = false; // turn ON/OFF the persistent fault
    uint8_t fault_index = 0x01; // which 5-bit S-box input we corrupt
    uint8_t fault_mask = 0x03;  // XOR this into the S-box output

    // Constructor / destructor auto-defined

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
    // 320-bit state as five 64-bit words
    uint64_t state[5];

    // Core permutation: runs the *last* nr rounds of the 12-round ASCON perm
    void permutation(int nr);

    // Absorb-only (for associated data), always calls p_b on *every* block
    void absorb(const std::vector<uint8_t> &data);

    // Absorb-and-encrypt (for plaintext)
    void absorb_and_encrypt(
        std::vector<uint8_t> &ciphertext,
        const std::vector<uint8_t> &plaintext);

    // Absorb-and-decrypt (for ciphertext)
    void absorb_and_decrypt(
        std::vector<uint8_t> &plaintext,
        const std::vector<uint8_t> &ciphertext);
};

#endif // ASCON128_H