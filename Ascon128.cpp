#include "Ascon128.hpp"
#include <stdexcept>
#include <cstring>
#include <iostream> // For debugging, can be removed later

// Helper macros for bitwise operations
#define ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTATE_WORDS { \
    state[0] ^= ROR(state[0], 19) ^ ROR(state[0], 28); \
    state[1] ^= ROR(state[1], 61) ^ ROR(state[1], 39); \
    state[2] ^= ROR(state[2], 1) ^ ROR(state[2], 6); \
    state[3] ^= ROR(state[3], 10) ^ ROR(state[3], 17); \
    state[4] ^= ROR(state[4], 7) ^ ROR(state[4], 41); \
}

// ASCON round constants
const uint64_t RC[] = {
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
    0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F
};

void Ascon128::permutation(int nr) {
    for (int i = 12 - nr; i < 12; i++) {
        // Step 1: Add round constant
        state[2] ^= RC[i];

        // Step 2: Substitution layer (S-box)
        state[0] ^= state[4]; state[4] ^= state[3]; state[2] ^= state[1];
        uint64_t t0 = state[0], t1 = state[1], t2 = state[2], t3 = state[3], t4 = state[4];
        state[0] = t0 ^ (~t1 & t2);
        state[1] = t1 ^ (~t2 & t3);
        state[2] = t2 ^ (~t3 & t4);
        state[3] = t3 ^ (~t4 & t0);
        state[4] = t4 ^ (~t0 & t1);
        state[1] ^= state[0]; state[0] ^= state[4]; state[3] ^= state[2];
        state[2] = ~state[2];

        // Step 3: Linear diffusion layer
        ROTATE_WORDS;
    }
}

void Ascon128::absorb(const std::vector<uint8_t>& data) {
    size_t i = 0;
    while (i < data.size()) {
        size_t len = std::min(ASCON_RATE, data.size() - i);
        for (size_t j = 0; j < len; j++) {
            state[j / 8] ^= (uint64_t)data[i + j] << (56 - (j % 8) * 8);
        }
        if (len == ASCON_RATE) {
            permutation(6);
        } else {
            state[len / 8] ^= 0x80ULL << (56 - (len % 8) * 8);
        }
        i += len;
    }
}

void Ascon128::absorb_and_encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext) {
    size_t i = 0;
    while (i < plaintext.size()) {
        size_t len = std::min(ASCON_RATE, plaintext.size() - i);
        for (size_t j = 0; j < len; j++) {
            state[j / 8] ^= (uint64_t)plaintext[i + j] << (56 - (j % 8) * 8);
            uint8_t c_byte = (state[j / 8] >> (56 - (j % 8) * 8));
            ciphertext.push_back(c_byte);
        }
        if (len == ASCON_RATE) {
            permutation(6);
        } else {
            state[len / 8] ^= 0x80ULL << (56 - (len % 8) * 8);
        }
        i += len;
    }
}

void Ascon128::absorb_and_decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext) {
    size_t i = 0;
    while (i < ciphertext.size()) {
        size_t len = std::min(ASCON_RATE, ciphertext.size() - i);
        for (size_t j = 0; j < len; j++) {
            uint8_t s_byte = (state[j / 8] >> (56 - (j % 8) * 8));
            uint8_t c_byte = ciphertext[i + j];
            plaintext.push_back(s_byte ^ c_byte);
            
            state[j / 8] &= ~(0xFFULL << (56 - (j % 8) * 8));
            state[j / 8] |= (uint64_t)c_byte << (56 - (j % 8) * 8);
        }
        if (len == ASCON_RATE) {
            permutation(6);
        } else {
            state[len / 8] ^= 0x80ULL << (56 - (len % 8) * 8);
        }
        i += len;
    }
}

std::vector<uint8_t> Ascon128::encrypt(
    const std::vector<uint8_t>& key, 
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& associated_data, 
    const std::vector<uint8_t>& plaintext
) {
    if (key.size() != ASCON_KEY_SIZE || nonce.size() != ASCON_NONCE_SIZE) {
        throw std::invalid_argument("Invalid key or nonce size.");
    }

    // Phase 1: Initialization
    state[0] = 0x80400c0600000000ULL;
    memcpy(&state[1], key.data(), ASCON_KEY_SIZE);
    memcpy(&state[3], nonce.data(), ASCON_NONCE_SIZE);
    permutation(12);
    state[3] ^= *reinterpret_cast<const uint64_t*>(key.data());
    state[4] ^= *reinterpret_cast<const uint64_t*>(key.data() + 8);

    // Phase 2: Associated data processing
    if (!associated_data.empty()) {
        absorb(associated_data);
    }
    state[4] ^= 1;

    // Phase 3: Plaintext processing
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(plaintext.size() + ASCON_TAG_SIZE);
    absorb_and_encrypt(ciphertext, plaintext);

    // Phase 4: Finalization (generate tag)
    permutation(12);
    state[3] ^= *reinterpret_cast<const uint64_t*>(key.data());
    state[4] ^= *reinterpret_cast<const uint64_t*>(key.data() + 8);
    
    // Append tag to ciphertext
    for (size_t i = 0; i < ASCON_TAG_SIZE; ++i) {
        uint8_t tag_byte = (state[i / 8] >> (56 - (i % 8) * 8));
        ciphertext.push_back(tag_byte);
    }

    return ciphertext;
}

std::vector<uint8_t> Ascon128::decrypt(
    const std::vector<uint8_t>& key, 
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& associated_data, 
    const std::vector<uint8_t>& ciphertext
) {
    if (key.size() != ASCON_KEY_SIZE || nonce.size() != ASCON_NONCE_SIZE || ciphertext.size() < ASCON_TAG_SIZE) {
        throw std::invalid_argument("Invalid key, nonce, or ciphertext size.");
    }
    
    // Separate ciphertext and tag
    std::vector<uint8_t> c_only(ciphertext.begin(), ciphertext.end() - ASCON_TAG_SIZE);
    std::vector<uint8_t> received_tag(ciphertext.end() - ASCON_TAG_SIZE, ciphertext.end());
    
    // Phase 1: Initialization
    state[0] = 0x80400c0600000000ULL;
    memcpy(&state[1], key.data(), ASCON_KEY_SIZE);
    memcpy(&state[3], nonce.data(), ASCON_NONCE_SIZE);
    permutation(12);
    state[3] ^= *reinterpret_cast<const uint64_t*>(key.data());
    state[4] ^= *reinterpret_cast<const uint64_t*>(key.data() + 8);

    // Phase 2: Associated data processing
    if (!associated_data.empty()) {
        absorb(associated_data);
    }
    state[4] ^= 1;

    // Phase 3: Ciphertext processing
    std::vector<uint8_t> plaintext;
    plaintext.reserve(c_only.size());
    absorb_and_decrypt(plaintext, c_only);
    
    // Phase 4: Finalization (generate tag)
    permutation(12);
    state[3] ^= *reinterpret_cast<const uint64_t*>(key.data());
    state[4] ^= *reinterpret_cast<const uint64_t*>(key.data() + 8);

    // Verify tag
    for (size_t i = 0; i < ASCON_TAG_SIZE; ++i) {
        uint8_t computed_tag_byte = (state[i / 8] >> (56 - (i % 8) * 8));
        if (computed_tag_byte != received_tag[i]) {
            // Tag mismatch, return an empty vector or throw an exception
            return {};
        }
    }
    
    return plaintext;
}