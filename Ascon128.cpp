#include "Ascon128.hpp"
#include <stdexcept>
#include <algorithm>
#include <cstring>

// portable big-endian 64-bit load/store
static inline uint64_t load64_be(const uint8_t b[8])
{
    uint64_t x = 0;
    for (int i = 0; i < 8; i++)
        x = (x << 8) | b[i];
    return x;
}
static inline void store64_be(uint8_t out[8], uint64_t x)
{
    for (int i = 7; i >= 0; i--)
    {
        out[i] = uint8_t(x & 0xFF);
        x >>= 8;
    }
}

// rotate‐right and diffusion macro
#define ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTATE_WORDS                                       \
    {                                                      \
        state[0] ^= ROR(state[0], 19) ^ ROR(state[0], 28); \
        state[1] ^= ROR(state[1], 61) ^ ROR(state[1], 39); \
        state[2] ^= ROR(state[2], 1) ^ ROR(state[2], 6);   \
        state[3] ^= ROR(state[3], 10) ^ ROR(state[3], 17); \
        state[4] ^= ROR(state[4], 7) ^ ROR(state[4], 41);  \
    }

// round constants for the last 12 rounds
static const uint64_t RC[12] = {
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5,
    0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B};

// 5→5 S-box (Table 2)
static const uint8_t Sbox[32] = {
    0x04, 0x0B, 0x1F, 0x14, 0x1A, 0x15, 0x09, 0x02,
    0x16, 0x05, 0x08, 0x12, 0x1D, 0x03, 0x06, 0x1C,
    0x1E, 0x13, 0x07, 0x0E, 0x00, 0x0D, 0x11, 0x18,
    0x10, 0x0C, 0x01, 0x19, 0x17, 0x0A, 0x0F, 0x17};

// permutation: run rounds [12-nr .. 11]
void Ascon128::permutation(int nr)
{
    for (int r = 12 - nr; r < 12; r++)
    {
        // 1) add constant to x2
        state[2] ^= RC[r];

        // 2) substitution via 64-lane table
        {
            uint64_t x0 = state[0], x1 = state[1], x2 = state[2],
                     x3 = state[3], x4 = state[4];
            uint64_t y0 = 0, y1 = 0, y2 = 0, y3 = 0, y4 = 0;

            for (int lane = 0; lane < 64; lane++)
            {
                uint8_t in = uint8_t(
                    ((x0 >> lane) & 1ULL) << 4 | ((x1 >> lane) & 1ULL) << 3 | ((x2 >> lane) & 1ULL) << 2 | ((x3 >> lane) & 1ULL) << 1 | ((x4 >> lane) & 1ULL));
                uint8_t out = Sbox[in];

                // if this is the finalization perm and the chosen lane
                if (in_finalization && r == 11 && fault_enabled && lane == fault_lane)
                {
                    out ^= fault_mask;
                }

                y0 |= (uint64_t)((out >> 4) & 1) << lane;
                y1 |= (uint64_t)((out >> 3) & 1) << lane;
                y2 |= (uint64_t)((out >> 2) & 1) << lane;
                y3 |= (uint64_t)((out >> 1) & 1) << lane;
                y4 |= (uint64_t)((out) & 1) << lane;
            }

            state[0] = y0;
            state[1] = y1;
            state[2] = y2;
            state[3] = y3;
            state[4] = y4;
        }

        // 3) linear diffusion
        ROTATE_WORDS;
    }
}

// absorb-only for associated data (always p_b after every chunk)
void Ascon128::absorb(const std::vector<uint8_t> &data)
{
    size_t i = 0, n = data.size();
    while (i < n)
    {
        size_t chunk = std::min(n - i, ASCON_RATE);
        for (size_t j = 0; j < chunk; j++)
            state[0] ^= uint64_t(data[i + j]) << (56 - 8 * j);
        if (chunk < ASCON_RATE)
            state[0] ^= 0x80ULL >> (8 * chunk);
        permutation(6);
        i += chunk;
    }
}

// absorb+encrypt for plaintext
void Ascon128::absorb_and_encrypt(
    std::vector<uint8_t> &C,
    const std::vector<uint8_t> &P)
{
    size_t i = 0, n = P.size();
    while (i < n)
    {
        size_t chunk = std::min(n - i, ASCON_RATE);
        for (size_t j = 0; j < chunk; j++)
        {
            state[0] ^= uint64_t(P[i + j]) << (56 - 8 * j);
            C.push_back(uint8_t(state[0] >> (56 - 8 * j)));
        }
        if (chunk == ASCON_RATE)
        {
            permutation(6);
        }
        else
        {
            state[0] ^= 0x80ULL >> (8 * chunk);
        }
        i += chunk;
    }
}

// absorb+decrypt for ciphertext
void Ascon128::absorb_and_decrypt(
    std::vector<uint8_t> &P,
    const std::vector<uint8_t> &C)
{
    size_t i = 0, n = C.size();
    while (i < n)
    {
        size_t chunk = std::min(n - i, ASCON_RATE);
        for (size_t j = 0; j < chunk; j++)
        {
            uint8_t s = uint8_t(state[0] >> (56 - 8 * j));
            uint8_t c = C[i + j];
            P.push_back(s ^ c);
            state[0] &= ~(0xFFULL << (56 - 8 * j));
            state[0] |= uint64_t(c) << (56 - 8 * j);
        }
        if (chunk == ASCON_RATE)
        {
            permutation(6);
        }
        else
        {
            state[0] ^= 0x80ULL >> (8 * chunk);
        }
        i += chunk;
    }
}

// AEAD Encrypt
std::vector<uint8_t> Ascon128::encrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &ad,
    const std::vector<uint8_t> &pt)
{
    if (key.size() != ASCON_KEY_SIZE || nonce.size() != ASCON_NONCE_SIZE)
        throw std::invalid_argument("encrypt: bad key/nonce");

    // 1) initialize
    const uint8_t iv[8] = {0x80, 0x40, 0x0C, 0x06, 0, 0, 0, 0};
    state[0] = load64_be(iv);
    state[1] = load64_be(&key[0]);
    state[2] = load64_be(&key[8]);
    state[3] = load64_be(&nonce[0]);
    state[4] = load64_be(&nonce[8]);
    permutation(12);

    // xor key
    state[3] ^= state[1];
    state[4] ^= state[2];

    // 2) associated data
    if (!ad.empty())
        absorb(ad);
    state[4] ^= 1; // domain separation

    // 3) encrypt
    std::vector<uint8_t> C;
    C.reserve(pt.size() + ASCON_TAG_SIZE);
    absorb_and_encrypt(C, pt);

    // 4) finalization
    in_finalization = true;
    permutation(12);
    in_finalization = false;
    state[3] ^= state[1];
    state[4] ^= state[2];

    // 5) append tag = x3||x4
    uint8_t T[16];
    store64_be(T + 0, state[3]);
    store64_be(T + 8, state[4]);
    C.insert(C.end(), T, T + 16);

    return C;
}

// AEAD Decrypt + verify
std::vector<uint8_t> Ascon128::decrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &ad,
    const std::vector<uint8_t> &ct)
{
    if (key.size() != ASCON_KEY_SIZE || nonce.size() != ASCON_NONCE_SIZE || ct.size() < ASCON_TAG_SIZE)
        throw std::invalid_argument("decrypt: bad sizes");

    // split C||T
    size_t clen = ct.size() - ASCON_TAG_SIZE;
    std::vector<uint8_t> C(ct.begin(), ct.begin() + clen);
    const uint8_t *Trecv = &ct[clen];

    // 1) init
    const uint8_t iv[8] = {0x80, 0x40, 0x0C, 0x06, 0, 0, 0, 0};
    state[0] = load64_be(iv);
    state[1] = load64_be(&key[0]);
    state[2] = load64_be(&key[8]);
    state[3] = load64_be(&nonce[0]);
    state[4] = load64_be(&nonce[8]);
    permutation(12);
    state[3] ^= state[1];
    state[4] ^= state[2];

    // 2) associated data
    if (!ad.empty())
        absorb(ad);
    state[4] ^= 1;

    // 3) decrypt
    std::vector<uint8_t> P;
    P.reserve(C.size());
    absorb_and_decrypt(P, C);

    // 4) finalization + tag check
    in_finalization = true;
    permutation(12);
    in_finalization = false;
    state[3] ^= state[1];
    state[4] ^= state[2];

    uint8_t Tcalc[16];
    store64_be(Tcalc + 0, state[3]);
    store64_be(Tcalc + 8, state[4]);

    // constant-time compare
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= Tcalc[i] ^ Trecv[i];
    if (diff)
        return {}; // tag mismatch

    return P;
}