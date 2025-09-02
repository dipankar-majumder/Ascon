#include "Ascon128.hpp"
#include <stdexcept>
#include <cstring>

//------------------------------------------------------------------------------
// — Helpers for big-endian 64-bit load/store (portable, no alignment tricks) —
//------------------------------------------------------------------------------

static inline uint64_t load64_be(const uint8_t b[8])
{
    uint64_t x = 0;
    for (int i = 0; i < 8; i++)
    {
        x = (x << 8) | b[i];
    }
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

//------------------------------------------------------------------------------
// — Rotate‐Xor diffusion macro (unchanged) —
//------------------------------------------------------------------------------

#define ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTATE_WORDS                                       \
    {                                                      \
        state[0] ^= ROR(state[0], 19) ^ ROR(state[0], 28); \
        state[1] ^= ROR(state[1], 61) ^ ROR(state[1], 39); \
        state[2] ^= ROR(state[2], 1) ^ ROR(state[2], 6);   \
        state[3] ^= ROR(state[3], 10) ^ ROR(state[3], 17); \
        state[4] ^= ROR(state[4], 7) ^ ROR(state[4], 41);  \
    }

//------------------------------------------------------------------------------
// — Round constants (unchanged) —
//------------------------------------------------------------------------------

static const uint64_t RC[12] = {
    0x00000000000000F0ULL, 0x00000000000000E1ULL, 0x00000000000000D2ULL,
    0x00000000000000C3ULL, 0x00000000000000B4ULL, 0x00000000000000A5ULL,
    0x0000000000000096ULL, 0x0000000000000087ULL, 0x0000000000000078ULL,
    0x0000000000000069ULL, 0x000000000000005AULL, 0x000000000000004BULL};

//------------------------------------------------------------------------------
// — permutation(nr): runs the last nr rounds of a 12-round ASCON perm —
//------------------------------------------------------------------------------

void Ascon128::permutation(int nr)
{
    // we assume nr is either 6 or 12
    for (int round = 12 - nr; round < 12; round++)
    {
        // 1) Add constant
        state[2] ^= RC[round];

        // 2) Substitution layer (bit‐sliced 5-word S-box)
        state[0] ^= state[4];
        state[4] ^= state[3];
        state[2] ^= state[1];
        uint64_t t0 = state[0], t1 = state[1], t2 = state[2], t3 = state[3], t4 = state[4];
        state[0] = t0 ^ (~t1 & t2);
        state[1] = t1 ^ (~t2 & t3);
        state[2] = t2 ^ (~t3 & t4);
        state[3] = t3 ^ (~t4 & t0);
        state[4] = t4 ^ (~t0 & t1);
        state[1] ^= state[0];
        state[0] ^= state[4];
        state[3] ^= state[2];
        state[2] = ~state[2];

        // 3) Linear diffusion
        ROTATE_WORDS;
    }
}

//------------------------------------------------------------------------------
// — absorb() for associated data —
//    XORs in each ASCON_RATE-byte block, always calls p_b even on final partial
//------------------------------------------------------------------------------

void Ascon128::absorb(const std::vector<uint8_t> &data)
{
    size_t i = 0;
    while (i < data.size())
    {
        size_t chunk = std::min(data.size() - i, ASCON_RATE);
        // XOR chunk into state[0]
        for (size_t j = 0; j < chunk; j++)
        {
            state[0] ^= uint64_t(data[i + j]) << (56 - 8 * j);
        }

        if (chunk < ASCON_RATE)
        {
            // padding bit in the first unused byte position
            state[0] ^= 0x80ULL >> (8 * chunk);
        }
        // ALWAYS do the 6-round perm in the AAD phase
        permutation(6);
        i += chunk;
    }
}

//------------------------------------------------------------------------------
// — absorb_and_encrypt() for plaintext —
//   XOR in up to ASCON_RATE, output S^P, perm6 only on *full* blocks…
//------------------------------------------------------------------------------

void Ascon128::absorb_and_encrypt(std::vector<uint8_t> &C,
                                  const std::vector<uint8_t> &P)
{
    size_t i = 0;
    while (i < P.size())
    {
        size_t chunk = std::min(P.size() - i, ASCON_RATE);
        // XOR plaintext, produce ciphertext bytes
        for (size_t j = 0; j < chunk; j++)
        {
            state[0] ^= uint64_t(P[i + j]) << (56 - 8 * j);
            uint8_t c = uint8_t(state[0] >> (56 - 8 * j));
            C.push_back(c);
        }

        if (chunk == ASCON_RATE)
        {
            permutation(6);
        }
        else
        {
            // final partial: pad and STOP (no perm)
            state[0] ^= 0x80ULL >> (8 * chunk);
        }
        i += chunk;
    }
}

//------------------------------------------------------------------------------
// — absorb_and_decrypt() for ciphertext —
//   invert the above: recover P = S_old ^ C, then XOR C into state
//------------------------------------------------------------------------------

void Ascon128::absorb_and_decrypt(std::vector<uint8_t> &P,
                                  const std::vector<uint8_t> &C)
{
    size_t i = 0;
    while (i < C.size())
    {
        size_t chunk = std::min(C.size() - i, ASCON_RATE);
        for (size_t j = 0; j < chunk; j++)
        {
            uint8_t s_old = uint8_t(state[0] >> (56 - 8 * j));
            uint8_t c = C[i + j];
            P.push_back(s_old ^ c);

            // replace state byte with c
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

//------------------------------------------------------------------------------
// — encrypt() —
//------------------------------------------------------------------------------

std::vector<uint8_t> Ascon128::encrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &associated_data,
    const std::vector<uint8_t> &plaintext)
{
    if (key.size() != ASCON_KEY_SIZE ||
        nonce.size() != ASCON_NONCE_SIZE)
    {
        throw std::invalid_argument("Ascon128::encrypt: bad key/nonce size");
    }

    // 1) Initialization
    const uint8_t iv_bytes[8] = {
        0x80, 0x40, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00};
    state[0] = load64_be(iv_bytes);
    state[1] = load64_be(&key[0]);
    state[2] = load64_be(&key[8]);
    state[3] = load64_be(&nonce[0]);
    state[4] = load64_be(&nonce[8]);

    permutation(12);

    // XOR K into x3,x4
    state[3] ^= state[1];
    state[4] ^= state[2];

    // 2) Associated Data
    if (!associated_data.empty())
    {
        absorb(associated_data);
    }
    // domain-sep: toggle LSB of x4
    state[4] ^= 1;

    // 3) Encrypt plaintext
    std::vector<uint8_t> C;
    C.reserve(plaintext.size() + ASCON_TAG_SIZE);
    absorb_and_encrypt(C, plaintext);

    // 4) Finalization
    permutation(12);
    // XOR K into x3,x4
    state[3] ^= state[1];
    state[4] ^= state[2];

    // 5) Produce tag from x3||x4 (big-endian)
    uint8_t T[16];
    store64_be(T + 0, state[3]);
    store64_be(T + 8, state[4]);
    C.insert(C.end(), T, T + 16);

    return C;
}

//------------------------------------------------------------------------------
// — decrypt() —
//------------------------------------------------------------------------------

std::vector<uint8_t> Ascon128::decrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &associated_data,
    const std::vector<uint8_t> &ciphertext)
{
    if (key.size() != ASCON_KEY_SIZE ||
        nonce.size() != ASCON_NONCE_SIZE ||
        ciphertext.size() < ASCON_TAG_SIZE)
    {
        throw std::invalid_argument("Ascon128::decrypt: bad sizes");
    }

    // split off tag
    size_t clen = ciphertext.size() - ASCON_TAG_SIZE;
    std::vector<uint8_t> C(ciphertext.begin(), ciphertext.begin() + clen);
    const uint8_t *Trecv = &ciphertext[clen];

    // 1) Initialization (same as encrypt)
    const uint8_t iv_bytes[8] = {
        0x80, 0x40, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00};
    state[0] = load64_be(iv_bytes);
    state[1] = load64_be(&key[0]);
    state[2] = load64_be(&key[8]);
    state[3] = load64_be(&nonce[0]);
    state[4] = load64_be(&nonce[8]);

    permutation(12);
    state[3] ^= state[1];
    state[4] ^= state[2];

    // 2) Associated Data
    if (!associated_data.empty())
    {
        absorb(associated_data);
    }
    state[4] ^= 1; // domain-sep

    // 3) Decrypt
    std::vector<uint8_t> P;
    P.reserve(C.size());
    absorb_and_decrypt(P, C);

    // 4) Finalization & tag check
    permutation(12);
    state[3] ^= state[1];
    state[4] ^= state[2];

    uint8_t Tcalc[16];
    store64_be(Tcalc + 0, state[3]);
    store64_be(Tcalc + 8, state[4]);

    // constant-time compare
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++)
    {
        diff |= Tcalc[i] ^ Trecv[i];
    }
    if (diff)
    {
        // tag failure
        return {};
    }

    return P;
}