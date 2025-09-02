#include "Ascon128.hpp"
#include <stdexcept>
#include <cstring>

//------------------------------------------------------------------------------
// big-endian load/store (portable)
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
// Bitwise rotations & diffusion macro
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
// Round constants (only the last 12 rounds matter)
//------------------------------------------------------------------------------
static const uint64_t RC[12] = {
    0x00000000000000F0ULL, 0x00000000000000E1ULL,
    0x00000000000000D2ULL, 0x00000000000000C3ULL,
    0x00000000000000B4ULL, 0x00000000000000A5ULL,
    0x0000000000000096ULL, 0x0000000000000087ULL,
    0x0000000000000078ULL, 0x0000000000000069ULL,
    0x000000000000005AULL, 0x000000000000004BULL};

//------------------------------------------------------------------------------
// Core ASCON permutation: run the last `nr` rounds of the 12-round perm
//------------------------------------------------------------------------------
void Ascon128::permutation(int nr)
{
    int start = 12 - nr;
    for (int r = start; r < 12; r++)
    {
        // 1) Add constant to x2
        state[2] ^= RC[r];

        // 2) 5-word bit‐sliced S‐box
        //    a) x0 ^= x4; x4 ^= x3; x2 ^= x1
        state[0] ^= state[4];
        state[4] ^= state[3];
        state[2] ^= state[1];

        //    b) nonlinear layer
        uint64_t t0 = state[0], t1 = state[1],
                 t2 = state[2], t3 = state[3],
                 t4 = state[4];
        state[0] = t0 ^ (~t1 & t2);
        state[1] = t1 ^ (~t2 & t3);
        state[2] = t2 ^ (~t3 & t4);
        state[3] = t3 ^ (~t4 & t0);
        state[4] = t4 ^ (~t0 & t1);

        //    c) bit-permutation & inversion
        state[1] ^= state[0];
        state[0] ^= state[4];
        state[3] ^= state[2];
        state[2] = ~state[2];

        // 3) Linear diffusion
        ROTATE_WORDS

        // ——— Fault injection in the *final* round’s S-box? ———
        // Actually we want to flip the S-box output *just before* it
        // is re-written into state[?].  Because we did a bit-sliced
        // implementation above, we cannot fault‐inject here.  Instead,
        // what we do is re-execute the S-box on one word, flip its
        // low-order two bits, and then overwrite one lane of `state`.
        //
        // For our strong adversary model (exactly one S-box input index
        // is corrupted, persistently):
        if (r == 11 && fault_enabled)
        {
            // We choose word-0’s lane as an example and flip the
            // word-0 S-box input == fault_index
            // (in practice you’d bit-slice your fault across all 64 lanes,
            //  here we just demonstrate the idea on a single lane)
            {
                uint8_t in = uint8_t(state[0] & 0x1FUL); // pick 5-bit
                if (in == fault_index)
                {
                    uint8_t out = uint8_t(state[0] >> 5) & 0x1F; // pretend this was the S-box output
                    out ^= fault_mask;                           // flip its two low bits
                    // now mash it back
                    state[0] &= ~0x3FULL; // clear the old 6 bits
                    state[0] |= (uint64_t(out & 0x1F) << 5);
                }
            }
        }
    }
}

//------------------------------------------------------------------------------
// ABSORB-only (for associated data): always call p_b after each block
//------------------------------------------------------------------------------
void Ascon128::absorb(const std::vector<uint8_t> &A)
{
    size_t i = 0, n = A.size();
    while (i < n)
    {
        size_t chunk = std::min(n - i, ASCON_RATE);

        // XOR chunk into x0
        for (size_t j = 0; j < chunk; j++)
        {
            state[0] ^= uint64_t(A[i + j]) << (56 - 8 * j);
        }

        // pad if short
        if (chunk < ASCON_RATE)
        {
            state[0] ^= 0x80ULL >> (8 * chunk);
        }

        permutation(6); // ALWAYS in AAD phase
        i += chunk;
    }
}

//------------------------------------------------------------------------------
// ABSORB+ENCRYPT (for plaintext): permute only on *full* blocks
//------------------------------------------------------------------------------
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
            // XOR P into state, then output C = high-byte of state
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
            // final partial
            state[0] ^= 0x80ULL >> (8 * chunk);
        }

        i += chunk;
    }
}

//------------------------------------------------------------------------------
// ABSORB+DECRYPT (for ciphertext): invert the above
//------------------------------------------------------------------------------
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

            // overwrite state with c
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
// ENCRYPT
//------------------------------------------------------------------------------
std::vector<uint8_t> Ascon128::encrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &ad,
    const std::vector<uint8_t> &pt)
{
    if (key.size() != ASCON_KEY_SIZE ||
        nonce.size() != ASCON_NONCE_SIZE)
        throw std::invalid_argument("bad key/nonce size");

    // 1) Initialization
    const uint8_t iv[8] = {0x80, 0x40, 0x0c, 0x06, 0, 0, 0, 0};
    state[0] = load64_be(iv);
    state[1] = load64_be(&key[0]);
    state[2] = load64_be(&key[8]);
    state[3] = load64_be(&nonce[0]);
    state[4] = load64_be(&nonce[8]);
    permutation(12);

    // XOR key into x3,x4
    state[3] ^= state[1];
    state[4] ^= state[2];

    // 2) AAD
    if (!ad.empty())
        absorb(ad);
    // domain separation
    state[4] ^= 1;

    // 3) Encrypt
    std::vector<uint8_t> C;
    C.reserve(pt.size() + ASCON_TAG_SIZE);
    absorb_and_encrypt(C, pt);

    // 4) Finalization
    permutation(12);
    state[3] ^= state[1];
    state[4] ^= state[2];

    // 5) Tag = x3||x4
    uint8_t T[16];
    store64_be(T + 0, state[3]);
    store64_be(T + 8, state[4]);
    C.insert(C.end(), T, T + 16);

    return C;
}

//------------------------------------------------------------------------------
// DECRYPT
//------------------------------------------------------------------------------
std::vector<uint8_t> Ascon128::decrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonce,
    const std::vector<uint8_t> &ad,
    const std::vector<uint8_t> &ct)
{
    if (key.size() != ASCON_KEY_SIZE ||
        nonce.size() != ASCON_NONCE_SIZE ||
        ct.size() < ASCON_TAG_SIZE)
        throw std::invalid_argument("bad sizes");

    // split C||T
    size_t clen = ct.size() - ASCON_TAG_SIZE;
    std::vector<uint8_t> C(ct.begin(), ct.begin() + clen);
    const uint8_t *Trecv = &ct[clen];

    // 1) Initialization (same as encrypt)
    const uint8_t iv[8] = {0x80, 0x40, 0x0c, 0x06, 0, 0, 0, 0};
    state[0] = load64_be(iv);
    state[1] = load64_be(&key[0]);
    state[2] = load64_be(&key[8]);
    state[3] = load64_be(&nonce[0]);
    state[4] = load64_be(&nonce[8]);
    permutation(12);
    state[3] ^= state[1];
    state[4] ^= state[2];

    // 2) AAD
    if (!ad.empty())
        absorb(ad);
    state[4] ^= 1;

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
        diff |= (Tcalc[i] ^ Trecv[i]);
    if (diff)
        return {}; // tag failure

    return P;
}