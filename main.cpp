// main.cpp
#include <iostream>
#include <vector>
#include <random>
#include <array>
#include <algorithm>
#include <iomanip>
#include <cassert>
#include "Ascon128.hpp"

// flip one bit in an 8-byte block (bit 0 = MSB of byte[0], bit 63 = LSB of byte[7])
static void flip_bit(std::vector<uint8_t> &blk, int bit)
{
  int byte = bit / 8;
  int off = 7 - (bit % 8);
  blk[byte] ^= uint8_t(1u << off);
}

// hex dump
static void print_hex(const std::vector<uint8_t> &v)
{
  std::cout << std::hex << std::setfill('0');
  for (auto b : v)
    std::cout << std::setw(2) << int(b);
  std::cout << std::dec << "\n";
}

int main()
{
  // 1) AEAD self-test
  {
    std::cout << "--- AEAD self-test ---\n";
    std::mt19937_64 rng{std::random_device{}()};
    auto rnd = [&]
    { return uint8_t(rng() & 0xFF); };

    std::vector<uint8_t> key(ASCON_KEY_SIZE), nonce(ASCON_NONCE_SIZE);
    for (auto &b : key)
      b = rnd();
    for (auto &b : nonce)
      b = rnd();

    std::string msg = "Hello, ASCON-128 AEAD!";
    std::vector<uint8_t> pt(msg.begin(), msg.end()), ad;

    Ascon128 ascon;
    auto ct = ascon.encrypt(key, nonce, ad, pt);
    auto rec = ascon.decrypt(key, nonce, ad, ct);

    std::cout << "Plaintext:  " << msg << "\n";
    std::cout << "Ciphertext: ";
    print_hex(ct);
    assert(rec == pt && "AEAD self-test failed");
    std::cout << "Decryption OK\n\n";
  }

  // 2) POC PFA for j corresponding to lane F
  std::mt19937_64 rng{std::random_device{}()};
  auto rnd = [&]
  { return uint8_t(rng() & 0xFF); };

  // random key & nonce
  std::vector<uint8_t> key(ASCON_KEY_SIZE), nonce(ASCON_NONCE_SIZE);
  for (auto &b : key)
    b = rnd();
  for (auto &b : nonce)
    b = rnd();

  // three random 8-byte base plaintexts
  std::vector<std::vector<uint8_t>> P(3, std::vector<uint8_t>(8));
  for (auto &blk : P)
    for (auto &b : blk)
      b = rnd();

  // collect fault-free tags T0[i] for k=0
  Ascon128 ascon;
  ascon.fault_enabled = false;

  std::array<std::array<uint8_t, ASCON_TAG_SIZE>, 64> T0;
  for (int i = 0; i < 64; i++)
  {
    auto Q = P[0];
    flip_bit(Q, i);
    auto C = ascon.encrypt(key, nonce, {}, Q);
    std::copy_n(C.end() - ASCON_TAG_SIZE,
                ASCON_TAG_SIZE,
                T0[i].begin());
  }

  // pick a random lane F to fault
  std::uniform_int_distribution<int> dist(0, 63);
  int F = dist(rng);
  std::cout << "--- POC PFA (bit j = 63 - F) ---\n";
  std::cout << "Injecting persistent fault at lane = " << F << "\n";

  ascon.fault_enabled = true;
  ascon.fault_lane = F;
  ascon.fault_mask = 0x03; // flip low 2 bits

  // collect faulty tags T0p[i]
  std::array<std::array<uint8_t, ASCON_TAG_SIZE>, 64> T0p;
  for (int i = 0; i < 64; i++)
  {
    auto Q = P[0];
    flip_bit(Q, i);
    auto C = ascon.encrypt(key, nonce, {}, Q);
    std::copy_n(C.end() - ASCON_TAG_SIZE,
                ASCON_TAG_SIZE,
                T0p[i].begin());
  }

  // compute the tag-bit index j = 63 - lane (for x3 half)
  int j = 63 - F;
  std::cout << "Inspecting tag-bit j=" << j << " differences:\n";

  int hit_i = -1;
  for (int i = 0; i < 64; i++)
  {
    // bit j lives in byte index (j/8), bit position (7 - j%8)
    int bidx = j / 8, boff = 7 - (j % 8);
    uint8_t bf = (T0[i][bidx] >> boff) & 1;
    uint8_t bp = (T0p[i][bidx] >> boff) & 1;
    std::cout << " i=" << std::setw(2) << i
              << "  fault-free=" << int(bf)
              << "  faulty=" << int(bp)
              << (bf != bp ? "   <-- flipped\n" : "\n");
    if (bf != bp)
      hit_i = i;
  }

  if (hit_i >= 0)
  {
    std::cout << "\nSuccess: only i=" << hit_i
              << " flipped tag-bit j=" << j
              << " for lane=" << F << "\n";
  }
  else
  {
    std::cout << "\nFailure: no flip detected on bit j=" << j << "\n";
  }

  return 0;
}