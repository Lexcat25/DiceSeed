// Pure, Arduino-independent core: dice rolls -> BIP39 entropy -> mnemonic.
//
// This file has no TFT/GPIO/Serial dependency -- only mbedtls and stdint/
// string.h, both of which exist identically on-device (ESP32 Arduino core)
// and on a desktop toolchain. That's deliberate: tests/test_core.cpp
// #includes this SAME file and links it against a desktop mbedtls, so the
// test exercises the exact bytes that run on hardware rather than a
// reimplementation that could silently diverge from the firmware.
//
// Split into two stages on purpose, not one:
//   diceToEntropy() / diceToEntropySeedSignerCompat()
//                        dice rolls -> raw entropy bytes (no BIP39 involved)
//   entropyToMnemonic()  entropy bytes -> checksum -> word list (pure BIP39)
// entropyToMnemonic() alone can be checked against the official trezor/
// python-mnemonic test vectors (see tests/test_core.cpp) independent of
// whether the dice math is correct -- so a bug in one half can't hide
// behind a passing test of the other half. Two dice->entropy functions,
// selected at compile time by DiceSeed.ino via build_mode.h, share this one
// entropyToMnemonic() -- see each function's own comment for why it exists.
#pragma once

#include <stdint.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"
#include "bip39_wordlist.h"

namespace diceseed {

// buf is big-endian, len bytes. buf = buf*6 + digit.
inline void bignumMulAdd6(uint8_t* buf, int len, uint8_t digit) {
  uint16_t carry = digit;
  for (int i = len - 1; i >= 0; i--) {
    uint16_t v = (uint16_t)buf[i] * 6 + carry;
    buf[i] = v & 0xFF;
    carry = v >> 8;
  }
}

// Read `count` bits (<=16) starting at bit offset `bitOffset` (MSB-first).
inline uint16_t readBits(const uint8_t* buf, int bitOffset, int count) {
  uint32_t value = 0;
  for (int i = 0; i < count; i++) {
    int bitPos = bitOffset + i;
    int byteIdx = bitPos / 8;
    int bitIdx = 7 - (bitPos % 8);
    uint8_t bit = (buf[byteIdx] >> bitIdx) & 1;
    value = (value << 1) | bit;
  }
  return (uint16_t)value;
}

// rolls[i] in 1..6, rollsNeeded entries (50 for 12-word, 99 for 24-word).
// Writes entBytes bytes to `entropy` (16 for 12-word, 32 for 24-word).
//
// entropy = N mod 2^(entBytes*8), where N is the base-6 number formed by
// the rolls. For the 24-word/99-roll case, 6^99 - 1 < 2^256, so N fits
// entirely within the 256-bit result -- no truncation, no bias.
// For the 12-word/50-roll case, 6^50 needs up to 130 bits, so this modular
// reduction introduces a small, well-known bias (some 128-bit residues are
// ~1.5x as likely as others -- effective min-entropy is ~127.4 bits, not
// 128). This is the same tradeoff the reference dice-to-BIP39 method
// (iancoleman.io) makes; a bias-free fix would require rejection sampling
// (occasionally asking for one more roll), which was deliberately not
// added -- it would break the "redo this by hand with pencil and paper"
// auditability that's the whole point of a dice-based generator.
inline void diceToEntropy(const uint8_t* rolls, int rollsNeeded, int entBytes,
                           uint8_t* entropy) {
  static const int BIGBYTES = 40; // 320 bits, safely fits 6^99 (~256 bits)
  uint8_t big[BIGBYTES];
  memset(big, 0, sizeof(big));

  for (int i = 0; i < rollsNeeded; i++) {
    uint8_t digit = rolls[i] - 1; // 0..5
    bignumMulAdd6(big, BIGBYTES, digit);
  }

  memcpy(entropy, big + (BIGBYTES - entBytes), entBytes);
  mbedtls_platform_zeroize(big, sizeof(big));
}

// Alternate dice->entropy method, matching SeedSigner's own dice-roll seed
// feature byte-for-byte: hash the literal roll digits (ASCII '1'..'6', in
// roll order, no separator, no remapping) with SHA-256, and take the low
// `entBytes` bytes of the 32-byte digest as entropy. Verified against
// SeedSigner's own published test vectors (docs/dice_verification.md)
// before this was trusted -- see tests/vectors.h SEEDSIGNER_VECTORS.
//
// Why this exists alongside diceToEntropy(): the same physical dice rolls
// entered on DiceSeed (built with DICESEED_COMPAT_BUILD=1, see
// build_mode.h) and on an actual SeedSigner unit now produce the identical
// mnemonic -- independent-hardware agreement, not just an independent
// re-implementation of the math. The tradeoff: unlike diceToEntropy()'s
// base-6 positional number, a SHA-256 hash cannot be recomputed by hand
// with pencil and paper. This is not a new trust dependency, though --
// entropyToMnemonic() below already requires SHA-256 for the BIP39
// checksum step in EVERY DiceSeed build, classic included, so this reuses
// the exact same already-trusted mbedtls call rather than adding one.
inline void diceToEntropySeedSignerCompat(const uint8_t* rolls, int rollsNeeded,
                                           int entBytes, uint8_t* entropy) {
  char digits[99 + 1]; // rollsNeeded is 50 or 99; +1 for the NUL terminator
  for (int i = 0; i < rollsNeeded; i++) {
    digits[i] = '0' + rolls[i]; // rolls[i] is 1..6 -> ASCII '1'..'6'
  }
  digits[rollsNeeded] = '\0';

  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0); // 0 = SHA-256 (not SHA-224)
  mbedtls_sha256_update(&ctx, (const uint8_t*)digits, rollsNeeded);
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  memcpy(entropy, hash, entBytes); // first entBytes bytes of the digest

  mbedtls_platform_zeroize(digits, sizeof(digits));
  mbedtls_platform_zeroize(hash, sizeof(hash));
}

// Standard BIP39: entropy (entBytes bytes, 16 or 32) -> SHA-256 checksum
// (top csBits bits of the hash, 4 or 8) -> wordCount 11-bit word indices
// (12 or 24). mnemonicWords[w] must have room for >=9 chars (the longest
// BIP39 English word is 8 chars); callers pass char[][16] for headroom.
inline void entropyToMnemonic(const uint8_t* entropy, int entBytes,
                               int wordCount, int csBits,
                               char mnemonicWords[][16]) {
  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0); // 0 = SHA-256 (not SHA-224)
  mbedtls_sha256_update(&ctx, entropy, entBytes);
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);

  // Pack entropy bits followed by the top csBits bits of hash[0]. csBits is
  // never more than 8 (one byte), so hash[0] alone is always enough.
  uint8_t combined[33];
  mbedtls_platform_zeroize(combined, sizeof(combined));
  memcpy(combined, entropy, entBytes);
  combined[entBytes] = hash[0]; // only the top csBits bits of this are used

  for (int w = 0; w < wordCount; w++) {
    uint16_t idx = readBits(combined, w * 11, 11);
    strncpy(mnemonicWords[w], BIP39_WORDS[idx], 15);
    mnemonicWords[w][15] = '\0';
  }

  mbedtls_platform_zeroize(hash, sizeof(hash));
  mbedtls_platform_zeroize(combined, sizeof(combined));
}

// Convenience wrapper used by the sketch: dice rolls straight to mnemonic,
// with the intermediate entropy scrubbed before returning.
inline void computeMnemonic(const uint8_t* rolls, int rollsNeeded,
                             int wordCount, int entBytes, int csBits,
                             char mnemonicWords[][16]) {
  uint8_t entropy[32];
  diceToEntropy(rolls, rollsNeeded, entBytes, entropy);
  entropyToMnemonic(entropy, entBytes, wordCount, csBits, mnemonicWords);
  mbedtls_platform_zeroize(entropy, sizeof(entropy));
}

// Same convenience wrapper, using the SeedSigner-compatible entropy method
// instead. The sketch itself does NOT call either wrapper -- it needs the
// intermediate entropy to survive for the on-screen "show raw entropy"
// display (see DiceSeed.ino), so it calls diceToEntropy[SeedSignerCompat]()
// and entropyToMnemonic() directly as two steps. These wrappers exist for
// tests, to exercise the same call shape a caller who does NOT need the
// entropy afterward would use.
inline void computeMnemonicSeedSignerCompat(const uint8_t* rolls, int rollsNeeded,
                                             int wordCount, int entBytes, int csBits,
                                             char mnemonicWords[][16]) {
  uint8_t entropy[32];
  diceToEntropySeedSignerCompat(rolls, rollsNeeded, entBytes, entropy);
  entropyToMnemonic(entropy, entBytes, wordCount, csBits, mnemonicWords);
  mbedtls_platform_zeroize(entropy, sizeof(entropy));
}

} // namespace diceseed
