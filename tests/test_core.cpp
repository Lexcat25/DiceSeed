// Host-side correctness test for diceseed_core.h. Compiled and run inside a
// throwaway Docker container (see run_tests.sh) since the devbox has no C
// toolchain installed -- same reason erp/whistle build their tests in Docker.
//
// This is the ONLY thing in the repo that proves the entropy/checksum math
// is right beyond a human reading it. Run it after touching diceseed_core.h,
// bip39_wordlist.h, or tests/vectors.h.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../DiceSeed/diceseed_core.h"
#include "vectors.h"

static int failures = 0;

static void checkEq(const char* what, const char* got, const char* want) {
  if (strcmp(got, want) != 0) {
    printf("FAIL %s\n  got:  %s\n  want: %s\n", what, got, want);
    failures++;
  } else {
    printf("ok   %s\n", what);
  }
}

static void hexToBytes(const char* hex, uint8_t* out, int n) {
  for (int i = 0; i < n; i++) {
    unsigned int b;
    sscanf(hex + i * 2, "%2x", &b);
    out[i] = (uint8_t)b;
  }
}

static void joinWords(char words[][16], int wordCount, char* out) {
  out[0] = '\0';
  for (int i = 0; i < wordCount; i++) {
    if (i > 0) strcat(out, " ");
    strcat(out, words[i]);
  }
}

int main() {
  printf("=== BIP39_VECTORS (official trezor/python-mnemonic, entropy -> mnemonic) ===\n");
  for (int i = 0; i < BIP39_VECTORS_COUNT; i++) {
    const Bip39Vector& v = BIP39_VECTORS[i];
    int entBytes = v.word_count == 12 ? 16 : 32;
    uint8_t entropy[32];
    hexToBytes(v.entropy_hex, entropy, entBytes);

    char words[24][16];
    diceseed::entropyToMnemonic(entropy, entBytes, v.word_count, v.cs_bits, words);

    char joined[512];
    joinWords(words, v.word_count, joined);

    char label[64];
    snprintf(label, sizeof(label), "bip39_vector[%d] (%d-word)", i, v.word_count);
    checkEq(label, joined, v.mnemonic);
  }

  printf("\n=== DICE_VECTORS (independent Python oracle, dice rolls -> entropy + mnemonic) ===\n");
  for (int i = 0; i < DICE_VECTORS_COUNT; i++) {
    const DiceVector& v = DICE_VECTORS[i];

    uint8_t entropy[32];
    diceseed::diceToEntropy(v.rolls, v.roll_count, v.ent_bytes, entropy);

    char gotHex[65];
    for (int b = 0; b < v.ent_bytes; b++) snprintf(gotHex + b * 2, 3, "%02x", entropy[b]);

    char label1[64];
    snprintf(label1, sizeof(label1), "dice_vector[%s].entropy", v.name);
    checkEq(label1, gotHex, v.entropy_hex);

    char words[24][16];
    diceseed::entropyToMnemonic(entropy, v.ent_bytes, v.word_count, v.cs_bits, words);
    char joined[512];
    joinWords(words, v.word_count, joined);

    char label2[64];
    snprintf(label2, sizeof(label2), "dice_vector[%s].mnemonic", v.name);
    checkEq(label2, joined, v.mnemonic);

    // Also exercise the convenience wrapper the sketch actually calls, and
    // confirm it agrees with the two-step path above.
    char words2[24][16];
    diceseed::computeMnemonic(v.rolls, v.roll_count, v.word_count, v.ent_bytes, v.cs_bits, words2);
    char joined2[512];
    joinWords(words2, v.word_count, joined2);
    char label3[64];
    snprintf(label3, sizeof(label3), "dice_vector[%s].computeMnemonic_matches", v.name);
    checkEq(label3, joined2, v.mnemonic);
  }

  printf("\n=== SEEDSIGNER_VECTORS (SeedSigner's own published dice test vectors, compat mode) ===\n");
  for (int i = 0; i < SEEDSIGNER_VECTORS_COUNT; i++) {
    const DiceVector& v = SEEDSIGNER_VECTORS[i];

    uint8_t entropy[32];
    diceseed::diceToEntropySeedSignerCompat(v.rolls, v.roll_count, v.ent_bytes, entropy);

    char gotHex[65];
    for (int b = 0; b < v.ent_bytes; b++) snprintf(gotHex + b * 2, 3, "%02x", entropy[b]);

    char label1[64];
    snprintf(label1, sizeof(label1), "seedsigner_vector[%s].entropy", v.name);
    checkEq(label1, gotHex, v.entropy_hex);

    char words[24][16];
    diceseed::entropyToMnemonic(entropy, v.ent_bytes, v.word_count, v.cs_bits, words);
    char joined[512];
    joinWords(words, v.word_count, joined);

    char label2[64];
    snprintf(label2, sizeof(label2), "seedsigner_vector[%s].mnemonic", v.name);
    checkEq(label2, joined, v.mnemonic);

    // Also exercise the compat convenience wrapper and confirm it agrees.
    char words2[24][16];
    diceseed::computeMnemonicSeedSignerCompat(v.rolls, v.roll_count, v.word_count, v.ent_bytes, v.cs_bits, words2);
    char joined2[512];
    joinWords(words2, v.word_count, joined2);
    char label3[64];
    snprintf(label3, sizeof(label3), "seedsigner_vector[%s].computeMnemonic_matches", v.name);
    checkEq(label3, joined2, v.mnemonic);
  }

  printf("\n%d BIP39 vectors + %d dice vectors x3 checks + %d SeedSigner vectors x3 checks, %d failure(s)\n",
         BIP39_VECTORS_COUNT, DICE_VECTORS_COUNT, SEEDSIGNER_VECTORS_COUNT, failures);
  return failures == 0 ? 0 : 1;
}
