// Auto-generated-style fixture data lives inline below; do not hand-edit
// the arrays without regenerating them from the same source, or the test
// stops proving what it claims to prove.
//
// Two independent sources of truth, deliberately not just one:
//
// 1) BIP39_VECTORS: the official trezor/python-mnemonic test vectors
//    (https://github.com/trezor/python-mnemonic/blob/master/vectors.json),
//    fetched verbatim -- not retyped by hand. These pin entropyToMnemonic()
//    against a third-party-published, widely-trusted source, independent of
//    this repo entirely.
//
// 2) DICE_VECTORS: dice roll sequences with expected entropy+mnemonic
//    computed by an independent Python re-implementation (hashlib.sha256,
//    no mbedtls, no C++) in the same session that wrote this file. That
//    Python oracle was itself validated against all 16 applicable BIP39_VECTORS
//    entries before being trusted to generate these -- see the commit that
//    added this file for the derivation script. These pin diceToEntropy(),
//    which the official vectors cannot reach (they start from entropy, not dice).

#pragma once

struct Bip39Vector { const char* entropy_hex; int word_count; int cs_bits; const char* mnemonic; };

static const Bip39Vector BIP39_VECTORS[] = {
  { "00000000000000000000000000000000", 12, 4, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
  { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 12, 4, "legal winner thank year wave sausage worth useful legal winner thank yellow" },
  { "80808080808080808080808080808080", 12, 4, "letter advice cage absurd amount doctor acoustic avoid letter advice cage above" },
  { "ffffffffffffffffffffffffffffffff", 12, 4, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong" },
  { "0000000000000000000000000000000000000000000000000000000000000000", 24, 8, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" },
  { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 24, 8, "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" },
  { "8080808080808080808080808080808080808080808080808080808080808080", 24, 8, "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless" },
  { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 24, 8, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote" },
  { "9e885d952ad362caeb4efe34a8e91bd2", 12, 4, "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic" },
  { "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", 24, 8, "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length" },
  { "c0ba5a8e914111210f2bd131f3d5e08d", 12, 4, "scheme spot photo card baby mountain device kick cradle pact join borrow" },
  { "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863", 24, 8, "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside" },
  { "23db8160a31d3e0dca3688ed941adbf3", 12, 4, "cat swing flag economy stadium alone churn speed unique patch report train" },
  { "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad", 24, 8, "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform" },
  { "f30f8c1da665478f49b001d94c5fc452", 12, 4, "vessel ladder alter error federal sibling chat ability sun glass valve picture" },
  { "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f", 24, 8, "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold" },
};
static const int BIP39_VECTORS_COUNT = sizeof(BIP39_VECTORS)/sizeof(BIP39_VECTORS[0]);

struct DiceVector {
  const char* name;
  const uint8_t* rolls;
  int roll_count;
  int ent_bytes;
  int cs_bits;
  int word_count;
  const char* entropy_hex;
  const char* mnemonic;
};

static const uint8_t ROLLS_ALL_ONES_50[] = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
static const uint8_t ROLLS_ALL_ONES_99[] = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
static const uint8_t ROLLS_ALL_SIXES_50[] = { 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6 };
static const uint8_t ROLLS_ALL_SIXES_99[] = { 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6 };
static const uint8_t ROLLS_RANDOM_50[] = { 5, 6, 2, 4, 2, 5, 3, 3, 1, 4, 2, 4, 2, 1, 6, 3, 3, 3, 3, 6, 6, 1, 3, 2, 4, 6, 2, 4, 4, 2, 2, 5, 1, 5, 2, 4, 1, 1, 3, 2, 3, 5, 6, 1, 3, 1, 5, 5, 6, 4 };
static const uint8_t ROLLS_RANDOM_99[] = { 4, 2, 2, 3, 3, 6, 3, 1, 1, 2, 1, 3, 4, 1, 1, 3, 3, 3, 1, 5, 5, 5, 6, 6, 4, 6, 5, 6, 3, 2, 1, 2, 1, 4, 5, 3, 4, 4, 3, 1, 1, 3, 3, 3, 6, 4, 4, 2, 2, 4, 4, 1, 2, 6, 6, 6, 6, 3, 6, 6, 4, 2, 6, 1, 3, 5, 1, 5, 4, 4, 6, 2, 2, 4, 4, 5, 1, 6, 3, 2, 1, 1, 6, 4, 2, 1, 2, 6, 2, 5, 4, 2, 5, 3, 5, 4, 1, 6, 5 };

static const DiceVector DICE_VECTORS[] = {
  { "all_ones_50", ROLLS_ALL_ONES_50, 50, 16, 4, 12, "00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
  { "all_ones_99", ROLLS_ALL_ONES_99, 99, 32, 8, 24, "0000000000000000000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" },
  { "all_sixes_50", ROLLS_ALL_SIXES_50, 50, 16, 4, 12, "60154fc36cbf42778f23ffffffffffff", "gas price valid sunny vintage design develop lend zoo zoo zoo wrong" },
  { "all_sixes_99", ROLLS_ALL_SIXES_99, 99, 32, 8, 24, "f0bb8a1bbde9163b9e053e8f918bf8e4d34034d7ffffffffffffffffffffffff", "vague sword manage knock multiply build job pond moon middle wreck situate cross bounce garment zoo zoo zoo zoo zoo zoo zoo zoo valid" },
  { "random_50", ROLLS_RANDOM_50, 50, 16, 4, 12, "ee33fca6525d4391da9140f916364051", "until paper civil pigeon stage similar heart chimney weekend random mosquito pear" },
  { "random_99", ROLLS_RANDOM_99, 99, 32, 8, 24, "80a0f594d7290558852006bcc34afd489f3a2f593a6b4e7abe9d909c4ad0192a", "level amateur gown purity motion proof behind absorb rubber bottom satisfy muffin victory bless gossip estate example sting polar cancel seven gym gorilla excess" },
};
static const int DICE_VECTORS_COUNT = sizeof(DICE_VECTORS)/sizeof(DICE_VECTORS[0]);

// SeedSigner's own published test vectors for its dice-roll entropy feature
// (docs/dice_verification.md in SeedSigner/seedsigner, fetched verbatim --
// these are THEIR numbers, not ours). Pin diceToEntropySeedSignerCompat()
// against a third-party-published, independently-audited source, the same
// role BIP39_VECTORS plays for entropyToMnemonic(). The expected entropy_hex
// values were derived locally (sha256 of the literal roll-digit string,
// full 32 bytes for the 24-word case / first 16 bytes for the 12-word case)
// and cross-checked against the expected mnemonic before being trusted.
static const uint8_t SEEDSIGNER_ROLLS_99[] = { 6,5,5,1,5,2,2,3,1,3,1,6,5,2,1,3,2,1,6,1,1,3,3,1,5,4,4,4,4,1,2,3,6,1,6,4,6,6,4,4,3,1,1,2,1,5,3,4,4,1,5,6,3,3,5,2,6,4,5,6,2,5,4,4,6,2,2,4,5,5,4,6,2,3,6,5,4,2,3,6,4,2,4,6,3,1,2,6,1,3,3,2,2,2,3,4,6,1,2 };
static const uint8_t SEEDSIGNER_ROLLS_50[] = { 6,5,5,1,5,2,2,3,1,3,1,6,5,2,1,3,2,1,6,1,1,3,3,1,5,4,4,4,4,1,2,3,6,1,6,4,6,6,4,4,3,1,1,2,1,5,3,4,4,1 };

static const DiceVector SEEDSIGNER_VECTORS[] = {
  { "seedsigner_99", SEEDSIGNER_ROLLS_99, 99, 32, 8, 24,
    "51531761ec7a738946e0b9f46bb11320a695495430e345c14f01ad8b3b898a6d",
    "eyebrow obvious such suggest poet seven breeze blame virtual frown dynamic donor harsh pigeon express broccoli easy apology scatter force recipe shadow claim radio" },
  { "seedsigner_50", SEEDSIGNER_ROLLS_50, 50, 16, 4, 12,
    "6cb09af855050dcde6fe2adc3181c250",
    "hole luggage safe present express tragic orbit shed switch metal identify path" },
};
static const int SEEDSIGNER_VECTORS_COUNT = sizeof(SEEDSIGNER_VECTORS)/sizeof(SEEDSIGNER_VECTORS[0]);
