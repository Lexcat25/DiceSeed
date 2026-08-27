# DiceSeed

Offline, air-gapped dice-roll → BIP39 seed phrase generator for the
[LilyGO T-Display S3](https://www.lilygo.cc/products/t-display-s3) (plain,
non-touch variant).

You physically roll a d6, enter each result on the board's two buttons, and
the firmware turns your rolls into a standard 12- or 24-word BIP39 mnemonic —
the same kind of phrase a hardware wallet shows you, generated from entropy
*you* supplied and can audit, not a hardware RNG you have to trust blindly.

## Why dice instead of the chip's own RNG?

Because then nothing has to be trusted except a defined, checkable
conversion from your rolls to entropy — no hardware RNG, no radio, ever,
is mixed in (see [Security model](#security-model)). There are two builds
of that conversion, trading two different kinds of trust against each
other — see [Build variants](#build-variants).

## Hardware

- LilyGO T-Display S3 — plain/non-touch version. Uses the board's ST7789
  display (170×320, 8-bit parallel bus) and its two built-in buttons
  (GPIO0, GPIO14).
- USB-C cable for flashing. **Not required afterward** — see the security
  note about running on battery power for actual use.

## Build variants

One codebase, one repo, two firmware builds — selected by a single flag in
`build_mode.h` (`DICESEED_COMPAT_BUILD`). This exists because a local BTC
group wanted a way to trust this tool anchored to two things they already
trust: [iancoleman.io](https://iancoleman.io/bip39) and
[SeedSigner](https://seedsigner.com). Everything except the dice→entropy
step — display, buttons, wipe, wordlist, the BIP39 checksum step — is
identical between the two; that's deliberate, so there's only one thing to
independently review twice, not two whole codebases.

| | **Compat** (default, `DICESEED_COMPAT_BUILD=1`) | **Classic** (`DICESEED_COMPAT_BUILD=0`) |
|---|---|---|
| Roll → entropy | SHA-256 of the literal roll digits (`"1"`-`"6"`, no separator), low N bits of the digest | Whole roll sequence as one base-6 positional number, low N bits taken |
| Hand-auditable | No — SHA-256 isn't hand-computable | Yes — pencil-and-paper, in principle |
| Same rolls on a real **SeedSigner** unit | **Identical mnemonic** (verified against SeedSigner's own published test vectors) | Different mnemonic |
| Verifiable against **iancoleman.io** | Via the on-screen raw-entropy hex (below) — not its Dice mode | Via the on-screen raw-entropy hex (below) — not its Dice mode |

Neither variant is "more correct" — pick based on which property matters
more for a given device. **Compat is the default** because the point of a
group standardizing on this device is cross-checkable output, and that
should be what people get without touching anything; someone who
specifically wants to redo the whole derivation by hand wants **classic**
instead.

To build classic instead of the default:
- Edit `build_mode.h`, change the `1` to `0`, then compile/upload as usual — or
- `arduino-cli`, without touching tracked source:
  `arduino-cli compile --fqbn esp32:esp32:lilygo_t_display_s3 --build-property "build.extra_flags=-DDICESEED_COMPAT_BUILD=0" .`

The menu screen's version string shows which one is actually flashed
(`v2.0.0-classic` / `v2.0.0-compat`) — always check it after flashing,
especially if you're maintaining both builds across multiple boards.

## Build & flash

Confirmed working on real hardware as of v1.2.0 (display renders correctly)
and v2.0.1 (compat build's entropy matched both SeedSigner and iancoleman.io
on the same rolls; the two-button wipe hold works correctly — a v2.0.0
regression in that gesture was found and fixed in v2.0.1, see the version
history in `DiceSeed.ino`). Also confirmed working unmodified on the
touch-screen variant of the board (touch input itself isn't used yet).

**Getting the code onto disk, if you're not using `git clone`:** GitHub's
"Download ZIP" (from the repo page or a Release) extracts to a folder named
`DiceSeed-<version>` or `DiceSeed-main`, not `DiceSeed`. Arduino requires a
sketch's `.ino` to sit in a folder with the *exact same name* — if that
doesn't match, opening `DiceSeed.ino` makes the IDE "helpfully" create a
correctly-named `DiceSeed` subfolder and move **only the `.ino`** into it,
stranding `build_mode.h`, `diceseed_core.h`, `bip39_wordlist.h`, and
`tft_setup.h` one level up, outside the folder the compiler actually looks
in — a `fatal error: build_mode.h: No such file or directory` that has
nothing to do with your setup. **Rename the extracted folder to exactly
`DiceSeed` before opening anything in the IDE**, and this never happens.
`git clone https://github.com/Lexcat25/DiceSeed.git` sidesteps it
entirely, since the cloned folder is already named `DiceSeed`.

1. Install [Arduino IDE](https://www.arduino.cc/en/software) (2.x) or
   [`arduino-cli`](https://arduino.github.io/arduino-cli/).
2. Add the ESP32 board index:
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
   (Preferences → Additional Board Manager URLs), then install the **esp32**
   platform (tested against 3.3.11).
3. Install the **TFT_eSPI** library (tested against 2.5.43) via Library
   Manager.
4. Board: **LilyGo T-Display-S3** (`esp32:esp32:lilygo_t_display_s3`) — the `esp32:esp32`
   platform ships a dedicated board entry for this exact board (search "T-Display-S3" in
   Boards Manager), which also gets the flash size (16MB) and partition table right. The
   generic "ESP32S3 Dev Module" entry also compiles this sketch, but under different
   flash/partition defaults that don't match what's actually on the board.
5. Open `DiceSeed.ino` and compile/upload.

You do **not** need to hand-edit TFT_eSPI's own `User_Setup_Select.h`. This
repo ships `tft_setup.h` in the sketch folder, which TFT_eSPI auto-detects
and loads on its own (`__has_include(<tft_setup.h>)` — TFT_eSPI's own
documented mechanism, see that file's comments) with the exact ST7789/
8-bit-parallel pin configuration this board actually uses. Without it,
TFT_eSPI's out-of-the-box default targets a completely different display
and pin set (ILI9341 over SPI) — it still **compiles clean**, it just
drives nothing on real hardware, which is why this file matters even
though nothing about it is visible from a successful build log.

## Using it

1. Power on → menu: toggle 12-word (50 rolls) / 24-word (99 rolls) with
   button 1, confirm with button 2.
2. For each roll: cycle the shown face 1–6 with button 1 to match your
   physical die, confirm with button 2. Long-press button 2 to go back a
   roll if you mis-entered one.
3. After the last roll, the mnemonic is shown, four words per screen
   (button 2: next page). A red warning appears if every single roll came
   back identical — a sanity check, not a hard stop.
4. After the last word page, button 2 leads into a **3-step backup check**
   instead of wrapping back to page 1: it re-displays word #3, #7, and #11
   (12-word) or #6, #14, and #22 (24-word) one at a time — spread roughly
   beginning/middle/end of the phrase — so you can check each against what
   you actually wrote down. This isn't a blind quiz (there's no keyboard on
   this device to type an answer into); it's a targeted re-check of the
   transcription itself, which is one of the most common real ways a
   written-down backup ends up wrong. Button 2 advances through the 3
   checks, then returns to page 1.
5. **Button 1** on the result screen (word pages or the verify check)
   toggles to a **raw entropy (hex)** view —
   the intermediate bytes your rolls produced, before the BIP39 checksum
   and word lookup. Paste that hex into any BIP39 tool's raw entropy field
   (iancoleman.io: the **Hex [0-9A-F]** option, not its Dice mode — see
   [Cross-checking your output](#cross-checking-your-output)) to
   independently confirm the mnemonic, regardless of which build produced
   it. It's exactly as sensitive as the mnemonic itself — treat viewing it
   with the same care.
6. **Hold both buttons for 2 seconds** to wipe RAM and reset back to the
   menu. This is the only way to leave the result screen; there's no
   "start a new one without wiping" shortcut, deliberately.

## Security model

- No WiFi or Bluetooth code anywhere in this repo — the ESP32 core never
  brings either radio up.
- Rolls and the mnemonic live only in RAM. Nothing is ever written to
  flash, NVS, or Serial (`Serial.begin()` is never called).
- Sensitive buffers are cleared with `mbedtls_platform_zeroize()` (not
  `memset`, which a compiler can optimize away as a dead store) at boot and
  before the wipe-triggered reset. This now includes the raw entropy buffer
  (kept in RAM for the hex display above), not just the rolls and mnemonic.
- Entropy comes **only** from the dice rolls you enter.
- The **compat** build's use of SHA-256 for the entropy step isn't a new
  trust dependency: the BIP39 checksum step requires SHA-256 in *every*
  build, classic included, so compat just reuses that exact same
  already-required `mbedtls` call for a second purpose.

**What this cannot protect against:** the T-Display S3's USB port is a
native USB-Serial-JTAG peripheral, enabled by default at the silicon
level. Anyone with a USB cable and OpenOCD can halt the CPU and dump RAM
while a phrase is on screen, regardless of anything the firmware does. Run
it on battery power with no USB cable attached whenever you're actually
entering rolls or reading back a phrase.

**Known, accepted limitation (classic build only):** the 12-word/50-roll
mode has a small modular bias (effective min-entropy ≈127.4 bits, not a
clean 128) because
`6^50` needs slightly more than 128 bits and gets folded down via `mod
2^128`. This is the same tradeoff the reference
[iancoleman.io dice method](https://iancoleman.io/bip39/) makes — a
bias-free fix needs rejection sampling (occasionally asking for one more
roll), which was deliberately left out because it would break "verify this
by hand with pencil and paper." The 24-word/99-roll mode has **no** such
bias — 99 rolls was chosen specifically because `6^99 - 1 < 2^256`, so the
full number fits with nothing discarded. See `diceseed_core.h` for the
exact math.

## Testing

The dice→entropy→BIP39 algorithm lives in `diceseed_core.h`, deliberately
separated from anything Arduino/TFT-specific so it can be compiled and run
on a desktop. `tests/run_tests.sh` builds and runs `tests/test_core.cpp` in
a throwaway Docker container (no toolchain install needed on your machine)
against:

- the official [trezor/python-mnemonic](https://github.com/trezor/python-mnemonic)
  BIP39 test vectors (entropy → mnemonic, published independently of this
  repo), and
- dice-roll → entropy/mnemonic vectors computed by an independent Python
  re-implementation, itself validated against the same official vectors
  before being trusted to generate them.

```
tests/run_tests.sh
```

The **compat** build is additionally checked against SeedSigner's own
published [dice test vectors](https://github.com/SeedSigner/seedsigner/blob/main/docs/dice_verification.md) —
not retyped by hand, verified byte-for-byte via an independent Python
computation before being trusted, same standard as every other vector set
in this repo.

Run `tests/run_tests.sh` after touching `diceseed_core.h`, `bip39_wordlist.h`,
or `tests/vectors.h`.

## Cross-checking your output

**Don't type your raw dice rolls into iancoleman.io's "Dice" mode expecting
a match — on either build, that's not how to verify this device, and a
mismatch there doesn't mean anything is wrong.** BIP39 only standardizes
entropy→mnemonic; it says nothing about how dice rolls become entropy, and
iancoleman's Dice mode uses yet another convention (a variable-length
prefix code, face `6`→digit `0`) that doesn't match either DiceSeed build.
Confirmed directly: an all-`1`s roll sequence gives three *different*
results across DiceSeed-classic, DiceSeed-compat, and iancoleman's Dice
mode — none of them wrong, just three independently-invented conventions
for a step BIP39 never standardized.

**The actual verification paths, both using the on-device raw-entropy hex
screen** (see [Using it](#using-it), step 4):

- **Against iancoleman.io (either build):** roll, then view the raw entropy
  hex on-device, then paste that hex — not the rolls — into iancoleman's
  **Hex [0-9A-F]** entropy field (not Dice). That field does plain
  entropy→mnemonic, which is standard BIP39 and matches on both builds. Do
  this with a downloaded, offline copy of the page, and only with a test
  roll sequence you don't intend to actually use, never a real phrase.
- **Against SeedSigner (compat build only):** enter the *same physical
  rolls* directly into a real SeedSigner unit's dice-entropy feature. No
  hex transcription needed — compat's entropy derivation matches
  SeedSigner's exactly, so the resulting mnemonic should be identical.
  This is the strongest check available: two independently-developed,
  separately-audited implementations agreeing from the same raw input.

## Roadmap

Planned hardening and UX work — runtime build-mode toggle, reproducible
builds with published binary hashes, signed releases, and a consolidated
threat-model section — is tracked in [`ROADMAP.md`](ROADMAP.md).

## License

MIT — see `LICENSE`.
