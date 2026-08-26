# DiceSeed

Offline, air-gapped dice-roll → BIP39 seed phrase generator for the
[LilyGO T-Display S3](https://www.lilygo.cc/products/t-display-s3) (plain,
non-touch variant).

You physically roll a d6, enter each result on the board's two buttons, and
the firmware turns your rolls into a standard 12- or 24-word BIP39 mnemonic —
the same kind of phrase a hardware wallet shows you, generated from entropy
*you* supplied and can audit, not a hardware RNG you have to trust blindly.

## Why dice instead of the chip's own RNG?

Because then nothing has to be trusted except arithmetic you can, in
principle, redo by hand: roll → base-6 number → low N bits → SHA-256
checksum → word list lookup. No hardware RNG, no radio, ever, is mixed in
(see [Security model](#security-model)).

## Hardware

- LilyGO T-Display S3 — plain/non-touch version. Uses the board's ST7789
  display (170×320, 8-bit parallel bus) and its two built-in buttons
  (GPIO0, GPIO14).
- USB-C cable for flashing. **Not required afterward** — see the security
  note about running on battery power for actual use.

## Build & flash

Confirmed working on real hardware (display renders correctly) as of v1.2.0.

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
4. **Hold both buttons for 2 seconds** to wipe RAM and reset back to the
   menu. This is the only way to leave the result screen; there's no
   "start a new one without wiping" shortcut, deliberately.

## Security model

- No WiFi or Bluetooth code anywhere in this repo — the ESP32 core never
  brings either radio up.
- Rolls and the mnemonic live only in RAM. Nothing is ever written to
  flash, NVS, or Serial (`Serial.begin()` is never called).
- Sensitive buffers are cleared with `mbedtls_platform_zeroize()` (not
  `memset`, which a compiler can optimize away as a dead store) at boot and
  before the wipe-triggered reset.
- Entropy comes **only** from the dice rolls you enter.

**What this cannot protect against:** the T-Display S3's USB port is a
native USB-Serial-JTAG peripheral, enabled by default at the silicon
level. Anyone with a USB cable and OpenOCD can halt the CPU and dump RAM
while a phrase is on screen, regardless of anything the firmware does. Run
it on battery power with no USB cable attached whenever you're actually
entering rolls or reading back a phrase.

**Known, accepted limitation:** the 12-word/50-roll mode has a small
modular bias (effective min-entropy ≈127.4 bits, not a clean 128) because
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

Run it after touching `diceseed_core.h`, `bip39_wordlist.h`, or
`tests/vectors.h`.

## License

MIT — see `LICENSE`.
