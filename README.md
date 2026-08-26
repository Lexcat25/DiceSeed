# DiceSeed

Offline dice-roll → BIP39 seed phrase generator for the LilyGO T-Display S3.

Roll a standard six-sided die the required number of times, enter each
result on the device's two buttons, and it computes a valid BIP39 mnemonic
(12 or 24 words) entirely on-device. Nothing is ever written to flash,
NVS/Preferences, or Serial, and no WiFi/Bluetooth code is included — see
[Security model](#security-model) below for exactly what that does and does
not protect against.

## Prerequisites

### Hardware
- **LilyGO T-Display S3** (plain/non-touch variant — buttons on GPIO0 and
  GPIO14). Touch variants are not supported by this sketch as written.
- A USB-C cable for flashing.
- One standard six-sided die.
- (Recommended for actual use, not just flashing) A way to run the board on
  battery power with no USB cable attached — see the security note below.

### Software
- **Arduino IDE** 2.x.
- **esp32 board package** (by Espressif Systems) — tested against v3.3.11.
  Install via: Arduino IDE → Preferences → "Additional boards manager URLs" →
  add `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`,
  then Tools → Board → Boards Manager → search "esp32" → install.
- Board selection: **Tools → Board → LilyGo T-Display-S3**.
- **TFT_eSPI** library (by Bodmer) — tested against v2.5.43. Install via
  Tools → Manage Libraries → search "TFT_eSPI".
- TFT_eSPI must be pointed at the LilyGO T-Display S3 config. In the
  library's install folder, edit `User_Setup_Select.h`:
  - comment out `#include <User_Setup.h>`
  - uncomment `#include <User_Setups/Setup206_LilyGo_T_Display_S3.h>`

### Flashing
1. Connect the board via USB.
2. Select the board and port in the Arduino IDE (Tools → Board / Port).
3. Open `DiceSeed.ino`, click Verify to confirm it compiles, then Upload.

## Usage

- On boot, choose **12 words** (50 rolls) or **24 words** (99 rolls) with
  BTN1 to toggle, BTN2 to select.
- For each roll: BTN1 cycles the displayed die face 1–6, BTN2 confirms and
  advances. Hold BTN2 to go back and re-enter the previous roll.
- After the last roll, the mnemonic is computed and shown, several words per
  page. BTN2 taps to page through.
- **To wipe and reset**: hold both buttons for 2 seconds. This zeroes all
  in-RAM buffers and resets the device back to the menu.

## Security model

- No WiFi/Bluetooth code is included anywhere in the sketch — the radios are
  never brought up.
- Rolls, entropy, and the mnemonic exist only in RAM. Nothing touches flash,
  NVS/Preferences, or Serial.
- Sensitive buffers are cleared with `mbedtls_platform_zeroize()` (not
  `memset()`, which a compiler can legally optimize away as a dead store)
  both at boot and before the wipe-reset.
- Entropy comes only from the dice rolls you enter — no hardware RNG is
  mixed in, so the process is independently auditable and reproducible
  against other dice-to-BIP39 tools (e.g. iancoleman.io's offline dice mode).
- The derivation logic and wordlist have been checked against the official
  BIP39 test vectors and the canonical
  [english.txt](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)
  wordlist.

**What this cannot protect against:** the T-Display S3's USB port is a
native USB-Serial-JTAG peripheral enabled by default at the silicon level.
Anyone with a USB cable and OpenOCD can halt the CPU and dump all of RAM
while a phrase is on screen, regardless of anything the sketch does. Run the
device on battery power with no USB cable attached whenever you're actually
entering rolls or viewing a phrase.

This is a hobbyist tool, not an audited hardware wallet. Treat any phrase it
generates with the same caution you would treat one generated any other way,
and consider having the derivation logic independently reviewed before
trusting it with anything of real value.

## Versions

- `v1.0.0` — initial version.
- `v1.1.0` — security hardening pass (see the commit and the changelog
  comment at the top of `DiceSeed.ino` for details): fixed a wipe-gesture
  bug that could strand the board in the ROM bootloader, switched all RAM
  scrubbing to `mbedtls_platform_zeroize()`, removed unnecessary
  WiFi/Bluetooth calls, and a few other fixes from an independent code
  review.

Both are tagged in this repo's history and published as GitHub Releases.
