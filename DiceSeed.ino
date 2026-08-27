// Offline dice-roll -> BIP39 seed phrase generator for the LilyGO T-Display S3.
//
// Security model:
//   - Neither WiFi.h nor any Bluetooth API is included or called anywhere in
//     this file, so the Arduino-ESP32 core never brings up either radio.
//   - Rolls and the mnemonic live only in RAM (plain arrays on the
//     stack/BSS). Nothing is ever written to flash, NVS/Preferences, or Serial.
//   - RAM is scrubbed at boot (defense against residue from a previous run)
//     and again before the final reset-to-wipe, using
//     mbedtls_platform_zeroize() rather than memset() so the compiler can't
//     optimize the clear away as a dead store. The intermediate entropy is
//     kept as a global (entropyBytes) with the same lifetime as the
//     mnemonic, specifically so the result screen can display it as hex on
//     request (v2.0.0) -- it no longer self-scrubs immediately the way it
//     did in v1.2.0, since that's now something you may want to look at.
//   - Entropy is derived only from the dice rolls you enter -- no hardware RNG
//     is mixed in, so the whole process is independently auditable.
//
// Method: two build variants, selected at compile time by build_mode.h
// (DICESEED_COMPAT_BUILD), sharing every other line of this file:
//   - Compat (default, DICESEED_COMPAT_BUILD=1): the roll sequence, as
//     literal ASCII digits, is hashed with SHA-256 and the low ENT_BITS
//     bits of the digest become the entropy -- matching SeedSigner's own
//     dice-roll seed feature byte-for-byte (see diceseed_core.h,
//     diceToEntropySeedSignerCompat), so the same physical rolls produce
//     the identical mnemonic on either device. Not hand-computable.
//   - Classic (DICESEED_COMPAT_BUILD=0): each d6 roll becomes a base-6
//     digit (roll-1, i.e. 0-5), all digits accumulated into one big number
//     N, and the low ENT_BITS bits of N become the entropy -- recomputable
//     by hand with pencil and paper, unlike compat. See diceseed_core.h
//     (diceToEntropy) for the exact bias tradeoff in the 12-word/50-roll
//     case.
// Either way, a SHA-256 checksum of the entropy supplies the extra checksum
// bits BIP39 requires (this step is identical and unavoidable in both
// variants -- see entropyToMnemonic in diceseed_core.h), and the combined
// bitstream is split into 11-bit groups that index into the 2048-word list.
//
// Whichever variant is built, the intermediate entropy is kept in RAM (never
// written to flash/Serial) until wipe, and can be displayed on-screen as hex
// from the result screen -- paste it into a BIP39 tool's raw "Hex" entropy
// field (not its "Dice" mode -- see README.md) to cross-check against
// iancoleman.io or any other standard BIP39 implementation, regardless of
// which variant produced it.
//
// What this CANNOT protect against: the T-Display S3's USB port is a native
// USB-Serial-JTAG peripheral that is enabled by default at the silicon level.
// Anyone with a USB cable and OpenOCD can halt the CPU and dump all of RAM
// while a phrase is on screen, regardless of anything this sketch does. Run
// it on battery power with no USB cable attached whenever you're actually
// viewing or entering sensitive rolls/words.
//
// Hardware: LilyGO T-Display S3 (plain, non-touch). Buttons: GPIO0, GPIO14.
//
// The core algorithm (dice -> entropy -> BIP39 mnemonic) lives in
// diceseed_core.h, not in this file. It's shared verbatim with
// tests/test_core.cpp, which checks it against the official BIP39 test
// vectors and an independently-computed dice oracle -- run
// tests/run_tests.sh after touching diceseed_core.h or bip39_wordlist.h.
//
// Version history:
//   1.0.0 (2026-08-25) - Initial version.
//   1.1.0 (2026-08-25) - Security hardening pass: wipe no longer risks
//                         stranding the board in the ROM bootloader; all
//                         sensitive-buffer clears use mbedtls_platform_zeroize
//                         instead of memset (compiler can't elide it as a
//                         dead store); big[] in computeMnemonic is now
//                         scrubbed too; word display uses print() instead of
//                         printf() (printf leaves a formatted copy on the
//                         stack); removed WiFi.h/btStop() entirely (calling
//                         them to "turn radios off" was initializing the
//                         radio driver first); added a same-roll sanity
//                         warning; documented the USB-JTAG physical exposure.
//   1.2.0 (2026-08-25) - Correctness pass: extracted the dice/entropy/BIP39
//                         math into diceseed_core.h (no Arduino dependency)
//                         and added tests/test_core.cpp, which checks it
//                         against the official trezor/python-mnemonic BIP39
//                         test vectors plus an independent Python-computed
//                         dice oracle (34/34 pass). Documented the 12-word
//                         mode's small modular bias (~127.4 effective bits,
//                         inherent to any dice-to-BIP39 method, not fixed --
//                         see diceseed_core.h for why). No functional change
//                         to the 24-word path, which was already bias-free.
//                         Added README.md and LICENSE (MIT).
//   2.0.0 (2026-08-26) - Added a second build variant (build_mode.h,
//                         DICESEED_COMPAT_BUILD) using SeedSigner's own
//                         dice-roll entropy method (SHA-256 of the literal
//                         roll digits), verified against SeedSigner's
//                         published test vectors, so identical physical
//                         rolls produce an identical mnemonic on either
//                         device. This compat method is now the DEFAULT
//                         build (DICESEED_COMPAT_BUILD=1) -- the point of a
//                         group standardizing on this device is
//                         cross-checkable output, so that's what people get
//                         without touching anything. The original classic
//                         bignum method is unchanged and still available
//                         (DICESEED_COMPAT_BUILD=0) for anyone who
//                         specifically wants hand-auditability instead.
//                         Both variants can now show the intermediate raw
//                         entropy as hex from the result screen, for pasting
//                         into any BIP39 tool's raw-entropy field (e.g.
//                         iancoleman.io's Hex mode) as an independent check.
//                         Requested by Justin's local BTC group, who wanted
//                         DiceSeed's output checkable against the two tools
//                         they already trust (iancoleman.io, SeedSigner)
//                         without giving up the original hand-auditable
//                         build for people who want that property instead.
//                         Confirmed on real hardware: compat build matches
//                         both SeedSigner and iancoleman.io on the same
//                         rolls (2026-08-27).
//   2.0.1 (2026-08-27) - Fixed a REGRESSION: the two-button wipe hold had
//                         worked fine before v2.0.0 (confirmed -- it was
//                         tested and used on real hardware previously) and
//                         broke when v2.0.0 added the raw-entropy view
//                         toggle. Root cause: starting a two-button hold
//                         means pressing BTN1 down first (or very close to
//                         it), and v2.0.0 fired the entropy-view toggle
//                         (a full-screen redraw) unconditionally on BTN1's
//                         press edge -- disrupting the exact moment you're
//                         bringing BTN2 down too. Fixed by deciding BTN1's
//                         meaning at RELEASE instead of press: it's only
//                         treated as a view-toggle tap if BTN2 never also
//                         went down while BTN1 was held, so a genuine
//                         two-button hold never triggers a redraw at all.
//                         Also hardened the hold TIMER itself as a
//                         separate, defensive fix: it used to reset to
//                         zero on the very first sample where either
//                         button read not-pressed, with zero tolerance for
//                         contact bounce -- GPIO0 also carries the
//                         boot-strap role and is noisier than a plain
//                         GPIO, so this is now debounced (150ms) the same
//                         way the press side already was. Reported from
//                         real hardware (the touch-variant board).

#define FIRMWARE_VERSION_BASE "2.0.1"

#include "build_mode.h"
#include "tft_setup.h" // must precede <TFT_eSPI.h> -- see that file for why
#include <TFT_eSPI.h>
#include "diceseed_core.h"

#if DICESEED_COMPAT_BUILD
  #define FIRMWARE_VERSION FIRMWARE_VERSION_BASE "-compat"
#else
  #define FIRMWARE_VERSION FIRMWARE_VERSION_BASE "-classic"
#endif

// ---- Pins (from LilyGO's official pin_config.h for T-Display S3) ----------
#define PIN_BUTTON_1 0   // cycles the current die value 1..6
#define PIN_BUTTON_2 14  // confirms roll / advances; long-press = go back
#define PIN_POWER_ON 15  // must be held HIGH to power the display

TFT_eSPI tft = TFT_eSPI();

// ---- App state (RAM only, never persisted) ---------------------------------
static const int MAX_ROLLS = 99;          // enough for the 24-word case
static uint8_t rolls[MAX_ROLLS];          // each 1..6, 0 = not yet entered
static char mnemonicWords[24][16];        // resulting words, plain text
static uint8_t entropyBytes[32];          // intermediate entropy, kept for
                                           // the raw-entropy display (as
                                           // sensitive as mnemonicWords)

int wordCount = 0;          // 12 or 24, chosen at runtime
int rollsNeeded = 0;        // 50 or 99
int entBytes = 0;           // 16 or 32
int csBits = 0;             // 4 or 8

enum Screen { SCR_MENU, SCR_ROLLING, SCR_RESULT, SCR_WIPE_CONFIRM };
Screen screen = SCR_MENU;

// ---- RAM scrubbing -----------------------------------------------------
// Uses mbedtls_platform_zeroize() instead of memset(): a plain memset on a
// buffer nobody reads again is a "dead store" the compiler is allowed to
// (and does) optimize away. platform_zeroize is specifically designed to
// survive that optimization.
void scrubSensitiveRAM() {
  mbedtls_platform_zeroize(rolls, sizeof(rolls));
  mbedtls_platform_zeroize(mnemonicWords, sizeof(mnemonicWords));
  mbedtls_platform_zeroize(entropyBytes, sizeof(entropyBytes));
  // The BIP39 checksum step's own scratch space is function-local inside
  // diceseed_core.h and zeroizes itself before returning. entropyBytes
  // above is different: it's kept as a global (v2.0.0) specifically so the
  // result screen can display it, so it needs the same lifetime and the
  // same scrub treatment as mnemonicWords.
}

// ---- Buttons (active LOW, simple debounce) ---------------------------------
bool button1Pressed() {
  static bool last = HIGH;
  bool cur = digitalRead(PIN_BUTTON_1);
  bool pressed = (last == HIGH && cur == LOW);
  last = cur;
  if (pressed) delay(30);
  return pressed;
}

// Returns 0 = nothing, 1 = short press, 2 = long press (>=800ms)
int button2Event() {
  static bool wasDown = false;
  static unsigned long downAt = 0;
  bool down = (digitalRead(PIN_BUTTON_2) == LOW);
  int result = 0;
  if (down && !wasDown) {
    downAt = millis();
    delay(30);
  } else if (!down && wasDown) {
    unsigned long held = millis() - downAt;
    result = (held >= 800) ? 2 : 1;
    delay(30);
  }
  wasDown = down;
  return result;
}

// ---- UI ---------------------------------------------------------------
int menuChoice = 0; // 0 = 12 words, 1 = 24 words
int currentRollIndex = 0;
uint8_t currentFace = 1;
int resultPage = 0;
unsigned long bothDownSince = 0;
unsigned long bothUpSince = 0;  // debounces the RELEASE of the wipe-hold gesture
bool allRollsIdentical = false; // sanity flag: every roll came out the same face
bool showingEntropy = false;    // result-screen sub-view: words vs raw entropy hex
bool btn1WasDown = false;       // result-screen BTN1 edge tracking (independent
bool btn1PureTap = false;       // of button1Pressed() -- see SCR_RESULT for why

void drawMenu() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.println("Dice -> Seed Phrase");
  tft.setCursor(10, 50);
  tft.println("Choose word count:");
  tft.setCursor(10, 80);
  tft.setTextColor(menuChoice == 0 ? TFT_GREEN : TFT_WHITE, TFT_BLACK);
  tft.println(menuChoice == 0 ? "> 12 words (50 rolls)" : "  12 words (50 rolls)");
  tft.setCursor(10, 105);
  tft.setTextColor(menuChoice == 1 ? TFT_GREEN : TFT_WHITE, TFT_BLACK);
  tft.println(menuChoice == 1 ? "> 24 words (99 rolls)" : "  24 words (99 rolls)");
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(10, 145);
  tft.setTextSize(1);
  tft.println("BTN1: toggle   BTN2: select");
  // x=200, not the old 260: "v1.2.0" (6 chars) fit at 260, but the variant
  // suffix ("v2.0.0-classic"/"v2.0.0-compat", 14-15 chars) needs more room
  // on the 320px-wide landscape screen or it runs off the right edge --
  // exactly the kind of thing this display exists to let you visually
  // confirm, so it has to actually be visible.
  tft.setCursor(200, 155);
  tft.print("v");
  tft.print(FIRMWARE_VERSION);
}

void startRolling() {
  wordCount = (menuChoice == 0) ? 12 : 24;
  rollsNeeded = (menuChoice == 0) ? 50 : 99;
  entBytes = (menuChoice == 0) ? 16 : 32;
  csBits = (menuChoice == 0) ? 4 : 8;
  currentRollIndex = 0;
  currentFace = 1;
  screen = SCR_ROLLING;
}

void drawRolling() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.printf("Roll %d / %d\n", currentRollIndex + 1, rollsNeeded);

  tft.setTextSize(6);
  tft.setTextColor(TFT_GREEN, TFT_BLACK);
  tft.setCursor(130, 60);
  tft.printf("%d", currentFace);

  tft.setTextSize(1);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(10, 145);
  tft.println("BTN1: change value   BTN2 tap: confirm");
  tft.setCursor(10, 155);
  tft.println("BTN2 hold: back to previous roll");
}

void drawResult() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  int perPage = 4;
  int totalPages = (wordCount + perPage - 1) / perPage;
  tft.setCursor(10, 5);
  if (resultPage == 0 && allRollsIdentical) {
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.println("WARN: rolls all same");
  } else {
    tft.printf("Words (page %d/%d)\n", resultPage + 1, totalPages);
  }
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  int y = 35;
  for (int i = 0; i < perPage; i++) {
    int idx = resultPage * perPage + i;
    if (idx >= wordCount) break;
    tft.setCursor(10, y);
    // print(), not printf(): printf formats into a stack buffer first,
    // leaving an extra un-scrubbed copy of the word behind. print() streams
    // the string straight out with no intermediate buffer.
    if (idx + 1 < 10) tft.print(' ');
    tft.print(idx + 1);
    tft.print(". ");
    tft.print(mnemonicWords[idx]);
    tft.print("\n");
    y += 25;
  }
  tft.setTextSize(1);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(10, 130);
  if ((resultPage + 1) < totalPages) {
    tft.println("BTN2 tap: next page");
  } else {
    tft.println("BTN2 tap: back to page 1");
  }
  tft.setCursor(10, 142);
  tft.println("BTN1 tap: show raw entropy (hex)");
  tft.setCursor(10, 155);
  tft.println("Hold BOTH buttons 2s: WIPE + reset");
}

// One nibble at a time via a constant lookup table, never a formatted
// stack buffer of the actual entropy bytes -- same discipline as the word
// display above (print(), not printf()), just applied to hex digits.
void printHexByte(uint8_t b) {
  // Not named HEX: that identifier is a Print.h macro (base-16 formatting
  // flag), and #define HEX 16 would silently mangle this into an int array.
  static const char* hexDigits = "0123456789abcdef";
  tft.print(hexDigits[(b >> 4) & 0xF]);
  tft.print(hexDigits[b & 0xF]);
}

void drawEntropy() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_YELLOW, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 5);
  tft.println("Raw entropy (hex)");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  const int bytesPerLine = 8; // 16 hex chars/line; 32 bytes -> 4 lines
  int y = 35;
  for (int off = 0; off < entBytes; off += bytesPerLine) {
    tft.setCursor(10, y);
    int n = (entBytes - off < bytesPerLine) ? (entBytes - off) : bytesPerLine;
    for (int i = 0; i < n; i++) printHexByte(entropyBytes[off + i]);
    y += 22;
  }
  tft.setTextSize(1);
  tft.setTextColor(TFT_RED, TFT_BLACK);
  tft.setCursor(10, 130);
  tft.println("As sensitive as the mnemonic itself.");
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(10, 142);
  tft.println("Paste into a BIP39 tool's Hex field.");
  tft.setCursor(10, 155);
  tft.println("BTN1 tap: back to words");
}

void drawWipeConfirm() {
  tft.fillScreen(TFT_RED);
  tft.setTextColor(TFT_WHITE, TFT_RED);
  tft.setTextSize(2);
  tft.setCursor(10, 60);
  tft.println("Wiping RAM");
  tft.setCursor(10, 90);
  tft.println("and resetting...");
}

void setup() {
  // No Serial.begin() on purpose: never let the mnemonic risk leaking to USB.
  pinMode(PIN_POWER_ON, OUTPUT);
  digitalWrite(PIN_POWER_ON, HIGH);
  pinMode(PIN_BUTTON_1, INPUT_PULLUP);
  pinMode(PIN_BUTTON_2, INPUT_PULLUP);

  // No WiFi.h/BluetoothSerial and no calls into either radio's API at all:
  // the Arduino-ESP32 core never starts a radio on its own, and calling
  // WiFi.mode()/btStop() to "turn it off" actually initializes the radio
  // driver first (including an NVS touch for WiFi), which is worse than
  // just never touching it.

  // Scrub RAM before first use too, in case of a warm reset with old content.
  scrubSensitiveRAM();

  tft.init();
  tft.setRotation(1);
  tft.fillScreen(TFT_BLACK);

  drawMenu();
}

void loop() {
  switch (screen) {
    case SCR_MENU: {
      if (button1Pressed()) {
        menuChoice = 1 - menuChoice;
        drawMenu();
      }
      int ev = button2Event();
      if (ev == 1) {
        startRolling();
        drawRolling();
      }
      break;
    }

    case SCR_ROLLING: {
      if (button1Pressed()) {
        currentFace = (currentFace % 6) + 1;
        drawRolling();
      }
      int ev = button2Event();
      if (ev == 1) {
        rolls[currentRollIndex] = currentFace;
        currentRollIndex++;
        currentFace = 1;
        if (currentRollIndex >= rollsNeeded) {
          allRollsIdentical = true;
          for (int i = 1; i < rollsNeeded; i++) {
            if (rolls[i] != rolls[0]) { allRollsIdentical = false; break; }
          }
          // Two steps, not the computeMnemonic() convenience wrapper: this
          // build needs entropyBytes to survive afterward for the raw-
          // entropy display, so it can't use the wrapper (which scrubs its
          // internal entropy copy before returning).
#if DICESEED_COMPAT_BUILD
          diceseed::diceToEntropySeedSignerCompat(rolls, rollsNeeded, entBytes, entropyBytes);
#else
          diceseed::diceToEntropy(rolls, rollsNeeded, entBytes, entropyBytes);
#endif
          diceseed::entropyToMnemonic(entropyBytes, entBytes, wordCount, csBits, mnemonicWords);
          // Rolls are no longer needed once the mnemonic is derived.
          mbedtls_platform_zeroize(rolls, sizeof(rolls));
          resultPage = 0;
          showingEntropy = false;
          btn1WasDown = false;
          btn1PureTap = false;
          screen = SCR_RESULT;
          drawResult();
        } else {
          drawRolling();
        }
      } else if (ev == 2 && currentRollIndex > 0) {
        currentRollIndex--;
        currentFace = rolls[currentRollIndex];
        rolls[currentRollIndex] = 0;
        drawRolling();
      }
      break;
    }

    case SCR_RESULT: {
      bool b1 = (digitalRead(PIN_BUTTON_1) == LOW);
      bool b2 = (digitalRead(PIN_BUTTON_2) == LOW);
      if (b1 && b2) {
        bothUpSince = 0; // solidly down again; cancel any pending release
        if (bothDownSince == 0) bothDownSince = millis();
        if (millis() - bothDownSince >= 2000) {
          screen = SCR_WIPE_CONFIRM;
          drawWipeConfirm();
          scrubSensitiveRAM();
          // GPIO0 (BTN1) is the ESP32-S3's boot-strapping pin: if it's still
          // held LOW when the chip resets, it boots into the ROM download
          // bootloader instead of this sketch (black screen, stuck in
          // bootloader over USB). Wait for both buttons to be physically
          // released before resetting.
          while (digitalRead(PIN_BUTTON_1) == LOW || digitalRead(PIN_BUTTON_2) == LOW) {
            delay(20);
          }
          delay(300); // let the pin settle high before the reset samples it
          esp_restart();
        }
      } else if (bothDownSince != 0) {
        // Debounce the RELEASE, not just the press: GPIO0 also carries the
        // boot-strap role, which makes it noisier than a plain GPIO, so a
        // single bounced sample here used to zero the whole 2-second timer
        // instantly -- on a noisy button that can mean the hold never
        // accumulates to 2s at all (reported on the touch board, 2026-08).
        // Require the release to hold for 150ms before treating it as
        // real, so a momentary bounce mid-hold doesn't restart the count.
        if (bothUpSince == 0) bothUpSince = millis();
        if (millis() - bothUpSince >= 150) {
          bothDownSince = 0;
          bothUpSince = 0;
        }
      }

      // Decide BTN1's meaning at RELEASE, not at press, and only call it a
      // view-toggle tap if BTN2 never also went down while BTN1 was held.
      // v2.0.0 fired the toggle+redraw on BTN1's press edge unconditionally
      // (via button1Pressed()) -- but starting a two-button hold means
      // pressing BTN1 down first (or very close to it), so that redraw
      // could fire in the exact moment you're bringing BTN2 down too,
      // disrupting the gesture itself. Waiting until release, and voiding
      // the tap the instant BTN2 joins in, means a genuine hold attempt
      // never triggers a redraw at all.
      if (b1 && !btn1WasDown) btn1PureTap = true;   // BTN1 just went down
      if (b1 && b2) btn1PureTap = false;            // BTN2 joined -> not a tap
      if (!b1 && btn1WasDown && btn1PureTap) {      // BTN1 just released, clean
        showingEntropy = !showingEntropy;
        showingEntropy ? drawEntropy() : drawResult();
      }
      btn1WasDown = b1;

      int ev = button2Event();
      if (ev == 1 && !showingEntropy) {
        int perPage = 4;
        int totalPages = (wordCount + perPage - 1) / perPage;
        resultPage = (resultPage + 1) % totalPages;
        drawResult();
      }
      break;
    }

    case SCR_WIPE_CONFIRM:
      // esp_restart() already fired; nothing to do here.
      break;
  }
}
