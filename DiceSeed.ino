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
//   2.1.0 (2026-08-27) - Added a backup-verification pass after the last
//                         word page: instead of wrapping straight back to
//                         page 1, the result screen quizzes 3 checkpoint
//                         words (spread ~25%/60%/90% through the mnemonic,
//                         so it works the same shape for 12 or 24 words).
//                         First cut just re-displayed the correct word for
//                         you to eyeball against your paper copy -- tested
//                         on real hardware the same day and correctly
//                         flagged (by Justin's BTC group) as too weak: it
//                         could only catch "I copied it right, let me
//                         double check," not "I misread it and wrote down
//                         the wrong word confidently." Reworked into a
//                         genuine blind multiple-choice pick instead: the
//                         real word plus 2 decoys (chosen with esp_random()
//                         -- confirmed to have no side effects on other
//                         subsystems, unlike WiFi.mode(); irrelevant here
//                         anyway since decoy selection has zero security
//                         requirement), cycle with BTN1, lock in with BTN2,
//                         told right/wrong before moving to the next
//                         checkpoint. BTN1 still opens the raw-entropy view
//                         when not actively picking (and cancels an
//                         in-progress verify pass); the wipe-hold gesture
//                         is unaffected and works from any sub-view.
//   2.3.0 (2026-08-29) - The word-count menu is touch-operable on a Touch
//                         board: the 12/24 options draw as two rounded-
//                         rect cells in the same visual language as the
//                         roll grid, with the same two-tap rule (first
//                         tap lights a cell, second tap on that cell
//                         starts). No cell starts pre-lit -- the same
//                         "don't show a choice the user hasn't made"
//                         rule as the roll grid, via a menuNeedsSelect
//                         flag -- and until a count is chosen BTN2
//                         refuses to start (red hint flash) rather than
//                         committing an invisible default, adopting the
//                         stricter of the two behaviors issue #1 left
//                         open (the one issue #2 recommends everywhere).
//                         Non-touch boards render and behave exactly as
//                         before. Implements issue #1.
//   2.3.1 (2026-08-29) - BTN2 can no longer commit a roll nobody chose.
//                         After startRolling() and after every commit,
//                         currentFace resets to 1, so a BTN2 press with
//                         no selection made silently recorded that
//                         invisible default and advanced -- a value the
//                         user never chose entering the entropy path,
//                         undetectable downstream (the result is still
//                         valid BIP39, and the all-same warning only
//                         fires if EVERY roll is identical). The touch
//                         path already had the right rule (a first tap
//                         can only select); now BTN2 obeys it too, on
//                         every board: refused presses flash a red hint
//                         and do not advance. The non-touch screen also
//                         draws the big face white until chosen (green
//                         once chosen), so the displayed default no
//                         longer looks confirmed -- the touch grid's
//                         white->green language, one screen over.
//                         Accepted scope (issue #2, all boards by
//                         request). BTN1's first press likewise now
//                         REVEALS the current face (lighting it where
//                         it stands) instead of stepping past it --
//                         stepping 1->2 with nothing lit would have
//                         made a rolled 1 cost six wrapping presses.
//                         Reveal-then-advance means a roll of N costs
//                         exactly N presses: one more than the old
//                         pre-lit-default UI, for any N, and a rolled 1
//                         is a single press (issue #2's feared tradeoff,
//                         designed away).
//                         The gate is touchNeedsSelect, previously
//                         documented as "unused on a non-touch board."
//                         Hardware-verified on the Touch board; the
//                         non-touch digit rendering is compile-verified
//                         only (no non-touch board on hand). Implements
//                         issue #2.
//   2.3.2 (2026-08-29) - Escape hatch from roll entry (issue #3): before
//                         this the only exits were finishing all 50/99
//                         rolls or power-cycling, because BTN2's
//                         long-press only steps back ONE roll and the
//                         two-button wipe lived solely on the result
//                         screen. Now a 2s both-button hold on the roll
//                         screen opens a confirm screen: Cancel returns
//                         to rolling with every entered roll intact;
//                         Wipe scrubs RAM and reboots to the menu via
//                         the same release-then-restart path the result
//                         screen's wipe always used (extracted into one
//                         shared wipeAndRestart(); the result screen's
//                         behavior is unchanged). The hold ENTRY stays
//                         button-only, as documented -- touch is used
//                         only for the affirmative confirm. To make the
//                         gesture possible at all, SCR_ROLLING's button
//                         handling became release-decided with "pure
//                         press" voiding (the result screen's v2.0.1
//                         pattern, generalized to both buttons): without
//                         it, starting a hold with BTN1 would move the
//                         face mid-gesture, and an abandoned hold would
//                         fire a spurious go-back-one-roll on release.
//                         Touch boards get the menu's two-cell layout
//                         (no pre-highlight, two-tap confirm, BTN2
//                         refuses unselected); non-touch boards get a
//                         text list with the SAFE option (Cancel)
//                         pre-highlighted per the displayed-value
//                         contract. No idle auto-cancel: the screen
//                         waits for a decision. Implements issue #3.

#define FIRMWARE_VERSION_BASE "2.3.2"

#include "build_mode.h"
#include "tft_setup.h" // must precede <TFT_eSPI.h> -- see that file for why
#include <TFT_eSPI.h>
#include "diceseed_core.h"
#include "touch.h"

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
static char verifyChoices[3][16];         // current verify step's 3 choices
                                           // (1 real word, 2 decoys) -- as
                                           // sensitive as mnemonicWords;
                                           // declared here (not with the
                                           // rest of the verify state below)
                                           // so scrubSensitiveRAM() above
                                           // can reference it

int wordCount = 0;          // 12 or 24, chosen at runtime
int rollsNeeded = 0;        // 50 or 99
int entBytes = 0;           // 16 or 32
int csBits = 0;             // 4 or 8

enum Screen { SCR_MENU, SCR_ROLLING, SCR_RESULT, SCR_WIPE_CONFIRM, SCR_RESET_CONFIRM };
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
  mbedtls_platform_zeroize(verifyChoices, sizeof(verifyChoices));
  // The BIP39 checksum step's own scratch space is function-local inside
  // diceseed_core.h and zeroizes itself before returning. entropyBytes
  // above is different: it's kept as a global (v2.0.0) specifically so the
  // result screen can display it, so it needs the same lifetime and the
  // same scrub treatment as mnemonicWords. verifyChoices (v2.1.0) gets the
  // same treatment for the same reason: one of its 3 slots is a real
  // mnemonic word, not just a decoy.
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
bool verifying = false;         // result-screen sub-view: backup-verification quiz
int verifyStep = 0;             // which of the 3 verify checkpoints we're on
uint8_t verifyWordNums[3];      // 1-based word numbers to spot-check this session
int verifyChoiceIdx = 0;        // which of the 3 is currently displayed
int verifyCorrectSlot = 0;      // which slot (0-2) holds the real word
bool verifyAnswered = false;    // false = picking, true = showing right/wrong
bool verifyWasCorrect = false;  // set once, when the pick is locked in
bool touchNeedsSelect = true;   // "no face has been explicitly chosen yet this
                                // roll." Cleared by a tap OR by BTN1, since
                                // both are deliberate choices; set on entry and
                                // after every commit. Two jobs: the touch grid
                                // shows no green cell until a real choice is
                                // made (the post-commit reset to face 1 must
                                // not look pre-selected), and a tap can only
                                // commit a face that was actually chosen --
                                // otherwise tapping "1" straight after a commit
                                // would commit in one tap while every other
                                // face needs two. Since v2.3.1 it is
                                // consulted on every board, not just
                                // touch ones: BTN2 cannot commit a roll
                                // while it is set (the issue #2 gate),
                                // and on the non-touch screen it is
                                // what draws the big face white (no
                                // choice yet) instead of green.
bool menuNeedsSelect = true;    // the menu's analog of touchNeedsSelect:
                                // "no word count has been explicitly chosen
                                // yet." Cleared by a tap on a menu cell or
                                // by BTN1, since both are deliberate
                                // choices; true at boot (the menu is only
                                // reached at boot -- leaving it always
                                // leads to rolls, and the wipe path is a
                                // reboot). Two jobs, same as the grid flag:
                                // no cell shows green until a real choice
                                // is made (the internal menuChoice=0
                                // default must not look pre-selected), and
                                // BTN2 on a Touch board refuses to start
                                // rather than committing a count the user
                                // never chose. BTN1 clearing it on a
                                // non-touch board is harmless; it is never
                                // consulted there (the `>` marker already
                                // shows what BTN2 will start).

// ---- Leave-rolling confirm (issue #3) ------------------------------------
// Entered by a 2s both-button hold on the roll screen; see the SCR_ROLLING
// and SCR_RESET_CONFIRM cases in loop().
bool resetNeedsSelect = true;  // that screen's analog of menuNeedsSelect:
                               // nothing chosen yet. Set on every entry.
int resetChoice = 0;           // 0 = Cancel (keep rolling), 1 = Wipe

// SCR_ROLLING's own raw-button tracking. Since v2.3.2 that screen cannot
// use the shared edge helpers (button1Pressed/button2Event): a two-button
// hold BEGINS with one button going down, and the helpers would act on
// that press edge immediately -- BTN1 would move the face mid-gesture
// (the exact v2.0.1 regression class) and BTN2's helper would later
// report an abandoned hold as a long-press "go back one roll". So, like
// the result screen, decisions there are made at RELEASE, and any press
// the other button joined is voided ("pure press" only).
unsigned long rollBothDownSince = 0;
unsigned long rollBothUpSince = 0;  // debounces the hold's RELEASE (GPIO0 noise)
bool rollBtn1WasDown = false;
bool rollBtn1PureTap = false;
bool rollBtn2WasDown = false;
bool rollBtn2PurePress = false;
unsigned long rollBtn2DownAt = 0;

// ---- Touch menu cells ------------------------------------------------------
// Only used when a touch panel is actually present. The button layout in
// drawMenu() below is left exactly as it was, so a non-touch board renders
// and behaves identically to previous firmware. (Same split as
// drawRolling/drawRollingTouch.)
static const int MCELL_W = 148, MCELL_H = 64;
static const int MCELL_X0 = 8, MCELL_X1 = 164, MCELL_Y0 = 56;

static void menuCellOrigin(int choice, int &x, int &y) {
  x = (choice == 0) ? MCELL_X0 : MCELL_X1;
  y = MCELL_Y0;
}

// Returns 0 (12 words), 1 (24 words), or -1 if the point missed both
// cells. Misses are ignored, never snapped to the nearest cell -- same
// rule as faceAtPoint: on a seed-entry device a wrong value is worse than
// a dropped tap.
static int menuCellAtPoint(int x, int y) {
  for (int c = 0; c <= 1; c++) {
    int cx, cy;
    menuCellOrigin(c, cx, cy);
    if (x >= cx && x < cx + MCELL_W && y >= cy && y < cy + MCELL_H) return c;
  }
  return -1;
}

// Same visual language as the roll grid's cells: darkgrey/white when
// unchosen, a double green border plus green text once selected -- the lit
// border is the "did my tap land, and on what?" feedback. Shared by the
// word-count menu and the leave-rolling confirm (same geometry, so
// menuCellAtPoint serves both).
static void drawMenuCell(int choice, const char* line1, const char* line2, bool selected) {
  int x, y;
  menuCellOrigin(choice, x, y);
  uint16_t border = selected ? TFT_GREEN : TFT_DARKGREY;

  tft.fillRoundRect(x, y, MCELL_W, MCELL_H, 6, TFT_BLACK);
  tft.drawRoundRect(x, y, MCELL_W, MCELL_H, 6, border);
  if (selected) tft.drawRoundRect(x + 1, y + 1, MCELL_W - 2, MCELL_H - 2, 5, border);

  // Line 1 centered at size 2 (e.g. "12 words" = 96px in a 148px cell),
  // line 2 centered at size 1 below it.
  tft.setTextSize(2);
  tft.setTextColor(selected ? TFT_GREEN : TFT_WHITE, TFT_BLACK);
  tft.setCursor(x + (MCELL_W - 12 * (int)strlen(line1)) / 2, y + 12);
  tft.print(line1);
  tft.setTextSize(1);
  tft.setTextColor(selected ? TFT_GREEN : TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(x + (MCELL_W - 6 * (int)strlen(line2)) / 2, y + 42);
  tft.print(line2);
}

static void drawMenuTouch() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 8);
  tft.println("Dice -> Seed Phrase");
  tft.setCursor(10, 32);
  tft.println("Choose word count:");

  // Same rule as the roll grid: nothing is shown as selected until a real
  // choice has been made. Showing the internal default (12 words) as
  // pre-selected would claim a choice the user has not made.
  drawMenuCell(0, "12 words", "(50 rolls)", !menuNeedsSelect && menuChoice == 0);
  drawMenuCell(1, "24 words", "(99 rolls)", !menuNeedsSelect && menuChoice == 1);

  tft.setTextSize(1);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(10, 138);
  tft.println("Tap a count, tap it again to start");
  tft.setCursor(10, 150);
  tft.println("Buttons still work");
  // Same spot as the non-touch menu -- the version string has to stay
  // visible after flashing either build (see the comment in drawMenu).
  tft.setCursor(200, 160);
  tft.print("v");
  tft.print(FIRMWARE_VERSION);
}

void drawMenu() {
  if (dstouch::detected()) { drawMenuTouch(); return; }

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

// Touch boards only: BTN2 with no count chosen must not start -- the
// cells (correctly) show no default, so committing the hidden
// menuChoice=0 would enter a 50-roll session the user never chose. Flash
// the reason in red instead of silently ignoring the press; a plain no-op
// would read as a dead button.
static void menuRefuseStart() {
  tft.setTextSize(1);
  tft.setTextColor(TFT_RED, TFT_BLACK);
  tft.setCursor(10, 138);
  tft.print("Select a word count first (tap or BTN1)  ");
  delay(800);
  drawMenu();
}

// ---- Leave-rolling confirm screen (issue #3) -------------------------
// The SAFE option (Cancel) leads both layouts: on non-touch it is the
// pre-highlighted default per that board's displayed-value contract; on
// touch nothing is pre-highlighted and BTN2 refuses to act unselected,
// same as the menu.
static void drawResetConfirmTouch() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 8);
  tft.println("Leave rolling?");

  drawMenuCell(0, "Cancel", "keep rolling", !resetNeedsSelect && resetChoice == 0);
  drawMenuCell(1, "Wipe", "back to menu", !resetNeedsSelect && resetChoice == 1);

  tft.setTextSize(1);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(10, 138);
  tft.println("Tap, tap again to confirm");
  tft.setCursor(10, 150);
  tft.println("Buttons still work");
  tft.setCursor(10, 160);
  tft.setTextColor(TFT_RED, TFT_BLACK);
  tft.println("Wipe erases all rolls so far");
}

static void drawResetConfirm() {
  if (dstouch::detected()) { drawResetConfirmTouch(); return; }

  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.println("Leave rolling?");
  tft.setCursor(10, 50);
  tft.setTextColor(resetChoice == 0 ? TFT_GREEN : TFT_WHITE, TFT_BLACK);
  tft.println(resetChoice == 0 ? "> Cancel (keep rolling)" : "  Cancel (keep rolling)");
  tft.setCursor(10, 75);
  tft.setTextColor(resetChoice == 1 ? TFT_GREEN : TFT_WHITE, TFT_BLACK);
  tft.println(resetChoice == 1 ? "> Wipe, back to menu" : "  Wipe, back to menu");
  tft.setTextSize(1);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(10, 145);
  tft.println("BTN1: toggle   BTN2: confirm");
  tft.setCursor(10, 155);
  tft.setTextColor(TFT_RED, TFT_BLACK);
  tft.println("Wipe erases all rolls so far");
}

void startRolling() {
  wordCount = (menuChoice == 0) ? 12 : 24;
  rollsNeeded = (menuChoice == 0) ? 50 : 99;
  entBytes = (menuChoice == 0) ? 16 : 32;
  csBits = (menuChoice == 0) ? 4 : 8;
  currentRollIndex = 0;
  currentFace = 1;
  touchNeedsSelect = true;
  screen = SCR_ROLLING;
}

// ---- Touch roll-entry grid -------------------------------------------------
// Only used when a touch panel is actually present. The button layout is left
// exactly as it was, so a non-touch board renders and behaves identically to
// previous firmware.
static const int GRID_X0 = 8, GRID_Y0 = 32;
static const int CELL_W = 98, CELL_H = 52;
static const int CELL_DX = 103, CELL_DY = 56;  // cell pitch, including gaps

static void cellOrigin(int face, int &x, int &y) {
  int i = face - 1;                 // 1..6 -> 0..5, laid out 3 across, 2 down
  x = GRID_X0 + (i % 3) * CELL_DX;
  y = GRID_Y0 + (i / 3) * CELL_DY;
}

// Returns 1..6, or 0 if the point missed every cell. Taps in the gaps and
// margins are ignored rather than snapped to the nearest cell -- on a dice
// entry screen a wrong value is worse than a dropped tap.
static int faceAtPoint(int x, int y) {
  for (int face = 1; face <= 6; face++) {
    int cx, cy;
    cellOrigin(face, cx, cy);
    if (x >= cx && x < cx + CELL_W && y >= cy && y < cy + CELL_H) return face;
  }
  return 0;
}

static void drawCell(int face, bool selected) {
  int x, y;
  cellOrigin(face, x, y);
  uint16_t border = selected ? TFT_GREEN : TFT_DARKGREY;
  uint16_t digit  = selected ? TFT_GREEN : TFT_WHITE;

  tft.fillRoundRect(x, y, CELL_W, CELL_H, 6, TFT_BLACK);
  // The lit border is the "did my tap land, and on what?" feedback. Touch
  // gives no tactile confirmation the way the buttons do, so it has to be
  // visual or it isn't there at all.
  tft.drawRoundRect(x, y, CELL_W, CELL_H, 6, border);
  if (selected) tft.drawRoundRect(x + 1, y + 1, CELL_W - 2, CELL_H - 2, 5, border);

  tft.setTextSize(4);                       // 24x32 px glyph
  tft.setTextColor(digit, TFT_BLACK);
  tft.setCursor(x + (CELL_W - 24) / 2, y + (CELL_H - 32) / 2);
  tft.printf("%d", face);
}

static void drawRollingTouch() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 6);
  tft.printf("Roll %d / %d", currentRollIndex + 1, rollsNeeded);

  // Nothing is shown as selected until a tap has actually landed: on entry
  // every cell is plain white, and the green cell means "this is what a second
  // tap will commit". Showing the post-commit reset value as pre-selected
  // would be claiming a choice the user has not made yet.
  for (int face = 1; face <= 6; face++)
    drawCell(face, !touchNeedsSelect && face == currentFace);

  tft.setTextSize(1);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(10, 146);
  tft.println("Tap a number, then tap it again to confirm");
  tft.setCursor(10, 156);
  tft.println("Buttons still work.  BTN2 hold: previous roll");
}

void drawRolling() {
  if (dstouch::detected()) { drawRollingTouch(); return; }

  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.printf("Roll %d / %d\n", currentRollIndex + 1, rollsNeeded);

  tft.setTextSize(6);
  // White until a face has actually been chosen, green once chosen -- the
  // same white->green language as the touch grid's cells. Always-green is
  // what made the unselected default look confirmed (changed in v2.3.1).
  tft.setTextColor(touchNeedsSelect ? TFT_WHITE : TFT_GREEN, TFT_BLACK);
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
    tft.println("BTN2 tap: verify backup");
  }
  tft.setCursor(10, 142);
  tft.println("BTN1 tap: show raw entropy (hex)");
  tft.setCursor(10, 155);
  tft.println("Hold BOTH buttons 2s: WIPE + reset");
}

// Fills verifyWordNums with 3 checkpoint word numbers (1-based), spread
// roughly beginning/middle/end regardless of word count, so the check
// works the same shape whether the mnemonic is 12 or 24 words. Fixed
// absolute numbers like "3, 8, 12" only make sense for one word count;
// these are proportional (~25%/60%/90%) and rounded to the nearest word
// with integer math (n*pct+50)/100, which matches round-to-nearest --
// e.g. 12 words -> 3, 7, 11; 24 words -> 6, 14, 22.
void pickVerifyWords() {
  const int pct[3] = { 25, 60, 90 };
  for (int i = 0; i < 3; i++) {
    int n = (wordCount * pct[i] + 50) / 100;
    if (n < 1) n = 1;
    if (n > wordCount) n = wordCount;
    verifyWordNums[i] = (uint8_t)n;
  }
}

// Fills out[0]/out[1] with two DECOY word indices into BIP39_WORDS --
// distinct from each other, from the correct word, and from every OTHER
// word already in this mnemonic (so a decoy never happens to be one of
// your other real words, which would be needlessly confusing). Uses the
// chip's hardware RNG (esp_random()) purely to choose which WRONG words to
// display: this is NOT part of the entropy/mnemonic path in any way, and
// unlike WiFi.mode() (see the v1.1.0 history above), esp_random() is
// confirmed to have no side effects on other subsystems -- it never
// touches the radio or NVS, and always returns usable output (worst case
// "pseudo-random only" quality with no RF active, which is completely
// fine here: a decoy just needs to be a different word, not unpredictable
// in any cryptographic sense).
void pickDecoyIndices(const char* correctWord, uint16_t out[2]) {
  for (int slot = 0; slot < 2; slot++) {
    uint16_t candidate;
    bool ok;
    do {
      candidate = esp_random() % 2048;
      ok = (strcmp(BIP39_WORDS[candidate], correctWord) != 0);
      if (ok && slot == 1 && candidate == out[0]) ok = false;
      for (int i = 0; ok && i < wordCount; i++) {
        if (strcmp(BIP39_WORDS[candidate], mnemonicWords[i]) == 0) ok = false;
      }
    } while (!ok);
    out[slot] = candidate;
  }
}

// Sets up one verify checkpoint: picks 2 decoys, places the real word in a
// randomly chosen slot among 3, and starts the display on a random slot
// too (so there's no learnable "the answer is always slot 1" pattern).
void startVerifyStep() {
  const char* correctWord = mnemonicWords[verifyWordNums[verifyStep] - 1];
  uint16_t decoys[2];
  pickDecoyIndices(correctWord, decoys);

  verifyCorrectSlot = esp_random() % 3;
  int d = 0;
  for (int slot = 0; slot < 3; slot++) {
    const char* word = (slot == verifyCorrectSlot) ? correctWord : BIP39_WORDS[decoys[d++]];
    strncpy(verifyChoices[slot], word, 15);
    verifyChoices[slot][15] = '\0';
  }
  verifyChoiceIdx = esp_random() % 3;
  verifyAnswered = false;
  drawVerifyPicking();
}

// A blind multiple-choice pick, not a "here's the answer, compare it
// yourself" re-display: the word list is gone, and this is the one
// candidate currently selected out of 3 (1 real, 2 decoys). This is what
// catches "I misread the word the first time and wrote down the wrong
// one confidently" -- the earlier re-display design could only catch
// "I copied it correctly, let me double check," which is a materially
// weaker guarantee (this is the exact tradeoff Justin's BTC group flagged
// after testing v2.1.0's original re-display version on real hardware).
void drawVerifyPicking() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_CYAN, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 5);
  tft.print("Verify backup (");
  tft.print(verifyStep + 1);
  tft.print("/3)");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setCursor(10, 35);
  tft.print("Word #");
  tft.print(verifyWordNums[verifyStep]);
  tft.println(" was:");
  tft.setTextSize(3);
  tft.setTextColor(TFT_GREEN, TFT_BLACK);
  tft.setCursor(10, 75);
  tft.print(verifyChoices[verifyChoiceIdx]);
  tft.setTextSize(1);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(10, 130);
  tft.println("Pick the word you actually wrote down.");
  tft.setCursor(10, 142);
  tft.println("BTN1: cycle choices   BTN2: select this one");
  tft.setCursor(10, 155);
  tft.println("Hold BOTH buttons 2s: WIPE + reset");
}

void drawVerifyResult() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(10, 5);
  if (verifyWasCorrect) {
    tft.setTextColor(TFT_GREEN, TFT_BLACK);
    tft.println("Correct!");
  } else {
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.println("Not quite --");
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setCursor(10, 35);
    tft.print("word #");
    tft.print(verifyWordNums[verifyStep]);
    tft.print(" was ");
    tft.println(verifyChoices[verifyCorrectSlot]);
  }
  tft.setTextSize(1);
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setCursor(10, 142);
  tft.println(verifyStep + 1 < 3 ? "BTN2 tap: next check" : "BTN2 tap: back to word list");
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

// Shared wipe-and-reboot path (v2.3.2): used by the result screen's
// two-button hold and the leave-rolling confirm's Wipe choice. GPIO0
// (BTN1) is the ESP32-S3's boot-strapping pin: if it is still held LOW
// when the chip resets, it boots into the ROM download bootloader instead
// of this sketch (black screen, stuck in bootloader over USB) -- hence
// the wait for both buttons to be physically released before resetting.
// The reboot lands on the menu, which also re-runs setup()'s boot-time
// RAM scrub.
static void wipeAndRestart() {
  screen = SCR_WIPE_CONFIRM;
  drawWipeConfirm();
  scrubSensitiveRAM();
  while (digitalRead(PIN_BUTTON_1) == LOW || digitalRead(PIN_BUTTON_2) == LOW) {
    delay(20);
  }
  delay(300); // let the pin settle high before the reset samples it
  esp_restart();
}

// A BTN2 short press with no face chosen must not commit: after
// startRolling() and after every commit, currentFace resets to 1, so
// committing the unshown default would silently record a roll the user
// never made -- the "entropy only from rolls you enter" violation issue
// #2 tracks. Flash the reason in red instead of silently ignoring the
// press; a plain no-op would read as a dead button. Works for both
// layouts -- drawRolling() re-dispatches to whichever one is active.
static void rollRefuseCommit() {
  tft.setTextSize(1);
  tft.setTextColor(TFT_RED, TFT_BLACK);
  tft.setCursor(10, dstouch::detected() ? 146 : 145);
  tft.print("Select a face first (BTN1 or tap), then confirm  ");
  delay(800);
  drawRolling();
}

// Commits the currently shown face as the next roll. Extracted verbatim from
// the BTN2 handler so the touch path commits through exactly the same code --
// duplicating the entropy-derivation block for a second caller would be the
// real risk here.
void confirmCurrentRoll() {
  touchNeedsSelect = true;  // the only line added to the extracted body
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
    verifying = false;
    verifyStep = 0;
    pickVerifyWords();
    screen = SCR_RESULT;
    drawResult();
  } else {
    drawRolling();
  }
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

  // Probe for a touch panel. A non-touch board simply does not answer, and
  // everything falls back to the buttons -- which are the floor on every
  // board, touch or not.
  dstouch::begin();

  drawMenu();
}

void loop() {
  switch (screen) {
    case SCR_MENU: {
      if (dstouch::detected()) {
        int tx, ty;
        if (dstouch::tapped(tx, ty)) {
          int c = menuCellAtPoint(tx, ty);
          // First tap lights a cell; a second tap on the SAME cell starts.
          // Same two-tap rule as the roll grid: a mis-tap must not start a
          // 50/99-roll session by accident, and "green = another tap here
          // commits" stays the touch language on every screen.
          if (c >= 0) {
            if (menuNeedsSelect || c != menuChoice) {
              menuChoice = c;
              menuNeedsSelect = false;
              drawMenu();
            } else {
              startRolling();
              drawRolling();
            }
          }
        }
      }
      if (button1Pressed()) {
        menuChoice = 1 - menuChoice;
        menuNeedsSelect = false;  // BTN1 is a choice; light it on the grid
        drawMenu();
      }
      int ev = button2Event();
      if (ev == 1) {
        // On a Touch board BTN2 does not start with nothing selected: the
        // cells show no default, so committing the hidden menuChoice=0
        // would be an invisible default -- the exact flaw issue #2 tracks
        // on the roll screen, refused here. Non-touch boards keep the
        // documented contract: the `>` marker shows what BTN2 will start.
        if (dstouch::detected() && menuNeedsSelect) {
          menuRefuseStart();
        } else {
          startRolling();
          drawRolling();
        }
      }
      break;
    }

    case SCR_ROLLING: {
      if (dstouch::detected()) {
        int tx, ty;
        if (dstouch::tapped(tx, ty)) {
          int f = faceAtPoint(tx, ty);
          // First tap selects (and lights that cell's border); a second tap on
          // the SAME cell commits. Deliberately not commit-on-first-tap: a
          // mis-tap would otherwise write a wrong roll with no warning.
          if (f != 0 && (touchNeedsSelect || f != currentFace)) {
            currentFace = f;
            touchNeedsSelect = false;
            drawRolling();
          } else if (f != 0) {
            confirmCurrentRoll();
          }
        }
      }
      // ---- Raw button handling (see the rollBtn* comment block above) --
      // Decisions at RELEASE, voided if the other button joined; the
      // two-button hold is checked first so its trigger can never be
      // accompanied by a single-button side effect.
      bool b1 = (digitalRead(PIN_BUTTON_1) == LOW);
      bool b2 = (digitalRead(PIN_BUTTON_2) == LOW);

      // Two-button hold: 2s opens the leave-rolling confirm (issue #3).
      // The release is debounced (150ms) like the result screen's wipe
      // hold -- GPIO0 also carries the boot-strap role and is noisier
      // than a plain GPIO.
      if (b1 && b2) {
        rollBothUpSince = 0;
        if (rollBothDownSince == 0) rollBothDownSince = millis();
        if (millis() - rollBothDownSince >= 2000) {
          rollBothDownSince = 0;
          resetNeedsSelect = true;
          resetChoice = 0;
          screen = SCR_RESET_CONFIRM;
          drawResetConfirm();
          break;
        }
      } else if (rollBothDownSince != 0) {
        if (rollBothUpSince == 0) rollBothUpSince = millis();
        if (millis() - rollBothUpSince >= 150) {
          rollBothDownSince = 0;
          rollBothUpSince = 0;
        }
      }

      // BTN1: reveal/advance, but only if released as a pure tap.
      if (b1 && !rollBtn1WasDown) rollBtn1PureTap = true;
      if (b1 && b2) rollBtn1PureTap = false;
      if (!b1 && rollBtn1WasDown && rollBtn1PureTap) {
        // First press REVEALS the current face (1 after start/commit)
        // rather than advancing past it: nothing is lit, so stepping to
        // 2 on the first press would make face 1 reachable only by
        // wrapping all the way around -- six presses for a rolled 1.
        // Reveal-then-advance means a roll of N costs exactly N presses.
        if (touchNeedsSelect) {
          touchNeedsSelect = false;  // light what's there; don't advance
        } else {
          currentFace = (currentFace % 6) + 1;
        }
        drawRolling();
      }
      rollBtn1WasDown = b1;

      // BTN2: short = commit (gated, v2.3.1), long = back one roll --
      // only if released as a pure press, so an abandoned two-button
      // hold can never fire a spurious go-back.
      if (b2 && !rollBtn2WasDown) {
        rollBtn2DownAt = millis();
        rollBtn2PurePress = true;
      }
      if (b1 && b2) rollBtn2PurePress = false;
      if (!b2 && rollBtn2WasDown && rollBtn2PurePress) {
        unsigned long held = millis() - rollBtn2DownAt;
        if (held >= 800) {
          if (currentRollIndex > 0) {
            currentRollIndex--;
            currentFace = rolls[currentRollIndex];
            rolls[currentRollIndex] = 0;
            touchNeedsSelect = false;  // the restored value is a real choice
            drawRolling();
          }
        } else {
          // v2.3.1: BTN2 cannot commit a roll nobody chose. With no
          // selection the internal currentFace is the post-commit reset
          // value (1) -- committing it would record a value the user
          // never entered, silently. Refused with feedback, never a no-op.
          if (touchNeedsSelect) {
            rollRefuseCommit();
          } else {
            confirmCurrentRoll();
          }
        }
      }
      rollBtn2WasDown = b2;
      break;
    }

    case SCR_RESULT: {
      bool b1 = (digitalRead(PIN_BUTTON_1) == LOW);
      bool b2 = (digitalRead(PIN_BUTTON_2) == LOW);
      if (b1 && b2) {
        bothUpSince = 0; // solidly down again; cancel any pending release
        if (bothDownSince == 0) bothDownSince = millis();
        if (millis() - bothDownSince >= 2000) {
          // Shared wipe path (v2.3.2) -- same sequence the leave-rolling
          // confirm uses; behavior identical to when this was inline.
          wipeAndRestart();
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
      // While actively picking an answer (verifying && !verifyAnswered),
      // BTN1 cycles the displayed choice instead of its usual meaning --
      // it's only ever "open the entropy view" outside that one state.
      bool picking = verifying && !verifyAnswered;
      if (b1 && !btn1WasDown) btn1PureTap = true;   // BTN1 just went down
      if (b1 && b2) btn1PureTap = false;            // BTN2 joined -> not a tap
      if (!b1 && btn1WasDown && btn1PureTap) {      // BTN1 just released, clean
        if (picking) {
          verifyChoiceIdx = (verifyChoiceIdx + 1) % 3;
          drawVerifyPicking();
        } else {
          verifying = false; // leaving the verify quiz if we were mid-pass
          showingEntropy = !showingEntropy;
          showingEntropy ? drawEntropy() : drawResult();
        }
      }
      btn1WasDown = b1;

      int ev = button2Event();
      if (ev == 1 && !showingEntropy) {
        if (verifying && !verifyAnswered) {
          // Lock in the currently-displayed choice.
          verifyAnswered = true;
          verifyWasCorrect = (verifyChoiceIdx == verifyCorrectSlot);
          drawVerifyResult();
        } else if (verifying) {
          // Already showed right/wrong -- move to the next checkpoint,
          // or finish the quiz and return to the word list.
          verifyStep++;
          if (verifyStep >= 3) {
            verifying = false;
            resultPage = 0;
            drawResult();
          } else {
            startVerifyStep();
          }
        } else {
          int perPage = 4;
          int totalPages = (wordCount + perPage - 1) / perPage;
          if (resultPage + 1 < totalPages) {
            resultPage++;
            drawResult();
          } else {
            // Last word page -- verify before wrapping back to page 1,
            // instead of just wrapping straight away.
            verifying = true;
            verifyStep = 0;
            startVerifyStep();
          }
        }
      }
      break;
    }

    case SCR_RESET_CONFIRM: {
      // Just entered via a 2s hold: both buttons are still physically
      // down. Ignore ALL input until they are released, so the shared
      // helpers' edge state (shaped by the hold's press and release) can
      // never leak into this screen's decisions.
      if (digitalRead(PIN_BUTTON_1) == LOW || digitalRead(PIN_BUTTON_2) == LOW) {
        break;
      }

      if (dstouch::detected()) {
        int tx, ty;
        if (dstouch::tapped(tx, ty)) {
          int c = menuCellAtPoint(tx, ty);
          // Same two-tap rule as the menu: first tap lights a cell, a
          // second tap on that cell commits it. Misses are ignored.
          if (c >= 0) {
            if (resetNeedsSelect || c != resetChoice) {
              resetChoice = c;
              resetNeedsSelect = false;
              drawResetConfirm();
            } else if (resetChoice == 0) {
              screen = SCR_ROLLING;  // rolls untouched
              drawRolling();
            } else {
              wipeAndRestart();
            }
          }
        }
      }
      if (button1Pressed()) {
        resetChoice = 1 - resetChoice;
        resetNeedsSelect = false;  // BTN1 is a choice; light it
        drawResetConfirm();
      }
      int ev = button2Event();
      if (ev == 1) {
        // Touch boards: refuse with feedback until a choice exists (same
        // rule as the menu). Non-touch boards commit the shown option --
        // the `>` marker always displays what BTN2 will do.
        if (dstouch::detected() && resetNeedsSelect) {
          tft.setTextSize(1);
          tft.setTextColor(TFT_RED, TFT_BLACK);
          tft.setCursor(10, 138);
          tft.print("Select an option first (tap or BTN1) ");
          delay(800);
          drawResetConfirm();
        } else if (resetChoice == 0) {
          screen = SCR_ROLLING;  // rolls untouched
          drawRolling();
        } else {
          wipeAndRestart();
        }
      }
      break;
    }

    case SCR_WIPE_CONFIRM:
      // esp_restart() already fired; nothing to do here.
      break;
  }
}
