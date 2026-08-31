// Minimal CST816-family capacitive touch driver for the LilyGO
// T-Display-S3 *Touch* board.
//
// Deliberately hand-rolled rather than pulling in TouchLib: once the probe
// is a bare address ACK and a read is 7 bytes from register 0x00, a 300KB
// dependency buys nothing and widens the surface someone has to audit. Same
// reasoning that kept the compat/classic split to one flag in one codebase.
//
// Everything below was verified on real hardware (both board variants) on
// 2026-08-28 before this file was written:
//
//   * The controller ACKs at 0x15 (self-capacitance CST816/820/826). LilyGO
//     also ships boards with a CST328 at 0x1A, which this does NOT support --
//     such a board reports "no touch" and falls back to the buttons, which is
//     the correct degradation, not a failure.
//
//   * Presence MUST be detected by a bare address ACK. The chip sits in
//     standby until a touch event and does NOT answer a register read before
//     then, so probing its ID register (0xA7) reports "absent" on a perfectly
//     good panel. Confirmed: the ID read failed at boot while touch-data
//     reads succeeded the instant the screen was touched.
//
//   * Coordinates arrive in the panel's native 170x320 PORTRAIT frame, so
//     they need rotating for this sketch's setRotation(1) 320x170 landscape:
//         display_x = native_y
//         display_y = 169 - native_x
//     A clean 1:1 rotation with no scaling. Verified by tapping four corners
//     and then confirming a crosshair tracked a finger across the screen.
//
//   * The chip AUTO-SLEEPS AFTER 2 SECONDS of no touch (register 0xF9,
//     factory default), and while asleep it stops answering register reads --
//     the panel goes dead until it is woken. Register 0xFE disables that.
//     Found the hard way: touch worked, then went unresponsive after a pause.
//     The write is retried on the first read the chip does answer, because at
//     boot it may already be asleep and reject the write itself.
//
//   * Reads use a STOP between the register write and the read (
//     endTransmission(true)), not a repeated start. A repeated start that
//     fails mid-transaction leaves the bus without a STOP, which can wedge it
//     for good -- exactly the failure mode a sleeping chip triggers.
//
// The non-touch board answers nothing at all on the bus -- no hang, no
// phantom device -- which is what lets one binary serve both boards.
// Buttons are the floor everywhere; touch is purely additive.

#pragma once

#include <Arduino.h>
#include <Wire.h>
#include "driver/gpio.h"

namespace dstouch {

static const uint8_t ADDR      = 0x15;
static const int     PIN_SDA   = 18;
static const int     PIN_SCL   = 17;
static const int     PIN_RESET = 21;

static const int DISP_W = 320;  // landscape, after setRotation(1)
static const int DISP_H = 170;

static bool present = false;
static bool autoSleepOff = false;

inline bool detected() { return present; }

inline bool writeReg(uint8_t reg, uint8_t val) {
  Wire.beginTransmission(ADDR);
  Wire.write(reg);
  Wire.write(val);
  return Wire.endTransmission(true) == 0;
}

// Register 0xFE, any non-zero value = auto-sleep disabled. Costs ~1.6mA and
// buys a panel that is still listening after a pause.
inline void disableAutoSleep() {
  if (!autoSleepOff) autoSleepOff = writeReg(0xFE, 0x01);
}

// Call once from setup(), after the display is up. Leaves `present` false on
// a non-touch board, so every later call is a no-op there.
inline bool begin() {
  gpio_hold_dis((gpio_num_t)PIN_RESET);  // defensive; nothing here sets a hold
  pinMode(PIN_RESET, OUTPUT);
  digitalWrite(PIN_RESET, LOW);
  delay(500);
  digitalWrite(PIN_RESET, HIGH);
  delay(500);
  // 500/500ms are the timings actually verified on hardware. TouchLib uses
  // 200/200 and probably works, but this runs once per boot and there is no
  // reason to shave 600ms off it in exchange for using unverified numbers.

  Wire.begin(PIN_SDA, PIN_SCL);
  Wire.beginTransmission(ADDR);
  present = (Wire.endTransmission() == 0);
  if (present) disableAutoSleep();
  return present;
}

// True while a finger is down; x/y are display coordinates.
inline bool read(int &x, int &y) {
  if (!present) return false;
  uint8_t d[7];
  Wire.beginTransmission(ADDR);
  Wire.write((uint8_t)0x00);
  if (Wire.endTransmission(true) != 0) return false;
  if (Wire.requestFrom((int)ADDR, 7) != 7) return false;
  for (int i = 0; i < 7; i++) d[i] = Wire.read();

  // It answered, so it is awake right now -- the one moment the auto-sleep
  // write can land if it was rejected at boot.
  if (!autoSleepOff) disableAutoSleep();

  if ((d[2] & 0x0F) == 0) return false;  // no fingers reported

  int nx = ((d[3] & 0x0F) << 8) | d[4];
  int ny = ((d[5] & 0x0F) << 8) | d[6];
  x = constrain(ny, 0, DISP_W - 1);
  y = constrain((DISP_H - 1) - nx, 0, DISP_H - 1);
  return true;
}

// Fires once per finger-down. Requires a release before it can fire again,
// so a held finger cannot repeat, and ignores contact bounce.
inline bool tapped(int &x, int &y) {
  static bool wasDown = false;
  static unsigned long lastTapAt = 0;
  int tx = 0, ty = 0;
  bool down = read(tx, ty);
  bool hit = (down && !wasDown);
  wasDown = down;
  if (hit) {
    if (millis() - lastTapAt < 150) return false;  // bounce
    lastTapAt = millis();
    x = tx;
    y = ty;
    return true;
  }
  return false;
}

}  // namespace dstouch
