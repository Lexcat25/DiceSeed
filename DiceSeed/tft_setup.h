// LilyGO T-Display S3 TFT_eSPI configuration.
//
// TFT_eSPI does NOT autodetect what it's wired to -- it needs driver/pin
// #defines supplied before its own setup selection runs. This exact
// filename is TFT_eSPI's OWN documented mechanism for that, not a
// workaround: TFT_eSPI.h does `#if __has_include(<tft_setup.h>)` and
// auto-includes a sketch-local file with this exact name before falling
// back to its shared, installation-wide User_Setup_Select.h (see
// TFT_eSPI.h's own "Sketch_with_tft_setup" comment/example). That shared
// file lives OUTSIDE this repo, wherever TFT_eSPI happens to be installed
// on a given machine -- easy to lose on a fresh Arduino IDE install or
// forget to redo -- so keeping the real config here, in git, is what
// makes a fresh clone actually reproducible.
//
// Values are TFT_eSPI's own bundled setup for this exact board --
// User_Setups/Setup206_LilyGo_T_Display_S3.h (TFT_eSPI v2.5.43) --
// reproduced verbatim. Notably this is ST7789 over an 8-bit PARALLEL bus,
// not SPI: without this file, TFT_eSPI's own out-of-the-box default
// (User_Setup.h) configures an ILI9341 driver on ESP8266 NodeMCU SPI
// pins, which shares no pins or protocol with this board at all. That
// default compiles cleanly -- it does not fail the build -- it just
// drives nothing, silently, on real hardware. Verified (2026-08-25) by
// compiling both ways against esp32:esp32@3.3.11 + TFT_eSPI@2.5.43: the
// default state before this file existed silently resolved to
// ILI9341_DRIVER on PIN_D3-D8; with this file, TFT_WIDTH/TFT_HEIGHT and
// the pin defines below are the ones actually compiled in.
#pragma once

#define USER_SETUP_LOADED 1
#define USER_SETUP_ID 206

#define ST7789_DRIVER
#define INIT_SEQUENCE_3 // Using this initialisation sequence improves the display image

#define CGRAM_OFFSET
#define TFT_RGB_ORDER TFT_RGB  // Colour order Red-Green-Blue

#define TFT_INVERSION_ON

#define TFT_PARALLEL_8_BIT

#define TFT_WIDTH 170
#define TFT_HEIGHT 320

#define TFT_CS  6
#define TFT_DC  7
#define TFT_RST 5

#define TFT_WR 8
#define TFT_RD 9

#define TFT_D0 39
#define TFT_D1 40
#define TFT_D2 41
#define TFT_D3 42
#define TFT_D4 45
#define TFT_D5 46
#define TFT_D6 47
#define TFT_D7 48

#define TFT_BL 38
#define TFT_BACKLIGHT_ON HIGH

#define LOAD_GLCD
#define LOAD_FONT2
#define LOAD_FONT4
#define LOAD_FONT6
#define LOAD_FONT7
#define LOAD_FONT8
#define LOAD_GFXFF

#define SMOOTH_FONT
