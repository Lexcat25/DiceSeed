// Build variant selector -- the ONLY thing that differs between the two
// DiceSeed firmware builds. Defaults to the SeedSigner-compatible entropy
// method (the point of a local BTC group standardizing on a device is
// cross-checkable output, and that should be what people get without
// touching anything). Set to 0 and recompile for the original hand-
// auditable bignum method instead. See README.md "Build variants" for what
// each buys you and why they're mutually exclusive (a single roll sequence
// can't be both hand-computable AND bit-identical to a SHA-256-based tool).
//
// arduino-cli: pass -DDICESEED_COMPAT_BUILD=0 via
//   --build-property "build.extra_flags=-DDICESEED_COMPAT_BUILD=0"
// instead of editing this file, if you'd rather not touch tracked source
// to switch variants for a one-off build.
#pragma once

#ifndef DICESEED_COMPAT_BUILD
#define DICESEED_COMPAT_BUILD 1
#endif
