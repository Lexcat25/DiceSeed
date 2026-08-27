# DiceSeed roadmap

Known-worth-doing work, roughly in priority order. Nothing here has a
release date — this is the "not done yet, but on the radar" list. Each item
came out of asking what an experienced firmware dev or a security-minded
Bitcoin user would push back on, and taking the pushback seriously.

## 1. Runtime build-mode toggle — OPEN QUESTION, not yet decided

Switching between the **compat** and **classic** entropy derivations (see
the README's *Build variants* section) currently means editing
`build_mode.h` and reflashing, which requires a working Arduino toolchain.

**This is deliberately parked pending a decision by the project's Bitcoin
group** — there are two defensible positions and it's a judgement call about
what the device is for, not a technical problem to solve. Both are recorded
here so whoever decides has the actual argument in front of them.

**The case for a runtime toggle:** requiring an Arduino toolchain to switch
modes is needless friction for an end user, and reads as dev artifact rather
than finished device. Most people expect "flash once, pick the mode in the
UI." Implementation would move `DICESEED_COMPAT_BUILD` to a start-menu
choice defaulting to compat, with the active mode displayed on the result
screen next to the version string, and the compile-time flag kept as an
override for anyone wanting a single-path build.

**The case for keeping it compile-time:** with one binary carrying both
derivations, the *same dice rolls can produce a different mnemonic*
depending on which menu option was selected that session — on a device whose
entire value proposition is that the same input always gives the same
output. Compile-time means one physical device has exactly one permanent,
verifiable behavior, and the on-screen version string
(`vX.Y.Z-compat` / `-classic`) is an unambiguous record of what that device
does. A runtime menu trades that guarantee for convenience. Showing the
active mode on the result screen mitigates this but does not eliminate it.

**Also weigh:** one binary carrying both paths slightly enlarges the
per-build audit surface — though both paths already live in the repo and are
already tested, so "review both" is arguably already the reality; the flag
only ever decided which one shipped.

## 2. Reproducible builds + published binary hashes

Someone who can't or won't compile from source has no way today to confirm
that a flashed `.bin` matches the published source. The established
airgapped-signing projects (SeedSigner, Krux) treat this as core, not
polish.

**Plan:**
- Pin the whole toolchain — exact `arduino-cli`, `esp32` core (3.3.11),
  `TFT_eSPI` (2.5.43) — and document it in `docs/reproducible-build.md`.
- Provide a scripted build in the same throwaway-Docker style as
  `tests/run_tests.sh`, producing a byte-identical `.bin` for a given tag
  on any machine.
- Publish the SHA-256 of each release `.bin` in the release notes and in
  the repo.

## 3. Signed releases

**Plan:** PGP-sign git tags and release artifacts; publish the signing-key
fingerprint in the README and out-of-band (the BTC group's own channels).
With item 2, this lets someone verify "this binary is what the maintainer
built from this reviewed source" without trusting GitHub's infrastructure
or their own toolchain.

## 4. Explicit threat-model / "what this is for" section in the README — DONE (2026-08-27)

Added as *What DiceSeed is for (and what it isn't)*, near the top of the
README: generator not signer/wallet, the battery-power intended flow, the
JTAG RAM-dump caveat, and the radios-are-on-the-board-even-if-not-in-the-
firmware point — consolidated from things the README already said in
scattered places.
