# DiceSeed roadmap

Known-worth-doing work, roughly in priority order. Nothing here has a
release date — this is the "not done yet, but on the radar" list. Each item
came out of asking what an experienced firmware dev or a security-minded
Bitcoin user would push back on, and taking the pushback seriously.

## 1. Runtime build-mode toggle

Switching between the **compat** and **classic** entropy derivations (see
the README's *Build variants* section) currently means editing
`build_mode.h` and reflashing, which requires a working Arduino toolchain.
Fine for a maintainer keeping several boards in sync; needless friction for
an end user, and the kind of thing that makes a security tool look like a
dev artifact rather than a finished device.

**Plan:** move `DICESEED_COMPAT_BUILD` from a compile-time flag to a choice
on the start-menu screen, defaulting to compat, with the active mode shown
on the result screen next to the version string. The two derivations
already differ by exactly one function, so both paths get compiled in and
selected at runtime.

**Tradeoff accepted:** one binary then carries both derivations, slightly
enlarging the per-build audit surface. Judged worth it — both paths already
live in the repo and are already tested, so "review both" is already the
reality; the flag only ever decided which one shipped. Keep the
compile-time flag working as an override, so a single-path build stays
possible for anyone who wants the smaller surface.

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

## 4. Explicit threat-model / "what this is for" section in the README

Consolidate things the README already says in scattered places into one
honest paragraph a first-time reader sees *before* deciding to trust the
device:

- DiceSeed is a **generator** — it makes a seed phrase from entropy you
  supply and can verify. It is not a signer and not a wallet.
- Intended flow: generate on battery power with no USB attached, write the
  phrase down, verify it (backup check + optional cross-check), then load
  it into a proper hardware signer for actual custody.
- It is **not** a substitute for a Coldcard / SeedSigner / Jade for holding
  funds. The USB-Serial-JTAG peripheral can dump RAM (already in the
  Security model section); a device that stores nothing and signs nothing
  is a smaller target only because it does less.
- The radios: the ESP32-S3 has WiFi/BT silicon physically present. This
  firmware never initializes either — but "no radio in the firmware" is not
  "no radio on the board," and someone who needs the latter wants a
  different device.
