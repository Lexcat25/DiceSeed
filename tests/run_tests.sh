#!/usr/bin/env bash
# Builds and runs test_core.cpp in a throwaway container (debian + g++ +
# libmbedtls-dev). The devbox has no C toolchain installed, same reason
# erp/whistle build their tests in Docker rather than on the host.
set -euo pipefail
cd "$(dirname "$0")/.."

docker run --rm -v "$PWD:/w:ro" -w /w/tests debian:bookworm-slim bash -c '
  set -e
  apt-get update -qq
  apt-get install -y -qq g++ libmbedtls-dev >/dev/null
  g++ -std=c++17 -Wall -Wextra -I/usr/include -o /tmp/test_core test_core.cpp -lmbedtls -lmbedcrypto
  /tmp/test_core
'
