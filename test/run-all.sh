#!/bin/sh
# Runs every Node test. Exit code is non-zero if any fail.
cd "$(dirname "$0")/.." || exit 1
status=0
for t in "test-ed25519.js" "test-github.js" "test-passphrase.js" "test-rsa.js" "test-mixed.js ed25519 p256 rsa"; do
  node test/$t || status=1
done
exit $status
