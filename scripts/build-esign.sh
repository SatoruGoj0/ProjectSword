#!/bin/bash
# Build ProjectSword IPA optimized for ESign on-device signing
# Usage: ./scripts/build-esign.sh
#
# This builds with LITE=1 (stripped entitlements) so ESign can sign
# with your developer certificate + provisioning profile.
#
# ESign steps after build:
# 1. Open ESign on iPhone
# 2. Import your .p12 certificate + .mobileprovision
# 3. Tap "Sign App" → select ProjectSword-lite.ipa
# 4. Sign with your imported certificate
# 5. Install

set -e
cd "$(dirname "$0")/.."
make LITE=1 ipa
mv ProjectSword.ipa ProjectSword-lite.ipa
echo "[+] ProjectSword-lite.ipa ready for ESign"
