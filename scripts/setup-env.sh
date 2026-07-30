#!/bin/bash
# Setup environment for ProjectSword development
# Run on macOS with Xcode installed

set -e

echo "[*] Checking build requirements..."

# Check Xcode
if ! xcode-select -p &>/dev/null; then
    echo "[-] Xcode not found. Install Xcode 15+ from the App Store."
    exit 1
fi

# Check ldid
if ! command -v ldid &>/dev/null; then
    echo "[*] Installing ldid..."
    brew install ldid
fi

# Verify SDK
SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null || true)
if [ -z "${SDK_PATH}" ]; then
    echo "[-] iOS SDK not found. Ensure Xcode has iOS 18 SDK."
    echo "    Run: sudo xcode-select --switch /Applications/Xcode.app"
    exit 1
fi

echo "[+] iOS SDK: ${SDK_PATH}"

# Check bootstrap
if [ ! -f "bootstrap.tar" ]; then
    echo "[*] bootstrap.tar not found. Run 'scripts/get-bootstrap.sh' from the project root."
fi

echo "[+] Environment ready. Run 'cd ios18-research/ProjectSword && make ipa' to build."
