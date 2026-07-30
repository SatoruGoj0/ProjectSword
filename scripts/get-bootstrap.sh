#!/bin/bash
# Download Procursus bootstrap for ProjectSword
# Source: https://github.com/opa334/Dopamine (download_bootstraps.sh)
# URL: https://apt.procurs.us/bootstraps/1900/bootstrap-iphoneos-arm64.tar.zst

set -e

OUTPUT_FILE="ios18-research/ProjectSword/bootstrap.tar"
TEMP_ZST="/tmp/bootstrap.tar.zst"
BOOTSTRAP_URL="https://apt.procurs.us/bootstraps/1900/bootstrap-iphoneos-arm64.tar.zst"

if [ -f "${OUTPUT_FILE}" ]; then
    echo "[*] bootstrap.tar already exists, skipping"
    exit 0
fi

echo "[*] Downloading from ${BOOTSTRAP_URL}..."
curl -L -o "${TEMP_ZST}" "${BOOTSTRAP_URL}"

echo "[*] Decompressing with zstd..."
if command -v zstd &>/dev/null; then
    zstd -d "${TEMP_ZST}" -c > "${OUTPUT_FILE}"
elif command -v zstdmt &>/dev/null; then
    zstdmt -d "${TEMP_ZST}" -c > "${OUTPUT_FILE}"
else
    echo "[-] zstd not found. Install with: brew install zstd"
    echo "    Or manually decompress: zstd -d ${TEMP_ZST} -o ${OUTPUT_FILE}"
    exit 1
fi

rm -f "${TEMP_ZST}"
echo "[+] Bootstrap saved: ${OUTPUT_FILE} ($(ls -lh "${OUTPUT_FILE}" | awk '{print $5}'))"
