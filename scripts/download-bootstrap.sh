#!/bin/bash
# Download Procursus bootstrap for ProjectSword
# This script downloads the latest Procursus bootstrap for rootless iOS 18

set -e

BOOTSTRAP_URL="https://github.com/ProcursusTeam/Procursus/releases/download/v6.0/bootstrap-iphoneos-arm64e-rootless.tar.xz"
OUTPUT_DIR="ios18-research/ProjectSword"
OUTPUT_FILE="${OUTPUT_DIR}/bootstrap.tar"

mkdir -p "${OUTPUT_DIR}"

if [ -f "${OUTPUT_FILE}" ]; then
    echo "[*] bootstrap.tar already exists, skipping download"
    exit 0
fi

echo "[*] Downloading Procursus bootstrap..."
curl -L -o /tmp/bootstrap.tar.xz "${BOOTSTRAP_URL}"

echo "[*] Extracting..."
xz -d -c /tmp/bootstrap.tar.xz > "${OUTPUT_FILE}"

echo "[+] Bootstrap saved to ${OUTPUT_FILE}"
ls -lh "${OUTPUT_FILE}"
