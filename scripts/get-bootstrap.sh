#!/bin/bash
# Download Procursus bootstrap for ProjectSword
# Run this locally, then commit bootstrap.tar with Git LFS:
#   git lfs track bootstrap.tar
#   git add bootstrap.tar .gitattributes
#   git commit -m "Add Procursus bootstrap"
#
# Procursus releases: https://github.com/ProcursusTeam/Procursus/releases

set -e

BASE_URL="https://github.com/ProcursusTeam/Procursus/releases/download"
BOOTSTRAP_FILE="bootstrap-iphoneos-arm64e-rootless.tar.xz"
OUTPUT_FILE="ios18-research/ProjectSword/bootstrap.tar"

# Try multiple possible tags
for TAG in nightly v6.0 6.0; do
    URL="${BASE_URL}/${TAG}/${BOOTSTRAP_FILE}"
    echo "[*] Trying ${URL}..."
    HTTP_CODE=$(curl -L -o /tmp/bootstrap.tar.xz -w "%{http_code}" --silent "${URL}")
    if [ "${HTTP_CODE}" = "200" ]; then
        echo "[+] Downloaded from ${URL}"
        break
    fi
    echo "    (HTTP ${HTTP_CODE})"
done

if [ ! -f /tmp/bootstrap.tar.xz ] || [ "$(stat -f%z /tmp/bootstrap.tar.xz 2>/dev/null || stat --format=%s /tmp/bootstrap.tar.xz 2>/dev/null)" -lt 1000 ]; then
    echo "[-] Failed to download bootstrap from any known URL."
    echo "[-] Go to https://github.com/ProcursusTeam/Procursus/releases"
    echo "    download ${BOOTSTRAP_FILE} manually, then:"
    echo "    xz -d -c bootstrap-iphoneos-arm64e-rootless.tar.xz > ${OUTPUT_FILE}"
    exit 1
fi

echo "[*] Extracting xz -> tar..."
xz -d -c /tmp/bootstrap.tar.xz > "${OUTPUT_FILE}"
rm -f /tmp/bootstrap.tar.xz

echo "[+] Bootstrap saved to ${OUTPUT_FILE} ($(ls -lh "${OUTPUT_FILE}" | awk '{print $5}'))"
echo ""
echo "Now commit it:"
echo "  git lfs track '${OUTPUT_FILE}'"
echo "  git add ${OUTPUT_FILE} .gitattributes"
echo "  git commit -m 'Add Procursus bootstrap'"
echo "  git push"
