#!/usr/bin/env bash
# gen-placeholder-icon.sh — generate a simple placeholder cat-face .icns for Disk Arcana.
#
# This script produces a recognizable cat silhouette using ImageMagick and the
# macOS `iconutil` tool. The result is committed to crates/disk-gui/assets/.
# Replace the output files with final artwork when ready.
#
# Prerequisites: ImageMagick (magick/convert) + macOS iconutil (bundled with Xcode CLI tools)
# Usage: bash scripts/gen-placeholder-icon.sh [output_dir]
#   output_dir defaults to crates/disk-gui/assets/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${1:-${REPO_ROOT}/crates/disk-gui/assets}"

command -v magick >/dev/null 2>&1 || { echo "ERROR: ImageMagick (magick) not found." >&2; exit 1; }
command -v iconutil >/dev/null 2>&1 || { echo "ERROR: iconutil not found (requires macOS with Xcode CLI tools)." >&2; exit 1; }

TMPDIR_ICON="$(mktemp -d)"
ICONSET="${TMPDIR_ICON}/disk-arcana.iconset"
mkdir -p "${ICONSET}"

generate_cat_png() {
  local size="$1"
  local out="$2"
  local half_stroke=$(( size / 64 > 1 ? size / 64 : 1 ))
  local thin_stroke=$(( size / 128 > 1 ? size / 128 : 1 ))

  magick -size "${size}x${size}" canvas:'#1a1a2e' \
    \( -size "${size}x${size}" canvas:none \
       -fill '#e8d5b0' -stroke none \
       -draw "ellipse $((size*50/100)) $((size*55/100)) $((size*36/100)) $((size*33/100)) 0 360" \
       -fill '#e8d5b0' \
       -draw "polygon $((size*18/100)),$((size*28/100)) $((size*10/100)),$((size*8/100)) $((size*34/100)),$((size*18/100))" \
       -fill '#e8d5b0' \
       -draw "polygon $((size*82/100)),$((size*28/100)) $((size*90/100)),$((size*8/100)) $((size*66/100)),$((size*18/100))" \
       -fill '#f4a0a0' \
       -draw "polygon $((size*21/100)),$((size*26/100)) $((size*15/100)),$((size*13/100)) $((size*32/100)),$((size*21/100))" \
       -fill '#f4a0a0' \
       -draw "polygon $((size*79/100)),$((size*26/100)) $((size*85/100)),$((size*13/100)) $((size*68/100)),$((size*21/100))" \
       -fill '#2d5016' \
       -draw "ellipse $((size*36/100)) $((size*46/100)) $((size*8/100)) $((size*6/100)) 0 360" \
       -fill '#88cc44' \
       -draw "ellipse $((size*36/100)) $((size*46/100)) $((size*7/100)) $((size*5/100)) 0 360" \
       -fill '#111111' \
       -draw "ellipse $((size*36/100)) $((size*46/100)) $((size*3/100)) $((size*5/100)) 0 360" \
       -fill white \
       -draw "ellipse $((size*38/100)) $((size*44/100)) $((size*1/100)) $((size*1/100)) 0 360" \
       -fill '#2d5016' \
       -draw "ellipse $((size*64/100)) $((size*46/100)) $((size*8/100)) $((size*6/100)) 0 360" \
       -fill '#88cc44' \
       -draw "ellipse $((size*64/100)) $((size*46/100)) $((size*7/100)) $((size*5/100)) 0 360" \
       -fill '#111111' \
       -draw "ellipse $((size*64/100)) $((size*46/100)) $((size*3/100)) $((size*5/100)) 0 360" \
       -fill white \
       -draw "ellipse $((size*66/100)) $((size*44/100)) $((size*1/100)) $((size*1/100)) 0 360" \
       -fill '#ff9999' \
       -draw "polygon $((size*50/100)),$((size*60/100)) $((size*46/100)),$((size*57/100)) $((size*54/100)),$((size*57/100))" \
       -fill none -stroke '#c08060' -strokewidth "${half_stroke}" \
       -draw "path 'M $((size*50/100)),$((size*60/100)) Q $((size*44/100)),$((size*65/100)) $((size*40/100)),$((size*63/100))'" \
       -draw "path 'M $((size*50/100)),$((size*60/100)) Q $((size*56/100)),$((size*65/100)) $((size*60/100)),$((size*63/100))'" \
       -fill none -stroke '#c8b89a' -strokewidth "${thin_stroke}" \
       -draw "line $((size*10/100)),$((size*58/100)) $((size*44/100)),$((size*60/100))" \
       -draw "line $((size*10/100)),$((size*62/100)) $((size*44/100)),$((size*62/100))" \
       -draw "line $((size*10/100)),$((size*66/100)) $((size*44/100)),$((size*64/100))" \
       -draw "line $((size*90/100)),$((size*58/100)) $((size*56/100)),$((size*60/100))" \
       -draw "line $((size*90/100)),$((size*62/100)) $((size*56/100)),$((size*62/100))" \
       -draw "line $((size*90/100)),$((size*66/100)) $((size*56/100)),$((size*64/100))" \
    \) -composite \
    "${out}"
}

echo "Generating cat-face PNGs..."

for size in 16 32 128 256 512; do
  generate_cat_png "${size}" "${ICONSET}/icon_${size}x${size}.png"
  echo "  icon_${size}x${size}.png"
done

for size in 32 64 256 512 1024; do
  half=$((size / 2))
  generate_cat_png "${size}" "${ICONSET}/icon_${half}x${half}@2x.png"
  echo "  icon_${half}x${half}@2x.png (actual ${size}x${size})"
done

echo "Converting iconset to .icns..."
iconutil -c icns "${ICONSET}" -o "${TMPDIR_ICON}/disk-arcana.icns"

FILESIZE=$(stat -f%z "${TMPDIR_ICON}/disk-arcana.icns" 2>/dev/null || stat -c%s "${TMPDIR_ICON}/disk-arcana.icns")
echo "Generated: ${TMPDIR_ICON}/disk-arcana.icns (${FILESIZE} bytes)"

cp "${TMPDIR_ICON}/disk-arcana.icns" "${OUTPUT_DIR}/disk-arcana.icns"
cp "${TMPDIR_ICON}/disk-arcana.icns" "${OUTPUT_DIR}/disk-arcana-placeholder.icns"
rm -rf "${TMPDIR_ICON}"

echo "Copied to ${OUTPUT_DIR}/"
echo "Done. Replace with final artwork before shipping."
