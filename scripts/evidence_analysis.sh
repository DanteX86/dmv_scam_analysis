#!/bin/bash

# Evidence Analysis Script for Scam Investigation
# Usage: ./evidence_analysis.sh [file_path]

FILE=$1

if [ -z "$FILE" ]; then
    echo "Usage: $0 [file_path]"
    echo "Example: $0 suspicious_document.pdf"
    exit 1
fi

if [ ! -f "$FILE" ]; then
    echo "Error: File '$FILE' not found"
    exit 1
fi

echo "=== EVIDENCE ANALYSIS: $FILE ==="
echo "File: $(basename "$FILE")"
echo "Path: $(realpath "$FILE")"
echo "Size: $(ls -lh "$FILE" | awk '{print $5}')"
echo "Modified: $(stat -f "%Sm" "$FILE")"
echo

echo "=== FILE TYPE ANALYSIS ==="
file "$FILE"
echo

echo "=== METADATA EXTRACTION ==="
exiftool "$FILE"
echo

echo "=== HASH ANALYSIS ==="
echo "MD5:    $(md5 -q "$FILE")"
echo "SHA1:   $(shasum -a 1 "$FILE" | cut -d' ' -f1)"
echo "SHA256: $(shasum -a 256 "$FILE" | cut -d' ' -f1)"
echo

echo "=== STRINGS ANALYSIS (first 50 strings) ==="
strings "$FILE" | head -50
echo

# If it's an image, check for steganography
if file "$FILE" | grep -qE "(JPEG|PNG|GIF|BMP)"; then
    echo "=== IMAGE ANALYSIS ==="
    echo "Checking for embedded data..."
    # Basic check for hidden data (would need additional tools for full stego analysis)
    hexdump -C "$FILE" | tail -20
fi
