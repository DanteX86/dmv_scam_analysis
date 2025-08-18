#!/usr/bin/env python3
"""
Fix unterminated string literals in Python files

This script finds and fixes common syntax errors like unterminated f-string literals
and print statements with missing closing quotes.
"""

import re
from pathlib import Path


def fix_unterminated_strings(file_path):
    """Fix common unterminated string patterns in a Python file"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        original_content = content

        # Pattern 1: print(f"\n{emoji} text") - fix f-strings split across lines
        content = re.sub(r'print\(f"(\n[^"]*)"', r'print(f"\\1")', content)

        # Pattern 2: print("\n{emoji} text") - fix regular strings split across lines
        content = re.sub(r'print\("(\n[^"]*)"', r'print("\\1")', content)

        # Pattern 3: return "\n{text}" - fix return statements
        content = re.sub(r'return "(\n[^"]*)"', r'return "\\1"', content)

        # Pattern 4: Fix specific f-string patterns
        content = re.sub(r"f\'\s*\n", "f'\\n", content)
        content = re.sub(r'f"\s*\n', 'f"\\n', content)

        # Pattern 5: Fix report = "=== text - multiline strings
        content = re.sub(r'report = "([^"]*)\n', r'report = "\1\\n', content)

        # Pattern 6: Fix "test - incomplete strings
        content = re.sub(r'^(\s*)"test\s*$', r'\1"test"', content, flags=re.MULTILINE)

        if content != original_content:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Fixed: {file_path}")
            return True
        else:
            return False

    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False


def find_and_fix_files():
    """Find all Python files and fix syntax errors"""
    fixed_count = 0
    error_files = []

    # Get all Python files in the current directory and subdirectories
    for path in Path(".").rglob("*.py"):
        if path.name == "fix_syntax.py":  # Skip this script itself
            continue

        try:
            if fix_unterminated_strings(path):
                fixed_count += 1
        except Exception as e:
            error_files.append((str(path), str(e)))

    print("\nSummary:")
    print(f"Files fixed: {fixed_count}")

    if error_files:
        print(f"Files with errors: {len(error_files)}")
        for file_path, error in error_files:
            print(f"  {file_path}: {error}")

    return fixed_count


if __name__ == "__main__":
    print("Starting syntax fix for unterminated string literals...")
    fixed = find_and_fix_files()

    if fixed > 0:
        print(
            f"\nFixed {fixed} files. Please run pre-commit again to check for remaining issues."
        )
    else:
        print("\nNo files needed fixing.")
