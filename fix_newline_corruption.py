#!/usr/bin/env python3
"""
Script to fix systematic newline corruption in Python files.

This script replaces literal \\n characters with actual newlines across all Python files
in the DMV scam analysis codebase.
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple


def find_python_files(root_dir: str) -> List[Path]:
    """Find all Python files in the directory tree."""
    root = Path(root_dir)
    python_files = []

    for file_path in root.rglob("*.py"):
        python_files.append(file_path)

    return python_files


def fix_newline_corruption(file_path: Path) -> Tuple[bool, int]:
    """
    Fix newline corruption in a single file.

    Args:
        file_path: Path to the Python file

    Returns:
        Tuple of (was_modified, num_replacements)
    """
    try:
        # Read file content
        with open(file_path, "r", encoding="utf-8") as f:
            original_content = f.read()

        # Count original \\n occurrences
        original_count = original_content.count("\\n")

        if original_count == 0:
            return False, 0

        # Replace literal \\n with actual newlines
        # We need to be careful to only replace literal \\n and not \\\\n or other patterns
        # The pattern should match \\n but not \\\n (escaped backslash followed by n)
        fixed_content = re.sub(r"(?<!\\)\\n", "\n", original_content)

        # Count replacements made
        new_count = fixed_content.count("\n")
        replacements = (
            new_count - original_count
            if new_count > original_count
            else original_count - new_count
        )

        # Only write if changes were made
        if fixed_content != original_content:
            # Create backup
            backup_path = file_path.with_suffix(file_path.suffix + ".backup")
            with open(backup_path, "w", encoding="utf-8") as f:
                f.write(original_content)

            # Write fixed content
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(fixed_content)

            return True, replacements

        return False, 0

    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False, 0


def main():
    """Main function to fix newline corruption across all Python files."""

    # Get current directory (assumes script is run from project root)
    project_root = Path.cwd()

    print(f"Scanning for Python files in: {project_root}")

    # Find all Python files
    python_files = find_python_files(str(project_root))
    print(f"Found {len(python_files)} Python files")

    # Process each file
    total_files_modified = 0
    total_replacements = 0

    for file_path in python_files:
        was_modified, replacements = fix_newline_corruption(file_path)

        if was_modified:
            total_files_modified += 1
            total_replacements += replacements
            print(f"Fixed {replacements} corrupted newlines in: {file_path}")

    print("\nSummary:")
    print(f"  Files processed: {len(python_files)}")
    print(f"  Files modified: {total_files_modified}")
    print(f"  Total replacements: {total_replacements}")

    if total_files_modified > 0:
        print("\nBackups created for modified files.")
        print("You can remove backups after verification with:")
        print(f"  find {project_root} -name '*.py.backup' -delete")

    return 0


if __name__ == "__main__":
    sys.exit(main())
