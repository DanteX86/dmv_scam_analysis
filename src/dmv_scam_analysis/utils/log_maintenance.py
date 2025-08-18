#!/usr/bin/env python3
"""
Log maintenance script for managing log files.
Handles log rotation, archival, and cleanup.
"""

import argparse
import gzip
import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


class LogMaintenance:
    """Class for managing log maintenance tasks."""

    def __init__(
        self, log_dir: str = "logs", archive_dir: str = "logs/archive"
    ) -> None:
        """
        Initialize log maintenance.

        Args:
            log_dir: Base directory for logs
            archive_dir: Directory for archived logs
        """
        self.log_dir = Path(log_dir)
        self.archive_dir = Path(archive_dir)
        self.logger = logging.getLogger("maintenance")

    def setup_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(parents=True, exist_ok=True)

    def find_old_logs(self, days: int) -> List[Path]:
        """
        Find log files older than specified days.

        Args:
            days: Number of days threshold

        Returns:
            List of old log file paths
        """
        old_files: List[Path] = []
        threshold = datetime.now() - timedelta(days=days)

        for log_file in self.log_dir.rglob("*.log*"):
            if log_file.stat().st_mtime < threshold.timestamp():
                old_files.append(log_file)

        return old_files

    def compress_log(self, log_file: Path) -> Optional[Path]:
        """
        Compress a log file using gzip.

        Args:
            log_file: Path to log file

        Returns:
            Path to compressed file or None if compression failed
        """
        try:
            compressed_path = log_file.with_suffix(log_file.suffix + ".gz")
            with log_file.open("rb") as f_in:
                with gzip.open(compressed_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return compressed_path
        except Exception as e:
            self.logger.error(f"Error compressing {log_file}: {e}")
            return None

    def archive_logs(self, files: List[Path]) -> None:
        """
        Archive log files.

        Args:
            files: List of files to archive
        """
        timestamp = datetime.now().strftime("%Y%m%d")
        archive_subdir = self.archive_dir / timestamp
        archive_subdir.mkdir(exist_ok=True)

        for file_path in files:
            try:
                # Compress file
                compressed_file = self.compress_log(file_path)
                if compressed_file:
                    # Move to archive
                    archive_path = archive_subdir / compressed_file.name
                    compressed_file.rename(archive_path)
                    # Remove original
                    file_path.unlink()
                    self.logger.info(f"Archived {file_path} to {archive_path}")
            except Exception as e:
                self.logger.error(f"Error archiving {file_path}: {e}")

    def cleanup_archives(self, keep_days: int) -> None:
        """
        Remove archive directories older than specified days.

        Args:
            keep_days: Number of days to keep archives
        """
        threshold = datetime.now() - timedelta(days=keep_days)

        for archive_dir in self.archive_dir.iterdir():
            if archive_dir.is_dir():
                try:
                    dir_date = datetime.strptime(archive_dir.name, "%Y%m%d")
                    if dir_date.timestamp() < threshold.timestamp():
                        shutil.rmtree(archive_dir)
                        self.logger.info(f"Removed old archive: {archive_dir}")
                except ValueError:
                    # Directory name doesn't match date format
                    continue

    def rotate_active_logs(self) -> None:
        """Rotate current log files."""
        try:
            from ..utils.logger import LogManager

            manager = LogManager()
            manager.rotate_logs()
            self.logger.info("Rotated active log files")
        except Exception as e:
            self.logger.error(f"Error rotating logs: {e}")

    def get_log_stats(self) -> Dict[str, Any]:
        """
        Get statistics about log files.

        Returns:
            Dictionary containing log statistics
        """
        stats: Dict[str, Any] = {
            "total_size": 0,
            "file_count": 0,
            "oldest_file": None,
            "newest_file": None,
            "by_type": {},
        }

        for log_file in self.log_dir.rglob("*.log*"):
            file_size = log_file.stat().st_size
            file_time = datetime.fromtimestamp(log_file.stat().st_mtime)

            # Update total size and count
            stats["total_size"] += int(file_size)
            stats["file_count"] += 1

            # Update oldest/newest
            if not stats["oldest_file"] or file_time < stats["oldest_file"][1]:
                stats["oldest_file"] = (log_file, file_time)
            if not stats["newest_file"] or file_time > stats["newest_file"][1]:
                stats["newest_file"] = (log_file, file_time)

            # Group by log type (parent directory name)
            log_type = log_file.parent.name
            by_type: Dict[str, Dict[str, int]] = stats.get("by_type", {})
            if log_type not in by_type:
                by_type[log_type] = {"size": 0, "count": 0}
            by_type[log_type]["size"] += int(file_size)
            by_type[log_type]["count"] += 1
            stats["by_type"] = by_type

        return stats


def main() -> None:
    """Main function to run log maintenance."""
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Log maintenance utility")
    parser.add_argument(
        "--archive-days",
        type=int,
        default=7,
        help="Archive logs older than this many days",
    )
    parser.add_argument(
        "--keep-days", type=int, default=30, help="Keep archives for this many days"
    )
    parser.add_argument("--stats", action="store_true", help="Show log statistics")
    parser.add_argument("--rotate", action="store_true", help="Rotate active log files")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize maintenance
    maintenance = LogMaintenance()
    maintenance.setup_directories()

    try:
        # Rotate logs if requested
        if args.rotate:
            maintenance.rotate_active_logs()

        # Find and archive old logs
        old_logs = maintenance.find_old_logs(args.archive_days)
        if old_logs:
            maintenance.archive_logs(old_logs)

        # Cleanup old archives
        maintenance.cleanup_archives(args.keep_days)

        # Show statistics if requested
        if args.stats:
            stats = maintenance.get_log_stats()
            print("\nLog Statistics:")
            print(f"Total files: {stats['file_count']}")
            print(f"Total size: {stats['total_size'] / 1024 / 1024:.2f} MB")
            if stats["oldest_file"]:
                print(
                    f"Oldest file: {stats['oldest_file'][0]} "
                    f"({stats['oldest_file'][1].isoformat()})"
                )
            if stats["newest_file"]:
                print(
                    f"Newest file: {stats['newest_file'][0]} "
                    f"({stats['newest_file'][1].isoformat()})"
                )
            print("\nBy log type:")
            for log_type, type_stats in stats["by_type"].items():
                print(f"{log_type}:")
                print(f"  Files: {type_stats['count']}")
                print(f"  Size: {type_stats['size'] / 1024 / 1024:.2f} MB")

    except Exception as e:
        logging.error(f"Error during maintenance: {e}")
        raise


if __name__ == "__main__":
    main()
